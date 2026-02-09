"""Tests for CLOAK Web UI server."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cloak.core.database import close_database, session_scope
from cloak.core.models import Asset, Execution, Finding
from cloak.web.server import create_app


@pytest.fixture
def client(test_config):
    """Create a test client with initialized database and sample data."""
    close_database()
    app = create_app(test_config)

    with session_scope(test_config) as session:
        execution = Execution(
            technique_name="s3.list_buckets",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/test",
        )
        execution.mark_completed(summary="Found 2 buckets", finding_count=1, asset_count=2)
        session.add(execution)
        session.flush()

        asset1 = Asset(
            execution_id=execution.id,
            service="s3",
            resource_type="s3_bucket",
            resource_id="test-bucket-1",
            account_id="123456789012",
            name="test-bucket-1",
        )
        asset2 = Asset(
            execution_id=execution.id,
            service="s3",
            resource_type="s3_bucket",
            resource_id="test-bucket-2",
            account_id="123456789012",
            name="test-bucket-2",
        )
        session.add_all([asset1, asset2])
        session.flush()

        finding = Finding(
            execution_id=execution.id,
            asset_id=asset1.id,
            severity="high",
            finding_type="public_access",
            title="Bucket may have public access",
            description="Test finding description",
            resource_type="s3_bucket",
            resource_id="test-bucket-1",
        )
        session.add(finding)
        session.commit()

    yield TestClient(app)
    close_database()


@pytest.fixture
def empty_client(test_config):
    """Create a test client with an empty database (no sample data)."""
    close_database()
    app = create_app(test_config)
    yield TestClient(app)
    close_database()


class TestApiStats:
    """Tests for /api/stats endpoint."""

    def test_returns_stats(self, client):
        """Test that stats endpoint returns dashboard statistics."""
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()

        assert "total_executions" in data
        assert data["total_executions"] == 1
        assert "total_assets" in data
        assert data["total_assets"] == 2
        assert "total_findings" in data
        assert data["total_findings"] == 1
        assert "findings_by_severity" in data
        assert "assets_by_service" in data


class TestApiExecutions:
    """Tests for /api/executions endpoints."""

    def test_list_executions(self, client):
        """Test listing executions."""
        response = client.get("/api/executions")
        assert response.status_code == 200
        data = response.json()

        assert "executions" in data
        assert len(data["executions"]) == 1
        assert data["executions"][0]["technique_name"] == "s3.list_buckets"
        assert data["total"] == 1

    def test_list_executions_with_filters(self, client):
        """Test listing executions with status filter."""
        response = client.get("/api/executions?status=completed")
        assert response.status_code == 200
        data = response.json()
        assert len(data["executions"]) == 1

        response = client.get("/api/executions?status=failed")
        assert response.status_code == 200
        data = response.json()
        assert len(data["executions"]) == 0

    def test_get_execution_detail(self, client):
        """Test getting execution detail by ID."""
        list_resp = client.get("/api/executions")
        exec_id = list_resp.json()["executions"][0]["id"]

        response = client.get(f"/api/executions/{exec_id}")
        assert response.status_code == 200
        data = response.json()

        assert data["technique_name"] == "s3.list_buckets"
        assert "assets" in data
        assert len(data["assets"]) == 2
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_get_execution_detail_not_found(self, client):
        """Test 404 for non-existent execution."""
        response = client.get("/api/executions/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert data["error"] == "Execution not found"


class TestApiFindings:
    """Tests for /api/findings endpoints."""

    def test_list_findings(self, client):
        """Test listing findings."""
        response = client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()

        assert "findings" in data
        assert len(data["findings"]) == 1
        assert data["findings"][0]["title"] == "Bucket may have public access"
        assert data["findings"][0]["severity"] == "high"

    def test_list_findings_with_severity_filter(self, client):
        """Test listing findings with severity filter."""
        response = client.get("/api/findings?severity=high")
        assert response.status_code == 200
        data = response.json()
        assert len(data["findings"]) == 1

        response = client.get("/api/findings?severity=critical")
        assert response.status_code == 200
        data = response.json()
        assert len(data["findings"]) == 0

    def test_get_finding_detail(self, client):
        """Test getting finding detail by ID."""
        list_resp = client.get("/api/findings")
        finding_id = list_resp.json()["findings"][0]["id"]

        response = client.get(f"/api/findings/{finding_id}")
        assert response.status_code == 200
        data = response.json()

        assert data["title"] == "Bucket may have public access"
        assert data["severity"] == "high"
        assert "execution" in data

    def test_get_finding_detail_not_found(self, client):
        """Test 404 for non-existent finding."""
        response = client.get("/api/findings/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert data["error"] == "Finding not found"


class TestApiExport:
    """Tests for export endpoints."""

    def test_export_findings(self, client):
        """Test exporting findings as JSON."""
        response = client.get("/api/export/findings")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
        assert "attachment" in response.headers.get("content-disposition", "")

        data = response.json()
        assert data["export_type"] == "cloak_findings"
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_export_execution(self, client):
        """Test exporting single execution as JSON."""
        list_resp = client.get("/api/executions")
        exec_id = list_resp.json()["executions"][0]["id"]

        response = client.get(f"/api/export/executions/{exec_id}")
        assert response.status_code == 200
        assert "attachment" in response.headers.get("content-disposition", "")

        data = response.json()
        assert data["export_type"] == "cloak_execution"
        assert "execution" in data
        assert "assets" in data
        assert "findings" in data

    def test_export_findings_with_finding_type_filter(self, client, test_config):
        """Test exporting findings filtered by finding_type."""
        # Add a finding with a different type
        exec_id = client.get("/api/executions").json()["executions"][0]["id"]
        with session_scope(test_config) as session:
            f = Finding(
                execution_id=exec_id,
                severity="low",
                finding_type="encryption_disabled",
                title="Encryption not enabled",
                description="Test finding",
                resource_type="s3_bucket",
                resource_id="bucket-1",
            )
            session.add(f)
            session.commit()

        # Filter by existing finding_type
        response = client.get("/api/export/findings?finding_type=public_access")
        assert response.status_code == 200
        data = response.json()
        assert data["total_findings"] == 1
        assert data["findings"][0]["finding_type"] == "public_access"
        assert data["filters"]["finding_type"] == "public_access"

        # Filter by the new finding_type
        response = client.get("/api/export/findings?finding_type=encryption_disabled")
        data = response.json()
        assert data["total_findings"] == 1
        assert data["findings"][0]["finding_type"] == "encryption_disabled"

        # No filter returns all
        response = client.get("/api/export/findings")
        data = response.json()
        assert data["total_findings"] == 2

    def test_export_execution_not_found(self, client):
        """Test 404 when exporting non-existent execution."""
        response = client.get("/api/export/executions/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert data["error"] == "Execution not found"
        # Should NOT have Content-Disposition attachment header
        assert "attachment" not in response.headers.get("content-disposition", "")


class TestIndex:
    """Tests for SPA index page."""

    def test_serve_index(self, client):
        """Test that index HTML is served."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "CLOAK" in response.text


class TestHealthCheck:
    """Tests for /api/health endpoint."""

    def test_health_check(self, client):
        """Test that health endpoint returns CLOAK identifier."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "cloak-web-ui"
        assert "version" in data

    def test_health_check_empty_db(self, empty_client):
        """Test health check works with an empty database."""
        response = empty_client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["service"] == "cloak-web-ui"


class TestEmptyDatabase:
    """Tests for API behavior with an empty database."""

    def test_stats_empty(self, empty_client):
        """Test stats endpoint with no data returns zeros."""
        response = empty_client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_executions"] == 0
        assert data["total_findings"] == 0
        assert data["total_assets"] == 0
        assert data["success_rate"] == 0
        assert data["findings_by_severity"] == {}
        assert data["finding_types"] == []

    def test_list_executions_empty(self, empty_client):
        """Test listing executions returns empty list."""
        response = empty_client.get("/api/executions")
        assert response.status_code == 200
        data = response.json()
        assert data["executions"] == []
        assert data["total"] == 0

    def test_list_findings_empty(self, empty_client):
        """Test listing findings returns empty list."""
        response = empty_client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert data["findings"] == []
        assert data["total"] == 0

    def test_list_assets_empty(self, empty_client):
        """Test listing assets returns empty list."""
        response = empty_client.get("/api/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["assets"] == []
        assert data["total"] == 0

    def test_export_findings_empty(self, empty_client):
        """Test exporting findings with no data returns valid JSON."""
        response = empty_client.get("/api/export/findings")
        assert response.status_code == 200
        data = response.json()
        assert data["total_findings"] == 0
        assert data["findings"] == []


class TestAgentEvents:
    """Tests for /api/agent-events endpoint."""

    def test_post_agent_event(self, client):
        """Test posting an agent event returns ok."""
        event = {
            "type": "technique_start",
            "technique": "s3.list_buckets",
            "dry_run": False,
        }
        response = client.post("/api/agent-events", json=event)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True

    def test_post_agent_event_complete(self, client):
        """Test posting a technique_complete event."""
        event = {
            "type": "technique_complete",
            "technique": "s3.list_buckets",
            "dry_run": False,
            "execution_id": "abc-123",
            "success": True,
        }
        response = client.post("/api/agent-events", json=event)
        assert response.status_code == 200
        assert response.json()["ok"] is True

    def test_post_agent_event_failed(self, client):
        """Test posting a technique_failed event."""
        event = {
            "type": "technique_failed",
            "technique": "s3.list_buckets",
            "error": "Access denied",
        }
        response = client.post("/api/agent-events", json=event)
        assert response.status_code == 200
        assert response.json()["ok"] is True

    def test_post_invalid_json(self, client):
        """Test posting invalid JSON returns error."""
        response = client.post(
            "/api/agent-events",
            content=b"not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is False
        assert "error" in data


class TestPagination:
    """Tests for pagination across list endpoints."""

    def test_executions_pagination(self, client, test_config):
        """Test execution list pagination with offset and limit."""
        # Add more executions
        with session_scope(test_config) as session:
            for i in range(5):
                exec_ = Execution(
                    technique_name=f"s3.technique_{i}",
                    service="s3",
                    aws_account_id="123456789012",
                    aws_identity_arn="arn:aws:iam::123456789012:user/test",
                )
                exec_.mark_completed(summary=f"Summary {i}", finding_count=0, asset_count=0)
                session.add(exec_)
            session.commit()

        # First page
        response = client.get("/api/executions?limit=3&offset=0")
        data = response.json()
        assert len(data["executions"]) == 3
        assert data["total"] == 6  # 1 from fixture + 5 added

        # Second page
        response = client.get("/api/executions?limit=3&offset=3")
        data = response.json()
        assert len(data["executions"]) == 3
        assert data["total"] == 6

        # Beyond data
        response = client.get("/api/executions?limit=3&offset=10")
        data = response.json()
        assert len(data["executions"]) == 0
        assert data["total"] == 6

    def test_findings_pagination(self, client, test_config):
        """Test finding list pagination with offset and limit."""
        # Get the execution ID from fixture
        list_resp = client.get("/api/executions")
        exec_id = list_resp.json()["executions"][0]["id"]

        # Add more findings
        with session_scope(test_config) as session:
            for i in range(4):
                f = Finding(
                    execution_id=exec_id,
                    severity="medium",
                    finding_type="misconfiguration",
                    title=f"Finding {i}",
                    description=f"Description {i}",
                    resource_type="s3_bucket",
                    resource_id=f"bucket-{i}",
                )
                session.add(f)
            session.commit()

        response = client.get("/api/findings?limit=2&offset=0")
        data = response.json()
        assert len(data["findings"]) == 2
        assert data["total"] == 5  # 1 from fixture + 4 added


class TestFilterCombinations:
    """Tests for combined filter parameters."""

    def test_executions_filter_by_service(self, client, test_config):
        """Test filtering executions by service."""
        with session_scope(test_config) as session:
            exec_ = Execution(
                technique_name="iam.list_users",
                service="iam",
                aws_account_id="123456789012",
                aws_identity_arn="arn:aws:iam::123456789012:user/test",
            )
            exec_.mark_completed(summary="Found users", finding_count=0, asset_count=3)
            session.add(exec_)
            session.commit()

        response = client.get("/api/executions?service=iam")
        data = response.json()
        assert len(data["executions"]) == 1
        assert data["executions"][0]["service"] == "iam"

        response = client.get("/api/executions?service=s3")
        data = response.json()
        assert len(data["executions"]) == 1
        assert data["executions"][0]["service"] == "s3"

    def test_findings_filter_by_type(self, client, test_config):
        """Test filtering findings by finding_type."""
        exec_id = client.get("/api/executions").json()["executions"][0]["id"]

        with session_scope(test_config) as session:
            f = Finding(
                execution_id=exec_id,
                severity="low",
                finding_type="encryption_disabled",
                title="Encryption not enabled",
                description="Test",
                resource_type="s3_bucket",
                resource_id="bucket-1",
            )
            session.add(f)
            session.commit()

        response = client.get("/api/findings?finding_type=public_access")
        data = response.json()
        assert len(data["findings"]) == 1

        response = client.get("/api/findings?finding_type=encryption_disabled")
        data = response.json()
        assert len(data["findings"]) == 1

    def test_findings_filter_by_execution_id(self, client):
        """Test filtering findings by execution_id."""
        exec_id = client.get("/api/executions").json()["executions"][0]["id"]

        response = client.get(f"/api/findings?execution_id={exec_id}")
        data = response.json()
        assert len(data["findings"]) == 1

        response = client.get("/api/findings?execution_id=00000000-0000-0000-0000-000000000000")
        data = response.json()
        assert len(data["findings"]) == 0

    def test_assets_filter_by_service(self, client):
        """Test filtering assets by service."""
        response = client.get("/api/assets?service=s3")
        data = response.json()
        assert len(data["assets"]) == 2

        response = client.get("/api/assets?service=iam")
        data = response.json()
        assert len(data["assets"]) == 0


class TestStatsStatusConsistency:
    """Tests for status case consistency fix."""

    def test_stats_counts_completed_correctly(self, client):
        """Test that stats endpoint correctly counts completed executions."""
        response = client.get("/api/stats")
        data = response.json()
        # The fixture creates 1 completed execution
        assert data["completed"] == 1
        assert data["failed"] == 0
        assert data["success_rate"] == 1.0

    def test_stats_counts_failed(self, client, test_config):
        """Test that stats counts failed executions correctly."""
        with session_scope(test_config) as session:
            exec_ = Execution(
                technique_name="s3.get_bucket_acl",
                service="s3",
                aws_account_id="123456789012",
                aws_identity_arn="arn:aws:iam::123456789012:user/test",
            )
            exec_.mark_failed(error_message="Access denied")
            session.add(exec_)
            session.commit()

        response = client.get("/api/stats")
        data = response.json()
        assert data["completed"] == 1
        assert data["failed"] == 1
        assert data["total_executions"] == 2

    def test_stats_includes_finding_types(self, client):
        """Test that stats endpoint includes distinct finding types."""
        response = client.get("/api/stats")
        data = response.json()
        assert "finding_types" in data
        assert "public_access" in data["finding_types"]

    def test_executions_filter_case_insensitive(self, client):
        """Test that execution status filter works with any case."""
        # Lower case
        response = client.get("/api/executions?status=completed")
        assert len(response.json()["executions"]) == 1

        # Upper case - should still work (lowered by server)
        response = client.get("/api/executions?status=COMPLETED")
        assert len(response.json()["executions"]) == 1
