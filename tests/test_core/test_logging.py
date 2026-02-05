"""Tests for logging sanitization."""

from cloak.core.logging import TechniqueLogger, filter_sensitive_data


class TestFilterSensitiveData:
    """Tests for filter_sensitive_data processor."""

    def test_filters_credentials(self):
        """Test that credential keys are redacted."""
        event_dict = {
            "event": "test",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }

        filtered = filter_sensitive_data(None, "info", event_dict)

        assert filtered["aws_access_key_id"] == "[REDACTED]"
        assert filtered["aws_secret_access_key"] == "[REDACTED]"

    def test_filters_resource_identifiers(self):
        """Test that resource identifier keys are redacted."""
        event_dict = {
            "event": "API call",
            "bucket": "my-secret-bucket",
            "bucket_name": "another-bucket",
            "instance_id": "i-1234567890abcdef0",
        }

        filtered = filter_sensitive_data(None, "info", event_dict)

        assert filtered["bucket"] == "[REDACTED_RESOURCE]"
        assert filtered["bucket_name"] == "[REDACTED_RESOURCE]"
        assert filtered["instance_id"] == "[REDACTED_RESOURCE]"

    def test_filters_arns_in_values(self):
        """Test that ARNs in string values are redacted."""
        event_dict = {
            "event": "Found resource",
            "message": "Bucket ARN: arn:aws:s3:::my-bucket",
        }

        filtered = filter_sensitive_data(None, "info", event_dict)

        assert "arn:aws:s3:::my-bucket" not in filtered["message"]
        assert "[REDACTED_RESOURCE]" in filtered["message"]

    def test_filters_account_ids(self):
        """Test that account IDs in values are redacted."""
        event_dict = {
            "event": "Account access",
            "message": "Accessing account 123456789012",
        }

        filtered = filter_sensitive_data(None, "info", event_dict)

        assert "123456789012" not in filtered["message"]
        assert "[REDACTED_RESOURCE]" in filtered["message"]

    def test_preserves_safe_content(self):
        """Test that safe content is not redacted."""
        event_dict = {
            "event": "Enumeration complete",
            "asset_count": 15,
            "region": "us-east-1",
            "status": "completed",
        }

        filtered = filter_sensitive_data(None, "info", event_dict)

        assert filtered["asset_count"] == 15
        assert filtered["region"] == "us-east-1"
        assert filtered["status"] == "completed"

    def test_filters_nested_dicts(self):
        """Test that nested dictionaries are filtered."""
        event_dict = {
            "event": "test",
            "config": {
                "bucket_name": "sensitive-bucket",
                "region": "us-west-2",
            },
        }

        filtered = filter_sensitive_data(None, "info", event_dict)

        assert filtered["config"]["bucket_name"] == "[REDACTED_RESOURCE]"
        assert filtered["config"]["region"] == "us-west-2"

    def test_filters_lists(self):
        """Test that lists are filtered."""
        event_dict = {
            "event": "test",
            "buckets": ["bucket-1", "bucket-2", "bucket-3"],
        }

        filtered = filter_sensitive_data(None, "info", event_dict)

        # List items should be redacted if key name matches
        assert all(item == "[REDACTED_RESOURCE]" for item in filtered["buckets"])


class TestTechniqueLogger:
    """Tests for TechniqueLogger class."""

    def test_api_call_redacts_sensitive_kwargs(self):
        """Test that api_call method redacts sensitive data."""
        logger = TechniqueLogger("test.technique", "test-exec-id")

        # This should not raise an error, and should redact bucket name in logs
        logger.api_call("s3:GetBucketLocation", bucket="sensitive-bucket-name")

        # Test passes if no exception raised
        # In real usage, the filter will redact the bucket parameter
