"""FastAPI web server for CLOAK Web UI."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from sqlalchemy import func

from cloak.core.config import CloakConfig
from cloak.core.database import init_database, session_scope
from cloak.core.logging import get_logger
from cloak.core.models import Asset, Execution, Finding

# Paths
STATIC_DIR = Path(__file__).parent / "static"

# Store config reference for database access
_config: CloakConfig | None = None
logger = get_logger(__name__)

# Agent status WebSocket connections for real-time updates
_agent_status_connections: list[WebSocket] = []


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan."""
    yield


# FastAPI app
app = FastAPI(
    title="CLOAK Web UI",
    description="Visual interface for browsing CLOAK security assessment results",
    version="0.1.0",
    lifespan=lifespan,
)


def set_config(config: CloakConfig) -> None:
    """Set the configuration for the web server."""
    global _config
    _config = config


# --- Global Exception Handler ---


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return consistent JSON error responses for unhandled exceptions."""
    logger.error("Unhandled server error", error=str(exc), path=str(request.url.path))
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# --- API Routes ---


@app.get("/api/health")
def health_check() -> dict[str, Any]:
    """Health check endpoint for verifying the CLOAK Web UI is running."""
    return {"status": "ok", "service": "cloak-web-ui", "version": "0.1.0"}


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    """Get dashboard statistics."""
    with session_scope(_config) as session:
        total_executions = session.query(Execution).count()
        completed = session.query(Execution).filter(Execution.status == "completed").count()
        failed = session.query(Execution).filter(Execution.status == "failed").count()
        total_assets = session.query(Asset).count()
        total_findings = session.query(Finding).count()

        # Findings by severity
        severity_counts = (
            session.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()
        )
        findings_by_severity: dict[str, int] = {str(row[0]): int(row[1]) for row in severity_counts}

        # Assets by service
        service_counts = (
            session.query(Asset.service, func.count(Asset.id)).group_by(Asset.service).all()
        )
        assets_by_service: dict[str, int] = {str(row[0]): int(row[1]) for row in service_counts}

        # Executions by service
        exec_service_counts = (
            session.query(Execution.service, func.count(Execution.id))
            .group_by(Execution.service)
            .all()
        )
        executions_by_service: dict[str, int] = {
            str(row[0]): int(row[1]) for row in exec_service_counts
        }

        # Distinct finding types (for filter dropdowns)
        finding_types = [
            row[0]
            for row in session.query(Finding.finding_type)
            .distinct()
            .order_by(Finding.finding_type)
            .all()
        ]

        return {
            "total_executions": total_executions,
            "completed": completed,
            "failed": failed,
            "success_rate": completed / total_executions if total_executions > 0 else 0,
            "total_assets": total_assets,
            "total_findings": total_findings,
            "findings_by_severity": findings_by_severity,
            "assets_by_service": assets_by_service,
            "executions_by_service": executions_by_service,
            "finding_types": finding_types,
        }


@app.get("/api/executions")
def list_executions(
    status: str | None = Query(None, description="Filter by status"),
    service: str | None = Query(None, description="Filter by service"),
    technique: str | None = Query(None, description="Filter by technique name"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> dict[str, Any]:
    """List executions with optional filters."""
    with session_scope(_config) as session:
        query = session.query(Execution)

        if status:
            query = query.filter(Execution.status == status.lower())
        if service:
            query = query.filter(Execution.service == service)
        if technique:
            query = query.filter(Execution.technique_name == technique)

        total = query.count()
        executions = query.order_by(Execution.started_at.desc()).offset(offset).limit(limit).all()

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "executions": [e.to_dict() for e in executions],
        }


@app.get("/api/executions/{execution_id}", response_model=None)
def get_execution(execution_id: str) -> dict[str, Any] | JSONResponse:
    """Get execution detail with assets and findings."""
    with session_scope(_config) as session:
        execution = session.query(Execution).filter(Execution.id == execution_id).first()

        if not execution:
            return JSONResponse(content={"error": "Execution not found"}, status_code=404)

        data = execution.to_dict()
        data["assets"] = [a.to_dict() for a in execution.assets]
        data["findings"] = [f.to_dict() for f in execution.findings]

        return data


@app.get("/api/assets")
def list_assets(
    service: str | None = Query(None, description="Filter by service"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    execution_id: str | None = Query(None, description="Filter by execution"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> dict[str, Any]:
    """List assets with optional filters."""
    with session_scope(_config) as session:
        query = session.query(Asset)

        if service:
            query = query.filter(Asset.service == service)
        if resource_type:
            query = query.filter(Asset.resource_type == resource_type)
        if execution_id:
            query = query.filter(Asset.execution_id == execution_id)

        total = query.count()
        assets = query.order_by(Asset.created_at.desc()).offset(offset).limit(limit).all()

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "assets": [a.to_dict() for a in assets],
        }


@app.get("/api/findings")
def list_findings(
    severity: str | None = Query(None, description="Filter by severity"),
    finding_type: str | None = Query(None, description="Filter by finding type"),
    execution_id: str | None = Query(None, description="Filter by execution"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> dict[str, Any]:
    """List findings with optional filters."""
    with session_scope(_config) as session:
        query = session.query(Finding)

        if severity:
            query = query.filter(Finding.severity == severity.lower())
        if finding_type:
            query = query.filter(Finding.finding_type == finding_type)
        if execution_id:
            query = query.filter(Finding.execution_id == execution_id)

        total = query.count()
        findings = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "findings": [f.to_dict() for f in findings],
        }


@app.get("/api/findings/{finding_id}", response_model=None)
def get_finding(finding_id: str) -> dict[str, Any] | JSONResponse:
    """Get finding detail."""
    with session_scope(_config) as session:
        finding = session.query(Finding).filter(Finding.id == finding_id).first()

        if not finding:
            return JSONResponse(content={"error": "Finding not found"}, status_code=404)

        data = finding.to_dict()
        # Include parent execution info
        if finding.execution:
            data["execution"] = {
                "id": finding.execution.id,
                "technique_name": finding.execution.technique_name,
                "service": finding.execution.service,
            }
        # Include related asset info
        if finding.asset:
            data["asset"] = {
                "id": finding.asset.id,
                "name": finding.asset.name,
                "resource_type": finding.asset.resource_type,
            }

        return data


# --- Export Endpoints ---


@app.get("/api/export/findings")
def export_findings(
    severity: str | None = Query(None, description="Filter by severity"),
    finding_type: str | None = Query(None, description="Filter by finding type"),
    execution_id: str | None = Query(None, description="Filter by execution"),
) -> Any:
    """Export findings as downloadable JSON.

    Returns findings data suitable for reporting and sharing.
    """
    with session_scope(_config) as session:
        query = session.query(Finding)

        if severity:
            query = query.filter(Finding.severity == severity.lower())
        if finding_type:
            query = query.filter(Finding.finding_type == finding_type)
        if execution_id:
            query = query.filter(Finding.execution_id == execution_id)

        findings = query.order_by(Finding.created_at.desc()).all()

        # Build export data
        export_data: dict[str, Any] = {
            "export_type": "cloak_findings",
            "export_time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "filters": {
                "severity": severity,
                "finding_type": finding_type,
                "execution_id": execution_id,
            },
            "total_findings": len(findings),
            "summary": {},
            "findings": [],
        }

        # Severity summary
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity or "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        export_data["summary"]["by_severity"] = severity_counts

        # Finding details
        for f in findings:
            finding_data = f.to_dict()
            # Include execution context
            if f.execution:
                finding_data["execution"] = {
                    "id": f.execution.id,
                    "technique": f.execution.technique_name,
                    "service": f.execution.service,
                    "started_at": (
                        f.execution.started_at.isoformat() if f.execution.started_at else None
                    ),
                }
            # Include asset context
            if f.asset:
                finding_data["asset"] = {
                    "id": f.asset.id,
                    "name": f.asset.name,
                    "resource_type": f.asset.resource_type,
                }
            export_data["findings"].append(finding_data)

        return JSONResponse(
            content=export_data,
            headers={
                "Content-Disposition": "attachment; filename=cloak-findings-export.json",
            },
        )


@app.get("/api/export/executions/{execution_id}")
def export_execution(execution_id: str) -> Any:
    """Export a single execution with all assets and findings as JSON."""
    with session_scope(_config) as session:
        execution = session.query(Execution).filter(Execution.id == execution_id).first()

        if not execution:
            return JSONResponse(content={"error": "Execution not found"}, status_code=404)

        export_data: dict[str, Any] = {
            "export_type": "cloak_execution",
            "export_time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "execution": execution.to_dict(),
            "assets": [a.to_dict() for a in execution.assets],
            "findings": [f.to_dict() for f in execution.findings],
            "summary": {
                "total_assets": len(execution.assets),
                "total_findings": len(execution.findings),
                "findings_by_severity": {},
            },
        }

        for f in execution.findings:
            sev = f.severity or "unknown"
            export_data["summary"]["findings_by_severity"][sev] = (
                export_data["summary"]["findings_by_severity"].get(sev, 0) + 1
            )

        return JSONResponse(
            content=export_data,
            headers={
                "Content-Disposition": (
                    f"attachment; filename=cloak-execution-{execution_id}.json"
                ),
            },
        )


# --- SSE (Server-Sent Events) for Real-Time Updates ---


async def _event_stream(request: Request) -> AsyncGenerator[str, None]:
    """Generate SSE events by polling the database for changes.

    Watches for new executions, status transitions, and findings,
    yielding events when changes are detected. Polls every 2 seconds.

    Args:
        request: FastAPI request (used to detect client disconnect).

    Yields:
        SSE-formatted event strings.
    """
    last_execution_count = 0
    last_finding_count = 0
    last_latest_status: str | None = None

    # Get initial counts and latest execution status
    try:
        with session_scope(_config) as session:
            last_execution_count = session.query(Execution).count()
            last_finding_count = session.query(Finding).count()
            latest = session.query(Execution).order_by(Execution.started_at.desc()).first()
            if latest:
                last_latest_status = latest.status
    except Exception as e:
        logger.warning("SSE initial count failed", error=str(e))

    while True:
        # Check if client disconnected
        if await request.is_disconnected():
            break

        try:
            with session_scope(_config) as session:
                current_exec_count = session.query(Execution).count()
                current_finding_count = session.query(Finding).count()

                # Also check the latest execution's status for transitions
                latest = session.query(Execution).order_by(Execution.started_at.desc()).first()
                current_latest_status = latest.status if latest else None

                events = []

                # Detect new executions OR status transitions on the latest
                count_changed = current_exec_count != last_execution_count
                status_changed = current_latest_status != last_latest_status

                if count_changed or status_changed:
                    event_data: dict[str, Any] = {
                        "type": "execution_update",
                        "total_executions": current_exec_count,
                        "delta": current_exec_count - last_execution_count,
                    }
                    if latest:
                        event_data["latest"] = {
                            "id": latest.id,
                            "technique": latest.technique_name,
                            "status": latest.status,
                        }
                    events.append(event_data)
                    last_execution_count = current_exec_count
                    last_latest_status = current_latest_status

                if current_finding_count != last_finding_count:
                    finding_event: dict[str, Any] = {
                        "type": "finding_update",
                        "total_findings": current_finding_count,
                        "delta": current_finding_count - last_finding_count,
                    }
                    events.append(finding_event)
                    last_finding_count = current_finding_count

                for event in events:
                    yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"

                if not events:
                    # Send heartbeat to keep connection alive
                    yield ": heartbeat\n\n"

        except Exception as e:
            logger.warning("SSE event stream error", error=str(e))
            yield ": error\n\n"

        await asyncio.sleep(2)


@app.get("/api/events")
async def event_stream(request: Request) -> StreamingResponse:
    """SSE endpoint for real-time dashboard updates.

    Streams events when new executions or findings are added to the database.
    Connect from the frontend with:
        const source = new EventSource('/api/events');
        source.addEventListener('execution_update', (e) => { ... });
        source.addEventListener('finding_update', (e) => { ... });
    """
    return StreamingResponse(
        _event_stream(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# --- Agent Status WebSocket ---


async def _broadcast_agent_status(event: dict[str, Any]) -> None:
    """Broadcast agent status event to all connected WebSocket clients."""
    if not _agent_status_connections:
        return
    message = json.dumps(event)
    dead: list[WebSocket] = []
    for ws in _agent_status_connections:
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _agent_status_connections.remove(ws)


@app.websocket("/api/agent-status")
async def agent_status_websocket(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time agent status (technique running, etc.)."""
    await websocket.accept()
    _agent_status_connections.append(websocket)
    try:
        while True:
            # Keep connection alive; client doesn't send, we push
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _agent_status_connections:
            _agent_status_connections.remove(websocket)


@app.post("/api/agent-events")
async def receive_agent_event(request: Request) -> dict[str, Any]:
    """Receive agent events from CLI/hooks and broadcast to WebSocket clients.

    Called by the CLI when running techniques. Events include:
    - technique_start: { "type": "technique_start", "technique": "s3.list_buckets", "dry_run": bool }
    - technique_complete: { "type": "technique_complete", "technique": str, "execution_id": str, ... }
    - technique_failed: { "type": "technique_failed", "technique": str, "error": str }
    """
    try:
        body = await request.json()
    except Exception:
        return {"ok": False, "error": "Invalid JSON"}
    await _broadcast_agent_status(body)
    return {"ok": True}


# --- Static File Serving ---


@app.get("/", response_class=HTMLResponse)
def serve_index() -> FileResponse:
    """Serve the SPA index page."""
    return FileResponse(STATIC_DIR / "index.html")


def create_app(config: CloakConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config: CLOAK configuration. Uses default if not provided.

    Returns:
        Configured FastAPI app.
    """
    if config is None:
        config = CloakConfig.default()

    set_config(config)
    config.ensure_directories()
    init_database(config)

    return app


def run_server(config: CloakConfig | None = None, port: int = 8080) -> None:
    """Run the web UI server.

    Args:
        config: CLOAK configuration. Uses default if not provided.
        port: Port to listen on (default: 8080).
    """
    import uvicorn

    create_app(config)

    print(f"\n  CLOAK Web UI starting on http://localhost:{port}")
    print("  Press Ctrl+C to stop\n")

    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    except OSError as e:
        import errno
        import sys

        if e.errno == errno.EADDRINUSE:
            print(
                f"\n  Error: Port {port} is already in use."
                f"\n  Try a different port: cloak --web-ui --port {port + 1}\n",
                file=sys.stderr,
            )
        else:
            raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CLOAK Web UI Server")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    args = parser.parse_args()
    run_server(port=args.port)
