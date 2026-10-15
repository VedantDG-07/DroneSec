"""REST API route handlers and WebSocket endpoints per docs/api-contract.md."""

from __future__ import annotations

import math
import os
import psutil
import time
from typing import Any, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, WebSocket, status
from fastapi.responses import JSONResponse

from backend.app.api.schemas import (
    AttackRunResponseData,
    BatteryModel,
    CommandExecutionData,
    CommandRequest,
    DroneStateData,
    ErrorDetail,
    GeographicModel,
    HealthData,
    MotionModel,
    PositionModel,
    SecurityModeRequest,
    SecurityModeResponseData,
    SecurityStatusData,
    StandardErrorResponse,
    StandardResponse,
)
from backend.app.core.drone_engine import DroneEngine
from backend.app.persistence.database import DatabaseManager
from backend.app.persistence.repositories import LogQueryRepository
from backend.app.security.message_protocol import SecurityMode
from backend.app.security.security_service import SecurityPipelineError, SecurityService
from backend.app.services.attack_service import AttackService
from backend.app.services.command_service import CommandService
from backend.app.services.telemetry_service import TelemetryService
from backend.app.websocket.hub import WebSocketHub

router = APIRouter()


# --- Dependency Injectors ---

def get_drone_engine(request: Request) -> DroneEngine:
    return request.app.state.drone_engine


def get_command_service(request: Request) -> CommandService:
    return request.app.state.command_service


def get_telemetry_service(request: Request) -> TelemetryService:
    return request.app.state.telemetry_service


def get_ws_hub(request: Request) -> WebSocketHub:
    return request.app.state.ws_hub


def get_db_manager(request: Request) -> DatabaseManager:
    return request.app.state.db_manager


def get_log_repo(request: Request) -> LogQueryRepository:
    return request.app.state.log_repo


def get_security_service(request: Request) -> SecurityService:
    return request.app.state.security_service


def get_attack_service(request: Request) -> AttackService:
    return request.app.state.attack_service


# --- REST Endpoints ---

@router.get(
    "/health",
    response_model=StandardResponse[HealthData],
    summary="System Health & Liveness",
)
async def get_health(
    request: Request,
    telemetry_service: TelemetryService = Depends(get_telemetry_service),
    db_manager: DatabaseManager = Depends(get_db_manager),
) -> StandardResponse[HealthData]:
    """Return operational health status of simulation loop, database, and system resources."""
    start_time = getattr(request.app.state, "start_time", time.time())
    uptime_seconds = time.time() - start_time

    db_health = await db_manager.check_health_async()
    loop_status = telemetry_service.get_loop_status()

    # Memory usage in MB
    try:
        process = psutil.Process(os.getpid())
        mem_mb = process.memory_info().rss / (1024 * 1024)
    except Exception:
        mem_mb = 0.0

    health_data = HealthData(
        system_status="OPERATIONAL",
        uptime_seconds=round(uptime_seconds, 1),
        simulation_loop=loop_status,
        database=db_health,
        memory_mb=round(mem_mb, 1),
    )

    return StandardResponse(data=health_data)


@router.get(
    "/api/drone/state",
    response_model=StandardResponse[DroneStateData],
    summary="Get Authoritative Drone State",
)
async def get_drone_state(
    drone_engine: DroneEngine = Depends(get_drone_engine),
) -> StandardResponse[DroneStateData]:
    """Retrieve an authoritative snapshot of the current drone state vector."""
    snapshot = drone_engine.get_state_snapshot()

    # Derive voltage and state of health based on battery percentage
    voltage = 10.0 + 2.6 * (snapshot.battery_level / 100.0)
    if snapshot.battery_level > 20.0:
        health_str = "GOOD"
    elif snapshot.battery_level > 5.0:
        health_str = "LOW"
    else:
        health_str = "CRITICAL"

    state_data = DroneStateData(
        state_version=snapshot.state_version,
        timestamp=snapshot.timestamp,
        flight_state=snapshot.flight_state.value,
        armed=snapshot.armed,
        position=PositionModel(
            x=round(snapshot.x, 3),
            y=round(snapshot.y, 3),
            z=round(snapshot.z, 3),
        ),
        geographic=GeographicModel(
            latitude=round(snapshot.latitude, 6),
            longitude=round(snapshot.longitude, 6),
            altitude_msl=round(snapshot.altitude_msl, 2),
        ),
        motion=MotionModel(
            heading=round(snapshot.heading, 1),
            speed=round(snapshot.speed, 2),
        ),
        battery=BatteryModel(
            level_percent=round(snapshot.battery_level, 2),
            voltage_volts=round(voltage, 2),
            state_of_health=health_str,
        ),
        last_command_id=snapshot.last_command_id,
    )

    return StandardResponse(data=state_data)


@router.post(
    "/api/drone/command",
    summary="Submit Flight Command",
    responses={
        200: {"model": StandardResponse[CommandExecutionData]},
        400: {"model": StandardErrorResponse},
        401: {"model": StandardErrorResponse},
        403: {"model": StandardErrorResponse},
        422: {"model": StandardErrorResponse},
        429: {"model": StandardErrorResponse},
    },
)
async def post_drone_command(
    request: Request,
    command_service: CommandService = Depends(get_command_service),
    security_service: SecurityService = Depends(get_security_service),
) -> Any:
    """Submit a discrete flight command to the authoritative drone engine through security verification."""
    try:
        raw_payload = await request.json()
    except Exception as e:
        err_envelope = StandardErrorResponse(
            error=ErrorDetail(code="INVALID_JSON", message="Request body must be valid JSON.")
        )
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=err_envelope.model_dump())

    if not isinstance(raw_payload, dict):
        err_envelope = StandardErrorResponse(
            error=ErrorDetail(code="INVALID_PAYLOAD", message="Request body must be a JSON object.")
        )
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=err_envelope.model_dump())

    # In UNSECURED mode with a plain command, enforce CommandRequest Pydantic validation (rejects extra fields -> 422)
    if security_service.current_mode == SecurityMode.UNSECURED and "header" not in raw_payload:
        try:
            CommandRequest(**raw_payload)
        except Exception as e:
            # Let FastAPI's standard validation response handle it
            err_envelope = StandardErrorResponse(
                error=ErrorDetail(
                    code="INVALID_SCHEMA",
                    message="Request payload failed schema validation.",
                    details={"error": str(e)},
                )
            )
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content=err_envelope.model_dump()
            )

    auth_header = request.headers.get("Authorization")
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        outcome = await command_service.process_and_execute(
            raw_payload=raw_payload,
            authorization_header=auth_header,
            source_ip=client_ip,
        )
    except SecurityPipelineError as err:
        headers = (
            {"Retry-After": str(int(math.ceil(err.retry_after)))} if err.retry_after is not None else None
        )
        err_envelope = StandardErrorResponse(
            error=ErrorDetail(
                code=err.error_code,
                message=err.message,
                details=err.details,
            )
        )
        return JSONResponse(
            status_code=err.status_code,
            content=err_envelope.model_dump(),
            headers=headers,
        )

    if not outcome.success:
        err_envelope = StandardErrorResponse(
            error=ErrorDetail(
                code=outcome.error_code or "COMMAND_FAILED",
                message=outcome.error_message or "Command execution failed.",
                details={"command": outcome.command, "state_version": outcome.state_version_after},
            )
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=err_envelope.model_dump(),
        )

    exec_data = CommandExecutionData(
        command_id=outcome.command_id,
        command=outcome.command,
        execution_status=outcome.execution_status,
        state_version_after=outcome.state_version_after,
        drone_position=PositionModel(**outcome.drone_position),
        processing_latency_ms=round(outcome.processing_latency_ms, 2),
    )

    return StandardResponse(data=exec_data)


@router.get(
    "/api/drone/telemetry",
    response_model=StandardResponse[list[dict[str, Any]]],
    summary="Get Rolling Telemetry Buffer",
)
async def get_telemetry_buffer(
    limit: int = Query(default=50, ge=1, le=500, description="Max telemetry records to retrieve"),
    telemetry_service: TelemetryService = Depends(get_telemetry_service),
) -> StandardResponse[list[dict[str, Any]]]:
    """Retrieve the rolling buffer of recent telemetry samples."""
    items = telemetry_service.get_recent_telemetry(limit=limit)
    return StandardResponse(data=items)


@router.get(
    "/api/logs",
    response_model=StandardResponse[list[dict[str, Any]]],
    summary="Query Audit & Security Logs",
)
async def get_logs(
    category: Optional[str] = Query(default=None, description="Filter by category (COMMAND, SECURITY_EVENT)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (INFO, WARNING, CRITICAL)"),
    limit: int = Query(default=100, ge=1, le=1000, description="Max records to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    log_repo: LogQueryRepository = Depends(get_log_repo),
) -> StandardResponse[list[dict[str, Any]]]:
    """Query persistently stored command execution and security incident audit logs."""
    logs = await log_repo.query_logs(
        category=category,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return StandardResponse(data=logs)


@router.get(
    "/api/security/status",
    response_model=StandardResponse[SecurityStatusData],
    summary="Get Security Engine Status",
)
async def get_security_status(
    security_service: SecurityService = Depends(get_security_service),
) -> StandardResponse[SecurityStatusData]:
    """Retrieve active security operating profile, key identifier, and anti-replay metrics."""
    status_dict = security_service.get_security_status()
    return StandardResponse(data=SecurityStatusData(**status_dict))


@router.post(
    "/api/security/mode",
    response_model=StandardResponse[SecurityModeResponseData],
    summary="Switch Security Mode",
)
async def post_security_mode(
    request_body: SecurityModeRequest,
    security_service: SecurityService = Depends(get_security_service),
) -> StandardResponse[SecurityModeResponseData]:
    """Switch active security operating mode (UNSECURED, INTEGRITY_ONLY, ENCRYPTED_AUTHENTICATED)."""
    try:
        target_mode = SecurityMode(request_body.mode)
    except ValueError:
        err_envelope = StandardErrorResponse(
            error=ErrorDetail(
                code="INVALID_SECURITY_MODE",
                message=f"Mode '{request_body.mode}' is invalid. Allowed: UNSECURED, INTEGRITY_ONLY, ENCRYPTED_AUTHENTICATED.",
            )
        )
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=err_envelope.model_dump())

    transition_result = security_service.set_security_mode(target_mode, reason=request_body.reason or "")
    return StandardResponse(data=SecurityModeResponseData(**transition_result))


@router.post(
    "/api/attacks/{attack_type}",
    response_model=StandardResponse[AttackRunResponseData],
    summary="Execute Controlled Cyberattack Scenario",
    responses={
        200: {"model": StandardResponse[AttackRunResponseData]},
        400: {"model": StandardErrorResponse},
    },
)
async def post_attack_scenario(
    attack_type: str,
    request: Request,
    attack_service: AttackService = Depends(get_attack_service),
) -> Any:
    """Execute a controlled local cyberattack scenario and verify authoritative state invariants."""
    parameters: dict[str, Any] = {}
    try:
        body = await request.json()
        if isinstance(body, dict):
            parameters = body.get("parameters", {}) or {}
    except Exception:
        parameters = {}

    try:
        attack_data = await attack_service.execute_attack(
            attack_type_str=attack_type,
            parameters=parameters,
        )
    except ValueError as val_err:
        err_envelope = StandardErrorResponse(
            error=ErrorDetail(
                code="INVALID_ATTACK_TYPE",
                message=str(val_err),
            )
        )
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=err_envelope.model_dump())

    return StandardResponse(data=attack_data)


@router.get(
    "/api/attacks/history",
    response_model=StandardResponse[list[dict[str, Any]]],
    summary="Query Cyberattack Scenario History",
)
async def get_attacks_history(
    limit: int = Query(default=50, ge=1, le=500, description="Max attack runs to retrieve"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    attack_service: AttackService = Depends(get_attack_service),
) -> StandardResponse[list[dict[str, Any]]]:
    """Retrieve paginated audit history of executed cyberattack scenarios."""
    history = await attack_service.get_attack_history(limit=limit, offset=offset)
    return StandardResponse(data=history)


# --- WebSocket Endpoint ---

@router.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None),
) -> None:
    """Real-time downstream telemetry broadcasting and keepalive ping/pong endpoint."""
    app = websocket.app
    ws_hub: WebSocketHub = app.state.ws_hub
    drone_engine: DroneEngine = app.state.drone_engine

    await ws_hub.connect(websocket)

    # Immediately transmit baseline telemetry snapshot upon connection
    snapshot = drone_engine.get_state_snapshot()
    await ws_hub.send_initial_telemetry(websocket, snapshot)

    # Listen for client upstream messages (heartbeat/ping)
    await ws_hub.handle_client_messages(websocket)
