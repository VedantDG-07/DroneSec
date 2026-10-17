"""FastAPI application entrypoint, lifespan management, and dependency wiring."""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.api.routes import router
from backend.app.api.schemas import ErrorDetail, StandardErrorResponse
from backend.app.config import AppConfig, config as default_config
from backend.app.core.coordinate_service import CoordinateService
from backend.app.core.drone_engine import DroneEngine
from backend.app.evaluation.repository import EvaluationRepository
from backend.app.evaluation.runner import EvaluationRunner
from backend.app.persistence.database import DatabaseManager
from backend.app.persistence.repositories import (
    AttackRunRepository,
    CommandLogRepository,
    LogQueryRepository,
    SecurityEventRepository,
)
from backend.app.security.authentication import AuthenticationManager
from backend.app.security.crypto_service import CryptoService
from backend.app.security.key_manager import KeyManager
from backend.app.security.rate_limiter import TokenBucketRateLimiter
from backend.app.security.replay_protection import AntiReplayFilter
from backend.app.security.security_service import SecurityService
from backend.app.services.attack_service import AttackService
from backend.app.services.command_service import CommandService
from backend.app.services.telemetry_service import TelemetryService
from backend.app.websocket.hub import WebSocketHub


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager: handles startup and graceful shutdown."""
    # --- Startup ---
    db_manager: DatabaseManager = app.state.db_manager
    telemetry_service: TelemetryService = app.state.telemetry_service

    # Asynchronously initialize SQLite schema
    await db_manager.initialize_schema_async()

    # Start simulation tick and telemetry broadcasting loop
    telemetry_service.start_background_loop()
    app.state.start_time = time.time()

    yield

    # --- Shutdown ---
    await telemetry_service.stop_background_loop()


def create_app(
    app_config: Optional[AppConfig] = None,
    drone_engine: Optional[DroneEngine] = None,
    db_manager: Optional[DatabaseManager] = None,
    security_service: Optional[SecurityService] = None,
) -> FastAPI:
    """Create and configure a FastAPI application instance."""
    cfg = app_config or default_config

    app = FastAPI(
        title="Drone Communication Security Simulation Platform",
        version="1.0.0",
        description="Local-first UAV C2 communication security and telemetry simulation platform.",
        lifespan=lifespan,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials="*" not in cfg.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Enforce request payload size limit across all HTTP endpoints
    @app.middleware("http")
    async def limit_body_size(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > cfg.max_request_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "status": "error",
                            "error": {
                                "code": "PAYLOAD_TOO_LARGE",
                                "message": f"Request entity exceeds limit of {cfg.max_request_body_bytes} bytes.",
                            },
                        },
                    )
            except ValueError:
                pass
        return await call_next(request)

    # Initialize Authoritative Singletons
    coord_service = CoordinateService(
        origin_latitude=cfg.origin_latitude,
        origin_longitude=cfg.origin_longitude,
        origin_altitude_msl=cfg.origin_altitude_msl,
    )

    engine = drone_engine or DroneEngine(coordinate_service=coord_service)
    db = db_manager or DatabaseManager(db_path=cfg.db_path)
    ws_hub = WebSocketHub()
    state_lock = asyncio.Lock()

    # Repositories
    cmd_repo = CommandLogRepository(db)
    sec_repo = SecurityEventRepository(db)
    attack_repo = AttackRunRepository(db)
    eval_repo = EvaluationRepository(db)
    log_repo = LogQueryRepository(cmd_repo=cmd_repo, sec_repo=sec_repo, attack_repo=attack_repo)

    # Security Components
    key_manager = KeyManager(
        aes_key=cfg.aes_256_key,
        hmac_key=cfg.hmac_sha256_key,
    )
    crypto_service = CryptoService(key_manager=key_manager)
    auth_manager = AuthenticationManager(
        valid_bearer_token=cfg.gcs_bearer_token,
        authorized_senders=[cfg.authorized_sender],
    )
    replay_filter = AntiReplayFilter(
        timestamp_tolerance_seconds=cfg.timestamp_freshness_window_seconds,
        window_size=cfg.sequence_window_size,
    )
    rate_limiter = TokenBucketRateLimiter(
        capacity=cfg.rate_limit_capacity,
        refill_rate=cfg.rate_limit_refill_rate,
    )
    sec_service = security_service or SecurityService(
        key_manager=key_manager,
        crypto_service=crypto_service,
        auth_manager=auth_manager,
        replay_filter=replay_filter,
        rate_limiter=rate_limiter,
        sec_repo=sec_repo,
        initial_mode=cfg.security_mode,
        require_fail_closed_audit=True,
    )

    # Services
    telemetry_service = TelemetryService(
        drone_engine=engine,
        ws_hub=ws_hub,
        tick_rate_hz=cfg.simulation_tick_rate_hz,
        broadcast_interval_seconds=cfg.telemetry_interval_seconds,
        max_buffer_size=cfg.max_telemetry_buffer_size,
        state_lock=state_lock,
    )

    command_service = CommandService(
        drone_engine=engine,
        cmd_repo=cmd_repo,
        telemetry_service=telemetry_service,
        state_lock=state_lock,
        security_service=sec_service,
    )

    attack_service = AttackService(
        drone_engine=engine,
        security_service=sec_service,
        command_service=command_service,
        attack_repo=attack_repo,
        crypto_service=crypto_service,
        app=app,
        bearer_token=cfg.gcs_bearer_token,
    )

    eval_runner = EvaluationRunner(
        drone_engine=engine,
        command_service=command_service,
        security_service=sec_service,
        attack_service=attack_service,
        eval_repo=eval_repo,
        crypto_service=crypto_service,
        log_repo=log_repo,
        db_manager=db,
        bearer_token=cfg.gcs_bearer_token,
    )

    # Bind dependencies to app.state
    app.state.config = cfg
    app.state.drone_engine = engine
    app.state.db_manager = db
    app.state.ws_hub = ws_hub
    app.state.cmd_repo = cmd_repo
    app.state.sec_repo = sec_repo
    app.state.attack_repo = attack_repo
    app.state.eval_repo = eval_repo
    app.state.log_repo = log_repo
    app.state.key_manager = key_manager
    app.state.crypto_service = crypto_service
    app.state.auth_manager = auth_manager
    app.state.replay_filter = replay_filter
    app.state.config = cfg
    app.state.rate_limiter = rate_limiter
    app.state.security_service = sec_service
    app.state.telemetry_service = telemetry_service
    app.state.command_service = command_service
    app.state.attack_service = attack_service
    app.state.eval_runner = eval_runner
    app.state.start_time = time.time()

    # Register Exception Handlers for Standard Error Envelope
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = exc.errors()
        error_details = {
            "fields": [
                {
                    "loc": list(err.get("loc", [])),
                    "msg": err.get("msg"),
                    "type": err.get("type"),
                }
                for err in errors
            ]
        }
        error_resp = StandardErrorResponse(
            error=ErrorDetail(
                code="INVALID_SCHEMA",
                message="Request payload failed schema validation.",
                details=error_details,
            )
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_resp.model_dump(),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        error_resp = StandardErrorResponse(
            error=ErrorDetail(
                code="HTTP_ERROR" if exc.status_code != 404 else "NOT_FOUND",
                message=str(exc.detail),
            )
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_resp.model_dump(),
        )

    # Include REST & WebSocket Routes
    app.include_router(router)

    # Mount static frontend files if directory exists
    frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
    if frontend_dir.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    return app


# Default ASGI application instance for uvicorn
app = create_app()
