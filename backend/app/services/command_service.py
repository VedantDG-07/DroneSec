"""Command service managing serialized, atomic execution of drone flight commands."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from backend.app.core.drone_engine import DroneCommand, DroneEngine, DroneStateSnapshot
from backend.app.persistence.repositories import CommandLogRecord, CommandLogRepository
from backend.app.services.telemetry_service import TelemetryService

if TYPE_CHECKING:
    from backend.app.security.security_service import SecurityService


@dataclass
class ServiceCommandOutcome:
    """Outcome payload returned by the command execution service."""

    success: bool
    command_id: str
    command: str
    execution_status: str
    state_version_after: int
    drone_position: dict[str, float]
    processing_latency_ms: float
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    details: Optional[dict[str, Any]] = None


class CommandService:
    """Serializes flight command execution, guarantees state invariants, and coordinates persistence."""

    def __init__(
        self,
        drone_engine: DroneEngine,
        cmd_repo: CommandLogRepository,
        telemetry_service: TelemetryService,
        state_lock: Optional[asyncio.Lock] = None,
        security_service: Optional[SecurityService] = None,
    ) -> None:
        self.drone_engine = drone_engine
        self.cmd_repo = cmd_repo
        self.telemetry_service = telemetry_service
        self.state_lock = state_lock or asyncio.Lock()
        self.security_service = security_service

    async def process_and_execute(
        self,
        raw_payload: dict[str, Any],
        authorization_header: Optional[str] = None,
        source_ip: str = "127.0.0.1",
    ) -> ServiceCommandOutcome:
        """Run payload through security pipeline before atomic execution on the drone engine.
        
        Fail-Closed Guarantee:
        If any security check (rate limit, bearer auth, crypto tag, anti-replay) fails,
        the request aborts before any state lock is acquired and leaves drone state untouched.
        """
        if self.security_service is not None:
            sec_res = await self.security_service.verify_command_request(
                raw_payload=raw_payload,
                authorization_header=authorization_header,
                source_ip=source_ip,
            )
            command_str = sec_res.command
            parameters = sec_res.parameters
            client_id = sec_res.sender_id
            command_id = sec_res.message_id
        else:
            command_str = raw_payload.get("command", "")
            parameters = raw_payload.get("parameters")
            client_id = raw_payload.get("client_id", "GCS_CLIENT")
            command_id = None

        return await self.execute_command(
            command_str=command_str,
            parameters=parameters,
            client_id=client_id,
            command_id=command_id,
        )

    async def execute_command(
        self,
        command_str: str,
        parameters: Optional[dict[str, Any]] = None,
        client_id: str = "GCS_CLIENT",
        command_id: Optional[str] = None,
    ) -> ServiceCommandOutcome:
        """Execute a flight command atomically.
        
        Guarantees:
        1. Commands are serialized through state_lock to prevent race conditions.
        2. Database logging and WebSocket broadcasts execute outside the state lock.
        3. Failed commands leave the authoritative drone state vector completely untouched.
        """
        start_time = time.perf_counter()
        assigned_command_id = command_id or str(uuid.uuid4())

        # Validate command name against enum
        try:
            command_enum = DroneCommand(command_str.upper())
        except (ValueError, AttributeError):
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            cur_version = self.drone_engine.state_version
            cur_pos = {"x": self.drone_engine.x, "y": self.drone_engine.y, "z": self.drone_engine.z}

            # Persist rejection log
            await self.cmd_repo.log_command_async(
                client_id=client_id,
                command=str(command_str),
                parameters=parameters,
                status="REJECTED",
                state_version_before=cur_version,
                state_version_after=cur_version,
                execution_duration_ms=duration_ms,
                error_code="UNKNOWN_COMMAND",
                error_message=f"Command '{command_str}' is not recognized.",
                command_id=assigned_command_id,
            )

            return ServiceCommandOutcome(
                success=False,
                command_id=assigned_command_id,
                command=str(command_str),
                execution_status="REJECTED",
                state_version_after=cur_version,
                drone_position=cur_pos,
                processing_latency_ms=duration_ms,
                error_code="UNKNOWN_COMMAND",
                error_message=f"Command '{command_str}' is not recognized.",
            )

        # Extract movement parameter if provided
        distance = None
        if parameters and "distance_meters" in parameters:
            distance = parameters["distance_meters"]

        # Critical Section: Execute command atomically under state_lock
        async with self.state_lock:
            version_before = self.drone_engine.state_version
            result = self.drone_engine.execute_command(
                command=command_enum,
                distance_meters=distance,
                command_id=assigned_command_id,
            )
            snapshot_after = self.drone_engine.get_state_snapshot()
            version_after = snapshot_after.state_version

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        pos_dict = {"x": snapshot_after.x, "y": snapshot_after.y, "z": snapshot_after.z}

        # Outside Lock: Log execution outcome
        status_str = "EXECUTED" if result.success else "REJECTED"
        await self.cmd_repo.log_command_async(
            client_id=client_id,
            command=command_enum.value,
            parameters=parameters,
            status=status_str,
            state_version_before=version_before,
            state_version_after=version_after,
            execution_duration_ms=duration_ms,
            error_code=result.error_code,
            error_message=result.message if not result.success else None,
            command_id=assigned_command_id,
        )

        # If successful, publish updated state to WebSocket clients immediately
        if result.success:
            await self.telemetry_service.record_and_broadcast(snapshot_after)

        return ServiceCommandOutcome(
            success=result.success,
            command_id=assigned_command_id,
            command=command_enum.value,
            execution_status=status_str,
            state_version_after=version_after,
            drone_position=pos_dict,
            processing_latency_ms=duration_ms,
            error_code=result.error_code,
            error_message=result.message if not result.success else None,
        )
