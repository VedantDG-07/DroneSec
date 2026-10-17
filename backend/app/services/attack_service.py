"""Attack orchestration service coordinating scenario executions and persistent logging."""

from __future__ import annotations

import asyncio
from typing import Any, Optional
from fastapi.testclient import TestClient

from backend.app.api.schemas import AttackRunResponseData, CoordinatesDrift
from backend.app.attacks.attack_types import AttackScenarioType
from backend.app.attacks.payload_factory import PayloadFactory
from backend.app.attacks.scenario_runner import AttackScenarioRunner, ScenarioResult
from backend.app.core.drone_engine import DroneEngine
from backend.app.persistence.repositories import AttackRunRecord, AttackRunRepository
from backend.app.security.crypto_service import CryptoService
from backend.app.security.security_service import SecurityService


class MockResponse:
    """Mock HTTP response matching requests/httpx API for internal direct testing."""

    def __init__(self, status_code: int, data: dict[str, Any]):
        self.status_code = status_code
        self._data = data

    def json(self) -> dict[str, Any]:
        return self._data


class InternalDirectClient:
    """In-memory direct client executing commands through the authoritative service pipeline."""

    def __init__(self, command_service: Any, security_service: Any) -> None:
        self.command_service = command_service
        self.security_service = security_service

    async def apost(
        self,
        url: str,
        json: Any = None,
        headers: Optional[dict[str, str]] = None,
    ) -> MockResponse:
        from backend.app.api.schemas import CommandRequest
        from backend.app.security.message_protocol import SecurityMode
        from backend.app.security.security_service import SecurityPipelineError

        raw_payload = json if json is not None else {}
        headers_dict = headers or {}
        auth_header = headers_dict.get("Authorization")
        client_ip = "127.0.0.1"

        if not isinstance(raw_payload, dict):
            return MockResponse(
                400,
                {"status": "error", "error": {"code": "INVALID_PAYLOAD", "message": "Payload must be a JSON object."}},
            )

        if self.security_service.current_mode == SecurityMode.UNSECURED and "header" not in raw_payload:
            try:
                CommandRequest(**raw_payload)
            except Exception:
                return MockResponse(
                    422,
                    {"status": "error", "error": {"code": "INVALID_SCHEMA", "message": "Schema validation failed."}},
                )

        try:
            outcome = await self.command_service.process_and_execute(
                raw_payload=raw_payload,
                authorization_header=auth_header,
                source_ip=client_ip,
            )
        except SecurityPipelineError as err:
            return MockResponse(
                err.status_code,
                {
                    "status": "error",
                    "error": {
                        "code": err.error_code,
                        "message": err.message,
                        "details": err.details,
                    },
                },
            )

        if not outcome.success:
            return MockResponse(
                400,
                {
                    "status": "error",
                    "error": {
                        "code": outcome.error_code or "COMMAND_FAILED",
                        "message": outcome.error_message or "Execution failed.",
                    },
                },
            )

        return MockResponse(
            200,
            {
                "status": "success",
                "data": {
                    "command_id": outcome.command_id,
                    "command": outcome.command,
                    "execution_status": outcome.execution_status,
                    "state_version_after": outcome.state_version_after,
                    "drone_position": outcome.drone_position,
                    "processing_latency_ms": outcome.processing_latency_ms,
                },
            },
        )


class AttackService:
    """High-level service coordinating attack scenarios, invariant verification, and audit logging."""

    def __init__(
        self,
        drone_engine: DroneEngine,
        security_service: SecurityService,
        attack_repo: AttackRunRepository,
        crypto_service: CryptoService,
        command_service: Optional[Any] = None,
        app: Any = None,
        http_client: Any = None,
        bearer_token: str = "valid_secret_token",
    ) -> None:
        self.engine = drone_engine
        self.security_service = security_service
        self.command_service = command_service
        self.attack_repo = attack_repo
        self.crypto_service = crypto_service
        self._app = app
        self._custom_client = http_client
        self.bearer_token = bearer_token
        self.factory = PayloadFactory(crypto_service=crypto_service)
        self._runner: Optional[AttackScenarioRunner] = None
        self._lock = asyncio.Lock()

    def get_runner(self) -> AttackScenarioRunner:
        """Lazy-initialize or return the scenario runner."""
        if self._runner is not None:
            return self._runner

        if self._custom_client is not None:
            client = self._custom_client
        elif self.command_service is not None:
            client = InternalDirectClient(self.command_service, self.security_service)
        elif self._app is not None:
            client = TestClient(self._app)
        else:
            raise RuntimeError("AttackService requires either a command_service, an ASGI app, or an http_client.")

        self._runner = AttackScenarioRunner(http_client=client, drone_engine=self.engine)
        return self._runner

    def set_client(self, client: Any) -> None:
        """Explicitly override the HTTP test client."""
        self._custom_client = client
        self._runner = AttackScenarioRunner(http_client=client, drone_engine=self.engine)

    def cancel_active_attack(self) -> bool:
        """Signal the currently executing attack scenario to terminate immediately."""
        if self._runner is not None:
            return self._runner.cancel()
        return False

    async def execute_attack(
        self,
        attack_type_str: str,
        parameters: Optional[dict[str, Any]] = None,
    ) -> AttackRunResponseData:
        """Execute a controlled attack scenario, persist the record, and return contract-compliant data."""
        async with self._lock:
            scenario_enum = AttackScenarioType.from_string(attack_type_str)
            runner = self.get_runner()
            current_mode = self.security_service.current_mode.value

            try:
                result: ScenarioResult = await runner.run_scenario(
                    scenario_type=scenario_enum,
                    security_mode=current_mode,
                    parameters=parameters,
                    factory=self.factory,
                    bearer_token=self.bearer_token,
                )
            except Exception:
                runner.cancel()
                raise

            # Persist attack run record in SQLite
            await self.attack_repo.log_attack_run_async(
                id=result.run_id,
                timestamp=result.finished_at,
                scenario_type=result.scenario_type.name,
                security_mode=result.security_mode_active,
                attack_result=result.attack_status.value,
                defense_triggered=result.defense_triggered,
                state_compromised=result.state_compromised,
                initial_state_version=result.state_version_initial,
                final_state_version=result.state_version_final,
                coordinates_drift=result.coordinates_drift,
                payload_injected=result.payload_injected,
                execution_duration_ms=result.execution_duration_ms,
            )

            return AttackRunResponseData(
                attack_run_id=result.run_id,
                attack_type=result.scenario_type.name,
                security_mode_active=result.security_mode_active,
                payload_injected=result.payload_injected,
                attack_result=result.attack_status.value,
                defense_triggered=result.defense_triggered,
                state_compromised=result.state_compromised,
                initial_state_version=result.state_version_initial,
                final_state_version=result.state_version_final,
                coordinates_drift=CoordinatesDrift(**result.coordinates_drift),
                execution_duration_ms=round(result.execution_duration_ms, 2),
            )

    async def get_attack_history(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query historically executed attack runs."""
        records: list[AttackRunRecord] = await self.attack_repo.get_attack_runs_async(
            limit=limit,
            offset=offset,
        )
        return [
            {
                "attack_run_id": r.id,
                "timestamp": r.timestamp,
                "attack_type": r.scenario_type,
                "security_mode_active": r.security_mode,
                "attack_result": r.attack_result,
                "defense_triggered": r.defense_triggered,
                "state_compromised": r.state_compromised,
                "initial_state_version": r.initial_state_version,
                "final_state_version": r.final_state_version,
                "coordinates_drift": r.coordinates_drift,
                "payload_injected": r.payload_injected,
                "execution_duration_ms": r.execution_duration_ms,
            }
            for r in records
        ]
