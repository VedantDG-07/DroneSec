"""Pydantic schemas for REST API and WebSocket contracts per docs/api-contract.md."""

from __future__ import annotations

import time
from typing import Any, Generic, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field


T = TypeVar("T")


class ErrorDetail(BaseModel):
    """Detailed error object inside standard error responses."""

    code: str
    message: str
    details: Optional[dict[str, Any]] = None


class StandardResponse(BaseModel, Generic[T]):
    """Standard success envelope."""

    status: str = "success"
    data: T
    timestamp: float = Field(default_factory=time.time)


class StandardErrorResponse(BaseModel):
    """Standard error envelope."""

    status: str = "error"
    error: ErrorDetail
    timestamp: float = Field(default_factory=time.time)


# --- Subsystem Data Models ---

class PositionModel(BaseModel):
    x: float
    y: float
    z: float


class GeographicModel(BaseModel):
    latitude: float
    longitude: float
    altitude_msl: float


class MotionModel(BaseModel):
    heading: float
    speed: float


class BatteryModel(BaseModel):
    level_percent: float
    voltage_volts: float
    state_of_health: str


class DroneStateData(BaseModel):
    """Authoritative drone state vector response model."""

    state_version: int
    timestamp: float
    flight_state: str
    armed: bool
    position: PositionModel
    geographic: GeographicModel
    motion: MotionModel
    battery: BatteryModel
    last_command_id: Optional[str] = None


class CommandRequest(BaseModel):
    """Command submission request schema for UNSECURED mode."""

    model_config = ConfigDict(extra="forbid")

    command: str
    parameters: Optional[dict[str, Any]] = None
    client_id: Optional[str] = "GCS_CLIENT"


class CommandExecutionData(BaseModel):
    """Data payload for successful command execution."""

    command_id: str
    command: str
    execution_status: str
    state_version_after: int
    drone_position: PositionModel
    processing_latency_ms: float


class TelemetryItem(BaseModel):
    """A single recorded telemetry record."""

    state_version: int
    timestamp: float
    flight_state: str
    armed: bool
    x: float
    y: float
    z: float
    latitude: float
    longitude: float
    altitude_msl: float
    heading: float
    speed: float
    battery_level: float


class TelemetryUpdatePayload(BaseModel):
    """Payload embedded in a TELEMETRY_UPDATE WebSocket frame."""

    state_version: int
    flight_state: str
    x: float
    y: float
    z: float
    latitude: float
    longitude: float
    altitude_msl: float
    heading: float
    speed: float
    battery_percent: float


class WebSocketTelemetryFrame(BaseModel):
    """Outbound TELEMETRY_UPDATE WebSocket broadcast frame."""

    type: str = "TELEMETRY_UPDATE"
    seq: int
    timestamp: float
    payload: TelemetryUpdatePayload


class HealthData(BaseModel):
    """System health check payload."""

    system_status: str
    uptime_seconds: float
    simulation_loop: dict[str, Any]
    database: dict[str, Any]
    memory_mb: float


class SecurityStatusData(BaseModel):
    """Current security configuration payload."""

    current_mode: str
    active_key_id: Optional[str]
    algorithms: dict[str, str]
    replay_protection: dict[str, Any]
    rate_limiting: dict[str, Any]


class SecurityModeRequest(BaseModel):
    """Payload for POST /api/security/mode."""

    model_config = ConfigDict(extra="forbid")

    mode: str
    reason: Optional[str] = ""


class SecurityModeResponseData(BaseModel):
    """Response data for POST /api/security/mode."""

    previous_mode: str
    new_mode: str
    transition_timestamp: float


# --- Cyberattack Simulator Models ---

class AttackParameters(BaseModel):
    """Optional configuration parameters for cyberattack simulation."""

    model_config = ConfigDict(extra="ignore")

    target_command: Optional[str] = "DISARM"
    tamper_coordinate_delta: Optional[float] = 500.0
    flood_count: Optional[int] = 40
    attempts: Optional[int] = 3


class AttackRequest(BaseModel):
    """Payload for POST /api/attacks/{attack_type}."""

    model_config = ConfigDict(extra="ignore")

    parameters: Optional[AttackParameters] = Field(default_factory=AttackParameters)


class CoordinatesDrift(BaseModel):
    """Position drift vector resulting from attack evaluation."""

    delta_x: float
    delta_y: float
    delta_z: float


class AttackRunResponseData(BaseModel):
    """Response data structure for POST /api/attacks/{attack_type} matching docs/api-contract.md."""

    attack_run_id: str
    attack_type: str
    security_mode_active: str
    payload_injected: dict[str, Any]
    attack_result: str
    defense_triggered: Optional[str] = None
    state_compromised: bool
    initial_state_version: int
    final_state_version: int
    coordinates_drift: CoordinatesDrift
    execution_duration_ms: float

