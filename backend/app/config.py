"""Configuration management for the Drone Security Simulation Platform."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AppConfig:
    """Application configuration settings."""

    # Persistence
    db_path: str = field(
        default_factory=lambda: os.getenv(
            "SIM_DB_PATH",
            str(Path(__file__).resolve().parent.parent.parent / "data" / "simulation.db"),
        )
    )

    # Telemetry and Tick Rates
    telemetry_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("SIM_TELEMETRY_INTERVAL", "0.1"))
    )
    simulation_tick_rate_hz: float = field(
        default_factory=lambda: float(os.getenv("SIM_TICK_RATE_HZ", "20.0"))
    )
    max_telemetry_buffer_size: int = field(
        default_factory=lambda: int(os.getenv("SIM_MAX_TELEMETRY_BUFFER", "500"))
    )

    # Geographic Origin
    origin_latitude: float = field(
        default_factory=lambda: float(os.getenv("SIM_ORIGIN_LATITUDE", "37.774929"))
    )
    origin_longitude: float = field(
        default_factory=lambda: float(os.getenv("SIM_ORIGIN_LONGITUDE", "-122.419416"))
    )
    origin_altitude_msl: float = field(
        default_factory=lambda: float(os.getenv("SIM_ORIGIN_ALTITUDE_MSL", "15.0"))
    )

    # Environment & Deployment
    app_env: str = field(
        default_factory=lambda: os.getenv("APP_ENV", os.getenv("SIM_ENV", "development")).lower()
    )
    require_admin_auth: bool = field(
        default_factory=lambda: os.getenv("SIM_REQUIRE_ADMIN_AUTH", "false").lower() in ("true", "1", "yes")
    )
    max_request_body_bytes: int = field(
        default_factory=lambda: int(os.getenv("SIM_MAX_REQUEST_BYTES", str(64 * 1024)))
    )

    # CORS and Host (Least Privilege Defaults)
    cors_origins: list[str] = field(
        default_factory=lambda: (
            os.getenv("SIM_CORS_ORIGINS").split(",")
            if os.getenv("SIM_CORS_ORIGINS")
            else ["http://127.0.0.1:8000", "http://localhost:8000", "http://127.0.0.1:3000", "http://localhost:3000"]
        )
    )
    app_host: str = field(default_factory=lambda: os.getenv("SIM_HOST", "127.0.0.1"))
    app_port: int = field(default_factory=lambda: int(os.getenv("SIM_PORT", "8000")))

    # Security Configuration (Phase 3)
    security_mode: str = field(
        default_factory=lambda: os.getenv("SIM_SECURITY_MODE", "UNSECURED")
    )
    aes_256_key: Optional[bytes] = field(
        default_factory=lambda: bytes.fromhex(os.getenv("SIM_AES_256_KEY"))
        if os.getenv("SIM_AES_256_KEY")
        else None
    )
    hmac_sha256_key: Optional[bytes] = field(
        default_factory=lambda: bytes.fromhex(os.getenv("SIM_HMAC_SHA256_KEY"))
        if os.getenv("SIM_HMAC_SHA256_KEY")
        else None
    )
    gcs_bearer_token: str = field(
        default_factory=lambda: os.getenv(
            "SIM_GCS_BEARER_TOKEN", "gcs-sim-token-secret-2026"
        )
    )
    authorized_sender: str = field(
        default_factory=lambda: os.getenv("SIM_AUTHORIZED_SENDER", "GCS-PRIMARY")
    )
    timestamp_freshness_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("SIM_TIMESTAMP_WINDOW_SECONDS", "5.0"))
    )
    sequence_window_size: int = field(
        default_factory=lambda: int(os.getenv("SIM_SEQUENCE_WINDOW_SIZE", "64"))
    )
    rate_limit_refill_rate: float = field(
        default_factory=lambda: float(os.getenv("SIM_RATE_LIMIT_REFILL_RATE", "10.0"))
    )
    rate_limit_capacity: int = field(
        default_factory=lambda: int(os.getenv("SIM_RATE_LIMIT_CAPACITY", "20"))
    )

    def __post_init__(self) -> None:
        """Enforce strict security validation for production environments."""
        if self.app_env in ("production", "prod"):
            # Prevent silent use of demonstration Bearer credentials in production
            if self.gcs_bearer_token == "gcs-sim-token-secret-2026":
                raise ValueError(
                    "Production environment cannot use default demonstration Bearer token ('gcs-sim-token-secret-2026'). Set SIM_GCS_BEARER_TOKEN."
                )
            # Prevent missing keys in secured modes under production
            if self.security_mode != "UNSECURED":
                if self.aes_256_key is None or self.hmac_sha256_key is None:
                    raise ValueError(
                        f"Production environment in {self.security_mode} mode requires explicit SIM_AES_256_KEY and SIM_HMAC_SHA256_KEY."
                    )
            # Disallow wildcard CORS in production
            if "*" in self.cors_origins:
                raise ValueError(
                    "Production environment cannot use wildcard ('*') CORS origins. Set explicit origins in SIM_CORS_ORIGINS."
                )


# Default global instance
config = AppConfig()

