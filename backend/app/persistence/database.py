"""SQLite database initialization, connection management, and WAL mode configuration."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path
from typing import Optional


CREATE_COMMAND_LOGS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS command_logs (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    client_id TEXT NOT NULL,
    command TEXT NOT NULL,
    parameters TEXT,
    status TEXT NOT NULL,
    state_version_before INTEGER NOT NULL,
    state_version_after INTEGER NOT NULL,
    error_code TEXT,
    error_message TEXT,
    execution_duration_ms REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_command_logs_timestamp ON command_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_command_logs_status ON command_logs(status);
"""

CREATE_SECURITY_EVENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    event_code TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    sender_id TEXT,
    message TEXT NOT NULL,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
"""

CREATE_ATTACK_RUNS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS attack_runs (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    scenario_type TEXT NOT NULL,
    security_mode TEXT NOT NULL,
    attack_result TEXT NOT NULL,
    defense_triggered TEXT,
    state_compromised INTEGER NOT NULL,
    initial_state_version INTEGER NOT NULL,
    final_state_version INTEGER NOT NULL,
    coordinates_drift TEXT,
    payload_injected TEXT,
    execution_duration_ms REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_runs_timestamp ON attack_runs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_attack_runs_scenario ON attack_runs(scenario_type);
"""


class DatabaseManager:
    """Manages SQLite connection pooling, WAL mode initialization, and thread-safe transactions."""

    def __init__(self, db_path: str = "data/simulation.db") -> None:
        self.db_path = db_path
        self._ensure_parent_directory()

    def _ensure_parent_directory(self) -> None:
        """Ensure parent directory exists unless using in-memory database."""
        if self.db_path != ":memory:":
            parent = Path(self.db_path).resolve().parent
            parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a configured SQLite connection.
        
        Enables WAL mode, foreign keys, and dictionary-like row access.
        """
        conn = sqlite3.connect(
            self.db_path,
            timeout=10.0,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode; transactions managed explicitly
        )
        conn.row_factory = sqlite3.Row
        
        # Enable WAL mode and foreign key constraints
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()
        
        return conn

    def initialize_schema(self) -> None:
        """Initialize database schema idempotently."""
        conn = self.get_connection()
        try:
            with conn:
                conn.executescript(CREATE_COMMAND_LOGS_TABLE_SQL)
                conn.executescript(CREATE_SECURITY_EVENTS_TABLE_SQL)
                conn.executescript(CREATE_ATTACK_RUNS_TABLE_SQL)
        finally:
            conn.close()

    async def initialize_schema_async(self) -> None:
        """Asynchronously initialize schema without blocking the event loop."""
        await asyncio.to_thread(self.initialize_schema)

    def check_health(self) -> dict[str, any]:
        """Perform a liveness check on the database."""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            return {
                "status": "CONNECTED",
                "wal_mode": journal_mode.upper() == "WAL",
                "path": self.db_path,
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e),
                "wal_mode": False,
                "path": self.db_path,
            }

    async def check_health_async(self) -> dict[str, any]:
        """Asynchronously check database health."""
        return await asyncio.to_thread(self.check_health)
