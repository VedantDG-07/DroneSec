"""Repositories for persistent audit logging of commands and security incidents."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Optional

from backend.app.persistence.database import DatabaseManager


@dataclass
class CommandLogRecord:
    """Persistent representation of an executed or rejected flight command."""

    id: str
    timestamp: float
    client_id: str
    command: str
    parameters: Optional[dict[str, Any]]
    status: str  # "EXECUTED" or "REJECTED"
    state_version_before: int
    state_version_after: int
    error_code: Optional[str]
    error_message: Optional[str]
    execution_duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = "COMMAND"
        d["severity"] = "INFO" if self.status == "EXECUTED" else "WARNING"
        return d


@dataclass
class SecurityEventRecord:
    """Persistent representation of a security violation or audit alert."""

    id: str
    timestamp: float
    event_code: str
    severity: str  # "INFO", "WARNING", "CRITICAL"
    source_ip: Optional[str]
    sender_id: Optional[str]
    message: str
    details: Optional[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = "SECURITY_EVENT"
        return d


class CommandLogRepository:
    """Repository handling persistence and queries for drone command executions."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db = db_manager

    def log_command(
        self,
        client_id: str,
        command: str,
        parameters: Optional[dict[str, Any]],
        status: str,
        state_version_before: int,
        state_version_after: int,
        execution_duration_ms: float,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        command_id: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> CommandLogRecord:
        """Insert a command execution record into the database."""
        record_id = command_id or str(uuid.uuid4())
        record_time = timestamp if timestamp is not None else time.time()
        param_json = json.dumps(parameters) if parameters is not None else None

        conn = self._db.get_connection()
        try:
            with conn:
                try:
                    conn.execute(
                        """
                        INSERT INTO command_logs (
                            id, timestamp, client_id, command, parameters, status,
                            state_version_before, state_version_after, error_code,
                            error_message, execution_duration_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            record_id,
                            record_time,
                            client_id,
                            command,
                            param_json,
                            status,
                            state_version_before,
                            state_version_after,
                            error_code,
                            error_message,
                            execution_duration_ms,
                        ),
                    )
                except sqlite3.IntegrityError:
                    record_id = f"{record_id}_dup_{int(time.time()*1000)}"
                    conn.execute(
                        """
                        INSERT INTO command_logs (
                            id, timestamp, client_id, command, parameters, status,
                            state_version_before, state_version_after, error_code,
                            error_message, execution_duration_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            record_id,
                            record_time,
                            client_id,
                            command,
                            param_json,
                            status,
                            state_version_before,
                            state_version_after,
                            error_code,
                            error_message,
                            execution_duration_ms,
                        ),
                    )
        finally:
            conn.close()

        return CommandLogRecord(
            id=record_id,
            timestamp=record_time,
            client_id=client_id,
            command=command,
            parameters=parameters,
            status=status,
            state_version_before=state_version_before,
            state_version_after=state_version_after,
            error_code=error_code,
            error_message=error_message,
            execution_duration_ms=execution_duration_ms,
        )

    async def log_command_async(self, **kwargs: Any) -> CommandLogRecord:
        """Asynchronously insert a command log record."""
        return await asyncio.to_thread(self.log_command, **kwargs)

    def get_command_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> list[CommandLogRecord]:
        """Query command logs with pagination and optional status filter."""
        conn = self._db.get_connection()
        try:
            query = "SELECT * FROM command_logs"
            params: list[Any] = []
            if status:
                query += " WHERE status = ?"
                params.append(status)
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
            params.extend([limit, offset])

            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()

            records: list[CommandLogRecord] = []
            for row in rows:
                params_dict = json.loads(row["parameters"]) if row["parameters"] else None
                records.append(
                    CommandLogRecord(
                        id=row["id"],
                        timestamp=row["timestamp"],
                        client_id=row["client_id"],
                        command=row["command"],
                        parameters=params_dict,
                        status=row["status"],
                        state_version_before=row["state_version_before"],
                        state_version_after=row["state_version_after"],
                        error_code=row["error_code"],
                        error_message=row["error_message"],
                        execution_duration_ms=row["execution_duration_ms"],
                    )
                )
            return records
        finally:
            conn.close()

    async def get_command_logs_async(
        self, limit: int = 100, offset: int = 0, status: Optional[str] = None
    ) -> list[CommandLogRecord]:
        return await asyncio.to_thread(self.get_command_logs, limit, offset, status)


class SecurityEventRepository:
    """Repository handling persistence and queries for security incidents and audit alerts."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db = db_manager

    def log_event(
        self,
        event_code: str,
        severity: str,
        message: str,
        source_ip: Optional[str] = None,
        sender_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> SecurityEventRecord:
        """Insert a security event into the database."""
        rec_id = event_id or str(uuid.uuid4())
        rec_time = timestamp if timestamp is not None else time.time()
        details_json = json.dumps(details) if details is not None else None

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO security_events (
                        id, timestamp, event_code, severity, source_ip,
                        sender_id, message, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        rec_id,
                        rec_time,
                        event_code,
                        severity,
                        source_ip,
                        sender_id,
                        message,
                        details_json,
                    ),
                )
        finally:
            conn.close()

        return SecurityEventRecord(
            id=rec_id,
            timestamp=rec_time,
            event_code=event_code,
            severity=severity,
            source_ip=source_ip,
            sender_id=sender_id,
            message=message,
            details=details,
        )

    async def log_event_async(self, **kwargs: Any) -> SecurityEventRecord:
        """Asynchronously insert a security event record."""
        return await asyncio.to_thread(self.log_event, **kwargs)

    def get_security_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        event_code: Optional[str] = None,
    ) -> list[SecurityEventRecord]:
        """Query security events with pagination and filters."""
        conn = self._db.get_connection()
        try:
            query = "SELECT * FROM security_events"
            conditions: list[str] = []
            params: list[Any] = []

            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            if event_code:
                conditions.append("event_code = ?")
                params.append(event_code)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
            params.extend([limit, offset])

            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()

            records: list[SecurityEventRecord] = []
            for row in rows:
                details_dict = json.loads(row["details"]) if row["details"] else None
                records.append(
                    SecurityEventRecord(
                        id=row["id"],
                        timestamp=row["timestamp"],
                        event_code=row["event_code"],
                        severity=row["severity"],
                        source_ip=row["source_ip"],
                        sender_id=row["sender_id"],
                        message=row["message"],
                        details=details_dict,
                    )
                )
            return records
        finally:
            conn.close()

    async def get_security_events_async(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        event_code: Optional[str] = None,
    ) -> list[SecurityEventRecord]:
        return await asyncio.to_thread(
            self.get_security_events, limit, offset, severity, event_code
        )


@dataclass
class AttackRunRecord:
    """Persistent representation of an executed attack simulation run."""

    id: str
    timestamp: float
    scenario_type: str
    security_mode: str
    attack_result: str
    defense_triggered: Optional[str]
    state_compromised: bool
    initial_state_version: int
    final_state_version: int
    coordinates_drift: dict[str, float]
    payload_injected: dict[str, Any]
    execution_duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = "ATTACK"
        d["severity"] = "CRITICAL" if self.state_compromised else "INFO"
        return d


class AttackRunRepository:
    """Repository handling persistence and queries for cyberattack simulation runs."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db = db_manager

    def log_attack_run(
        self,
        id: str,
        timestamp: float,
        scenario_type: str,
        security_mode: str,
        attack_result: str,
        defense_triggered: Optional[str],
        state_compromised: bool,
        initial_state_version: int,
        final_state_version: int,
        coordinates_drift: dict[str, float],
        payload_injected: dict[str, Any],
        execution_duration_ms: float,
    ) -> AttackRunRecord:
        """Insert an attack run record into the database."""
        drift_json = json.dumps(coordinates_drift)
        payload_json = json.dumps(payload_injected)

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO attack_runs (
                        id, timestamp, scenario_type, security_mode, attack_result,
                        defense_triggered, state_compromised, initial_state_version,
                        final_state_version, coordinates_drift, payload_injected,
                        execution_duration_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        id,
                        timestamp,
                        scenario_type,
                        security_mode,
                        attack_result,
                        defense_triggered,
                        1 if state_compromised else 0,
                        initial_state_version,
                        final_state_version,
                        drift_json,
                        payload_json,
                        execution_duration_ms,
                    ),
                )
        finally:
            conn.close()

        return AttackRunRecord(
            id=id,
            timestamp=timestamp,
            scenario_type=scenario_type,
            security_mode=security_mode,
            attack_result=attack_result,
            defense_triggered=defense_triggered,
            state_compromised=state_compromised,
            initial_state_version=initial_state_version,
            final_state_version=final_state_version,
            coordinates_drift=coordinates_drift,
            payload_injected=payload_injected,
            execution_duration_ms=execution_duration_ms,
        )

    async def log_attack_run_async(self, **kwargs: Any) -> AttackRunRecord:
        """Asynchronously insert an attack run record."""
        return await asyncio.to_thread(self.log_attack_run, **kwargs)

    def get_attack_runs(self, limit: int = 50, offset: int = 0) -> list[AttackRunRecord]:
        """Query attack runs ordered by timestamp descending."""
        conn = self._db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM attack_runs ORDER BY timestamp DESC LIMIT ? OFFSET ?;",
                (limit, offset),
            )
            rows = cursor.fetchall()
            cursor.close()

            records: list[AttackRunRecord] = []
            for row in rows:
                drift = (
                    json.loads(row["coordinates_drift"])
                    if row["coordinates_drift"]
                    else {"delta_x": 0.0, "delta_y": 0.0, "delta_z": 0.0}
                )
                payload = json.loads(row["payload_injected"]) if row["payload_injected"] else {}
                records.append(
                    AttackRunRecord(
                        id=row["id"],
                        timestamp=row["timestamp"],
                        scenario_type=row["scenario_type"],
                        security_mode=row["security_mode"],
                        attack_result=row["attack_result"],
                        defense_triggered=row["defense_triggered"],
                        state_compromised=bool(row["state_compromised"]),
                        initial_state_version=row["initial_state_version"],
                        final_state_version=row["final_state_version"],
                        coordinates_drift=drift,
                        payload_injected=payload,
                        execution_duration_ms=row["execution_duration_ms"],
                    )
                )
            return records
        finally:
            conn.close()

    async def get_attack_runs_async(self, limit: int = 50, offset: int = 0) -> list[AttackRunRecord]:
        return await asyncio.to_thread(self.get_attack_runs, limit, offset)


class LogQueryRepository:
    """Unified log query repository supporting GET /api/logs with mixed categories and filters."""

    def __init__(
        self,
        cmd_repo: CommandLogRepository,
        sec_repo: SecurityEventRepository,
        attack_repo: Optional[AttackRunRepository] = None,
    ) -> None:
        self.cmd_repo = cmd_repo
        self.sec_repo = sec_repo
        self.attack_repo = attack_repo

    async def query_logs(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query and merge logs across commands, security events, and attack runs."""
        results: list[dict[str, Any]] = []

        include_commands = category is None or category.upper() == "COMMAND"
        include_security = category is None or category.upper() == "SECURITY_EVENT"
        include_attacks = (category is None or category.upper() == "ATTACK") and self.attack_repo is not None

        # Fetch extra to sort and slice correctly when combining categories
        fetch_limit = limit + offset

        if include_commands:
            # Map severity to command status if specified
            status_filter = None
            if severity:
                if severity.upper() == "INFO":
                    status_filter = "EXECUTED"
                elif severity.upper() in {"WARNING", "CRITICAL"}:
                    status_filter = "REJECTED"

            cmds = await self.cmd_repo.get_command_logs_async(limit=fetch_limit, offset=0, status=status_filter)
            results.extend([c.to_dict() for c in cmds])

        if include_security:
            sec_events = await self.sec_repo.get_security_events_async(
                limit=fetch_limit, offset=0, severity=severity
            )
            results.extend([s.to_dict() for s in sec_events])

        if include_attacks and self.attack_repo is not None:
            attacks = await self.attack_repo.get_attack_runs_async(limit=fetch_limit, offset=0)
            results.extend([a.to_dict() for a in attacks])

        # Sort descending by timestamp
        results.sort(key=lambda x: x["timestamp"], reverse=True)

        return results[offset : offset + limit]
