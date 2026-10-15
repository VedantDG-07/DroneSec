"""Unit tests for SQLite persistence, WAL mode, and repository operations."""

import asyncio
from pathlib import Path
import pytest

from backend.app.persistence.database import DatabaseManager
from backend.app.persistence.repositories import (
    CommandLogRecord,
    CommandLogRepository,
    LogQueryRepository,
    SecurityEventRecord,
    SecurityEventRepository,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an isolated temporary SQLite database."""
    db_file = tmp_path / "test_simulation.db"
    mgr = DatabaseManager(str(db_file))
    mgr.initialize_schema()
    return mgr


@pytest.fixture
def cmd_repo(temp_db: DatabaseManager) -> CommandLogRepository:
    return CommandLogRepository(temp_db)


@pytest.fixture
def sec_repo(temp_db: DatabaseManager) -> SecurityEventRepository:
    return SecurityEventRepository(temp_db)


@pytest.fixture
def unified_repo(
    cmd_repo: CommandLogRepository, sec_repo: SecurityEventRepository
) -> LogQueryRepository:
    return LogQueryRepository(cmd_repo=cmd_repo, sec_repo=sec_repo)


def test_database_initialization_and_wal_mode(temp_db: DatabaseManager):
    """Database initialization must be idempotent and enable WAL mode."""
    # First init already ran in fixture; run again to verify idempotency
    temp_db.initialize_schema()

    health = temp_db.check_health()
    assert health["status"] == "CONNECTED"
    assert health["wal_mode"] is True


def test_log_command_success(cmd_repo: CommandLogRepository):
    """Valid command execution must persist all fields accurately."""
    rec = cmd_repo.log_command(
        client_id="GCS_ALPHA",
        command="TAKEOFF",
        parameters={"altitude_meters": 5.0},
        status="EXECUTED",
        state_version_before=1,
        state_version_after=2,
        execution_duration_ms=1.45,
    )

    assert isinstance(rec, CommandLogRecord)
    assert rec.status == "EXECUTED"
    assert rec.command == "TAKEOFF"
    assert rec.parameters == {"altitude_meters": 5.0}

    # Query back
    logs = cmd_repo.get_command_logs(limit=10)
    assert len(logs) == 1
    assert logs[0].id == rec.id
    assert logs[0].command == "TAKEOFF"
    assert logs[0].state_version_after == 2


def test_log_rejected_command(cmd_repo: CommandLogRepository):
    """Rejected commands must persist with error_code and error_message."""
    rec = cmd_repo.log_command(
        client_id="GCS_ALPHA",
        command="MOVE_FORWARD",
        parameters={"distance_meters": 500.0},
        status="REJECTED",
        state_version_before=2,
        state_version_after=2,
        execution_duration_ms=0.85,
        error_code="BOUNDARY_LIMIT_EXCEEDED",
        error_message="Target position exceeds geofence.",
    )

    assert rec.status == "REJECTED"
    assert rec.error_code == "BOUNDARY_LIMIT_EXCEEDED"

    logs = cmd_repo.get_command_logs(status="REJECTED")
    assert len(logs) == 1
    assert logs[0].error_code == "BOUNDARY_LIMIT_EXCEEDED"


def test_command_logs_pagination_and_ordering(cmd_repo: CommandLogRepository):
    """Logs must return in reverse chronological order with limit and offset."""
    # Insert 15 records with increasing timestamps
    for i in range(15):
        cmd_repo.log_command(
            client_id="GCS_TEST",
            command=f"STEP_{i}",
            parameters=None,
            status="EXECUTED",
            state_version_before=i,
            state_version_after=i + 1,
            execution_duration_ms=1.0,
            timestamp=1000.0 + i,
        )

    # First page: 5 items (most recent: STEP_14 down to STEP_10)
    page1 = cmd_repo.get_command_logs(limit=5, offset=0)
    assert len(page1) == 5
    assert page1[0].command == "STEP_14"
    assert page1[4].command == "STEP_10"

    # Second page: 5 items (STEP_9 down to STEP_5)
    page2 = cmd_repo.get_command_logs(limit=5, offset=5)
    assert len(page2) == 5
    assert page2[0].command == "STEP_9"
    assert page2[4].command == "STEP_5"


def test_persistence_across_reconnect(tmp_path: Path):
    """Records written by one DatabaseManager instance must persist on reconnection."""
    db_file = tmp_path / "reconnect_test.db"
    
    mgr1 = DatabaseManager(str(db_file))
    mgr1.initialize_schema()
    repo1 = CommandLogRepository(mgr1)
    rec = repo1.log_command(
        client_id="GCS_PERSIST",
        command="ARM",
        parameters=None,
        status="EXECUTED",
        state_version_before=0,
        state_version_after=1,
        execution_duration_ms=0.5,
    )

    # Reconnect with a new DatabaseManager pointing to the same file
    mgr2 = DatabaseManager(str(db_file))
    repo2 = CommandLogRepository(mgr2)
    logs = repo2.get_command_logs()
    assert len(logs) == 1
    assert logs[0].id == rec.id
    assert logs[0].command == "ARM"


def test_security_event_logging(sec_repo: SecurityEventRepository):
    """Security incidents must be logged and filterable by severity and event_code."""
    sec_repo.log_event(
        event_code="REPLAY_ATTACK_DETECTED",
        severity="CRITICAL",
        message="Duplicate sequence number detected.",
        source_ip="192.168.1.50",
        sender_id="MALICIOUS_ACTOR",
        details={"replayed_seq": 105},
    )
    sec_repo.log_event(
        event_code="RATE_LIMIT_WARNING",
        severity="WARNING",
        message="Approaching token bucket threshold.",
    )

    critical_events = sec_repo.get_security_events(severity="CRITICAL")
    assert len(critical_events) == 1
    assert critical_events[0].event_code == "REPLAY_ATTACK_DETECTED"
    assert critical_events[0].details == {"replayed_seq": 105}


@pytest.mark.asyncio
async def test_unified_log_query(unified_repo: LogQueryRepository, cmd_repo: CommandLogRepository, sec_repo: SecurityEventRepository):
    """Unified repository must correctly interleave and paginate commands and security events."""
    await cmd_repo.log_command_async(
        client_id="GCS",
        command="TAKEOFF",
        parameters=None,
        status="EXECUTED",
        state_version_before=1,
        state_version_after=2,
        execution_duration_ms=1.0,
        timestamp=100.0,
    )
    await sec_repo.log_event_async(
        event_code="AUTH_CHECK_FAIL",
        severity="CRITICAL",
        message="Unauthorized command attempt.",
        timestamp=105.0,
    )
    await cmd_repo.log_command_async(
        client_id="GCS",
        command="MOVE_FORWARD",
        parameters=None,
        status="EXECUTED",
        state_version_before=2,
        state_version_after=3,
        execution_duration_ms=1.0,
        timestamp=110.0,
    )

    all_logs = await unified_repo.query_logs(limit=10)
    assert len(all_logs) == 3
    # Most recent first: timestamp 110 (COMMAND), 105 (SECURITY_EVENT), 100 (COMMAND)
    assert all_logs[0]["timestamp"] == 110.0
    assert all_logs[0]["category"] == "COMMAND"
    assert all_logs[1]["timestamp"] == 105.0
    assert all_logs[1]["category"] == "SECURITY_EVENT"
    assert all_logs[2]["timestamp"] == 100.0


@pytest.mark.asyncio
async def test_concurrent_logging(cmd_repo: CommandLogRepository):
    """Concurrent asynchronous log insertions must not produce sqlite3 lock errors."""
    async def insert_worker(worker_id: int):
        for i in range(20):
            await cmd_repo.log_command_async(
                client_id=f"WORKER_{worker_id}",
                command="TEST",
                parameters={"iter": i},
                status="EXECUTED",
                state_version_before=i,
                state_version_after=i + 1,
                execution_duration_ms=0.5,
            )

    # Run 5 concurrent workers = 100 insertions
    tasks = [insert_worker(w) for w in range(5)]
    await asyncio.gather(*tasks)

    logs = await cmd_repo.get_command_logs_async(limit=200)
    assert len(logs) == 100
