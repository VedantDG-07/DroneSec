"""Unit tests for anti-replay filtering and timestamp freshness validation (Phase 3)."""

from __future__ import annotations

import pytest
from backend.app.security.replay_protection import (
    AntiReplayFilter,
    ReplayVerificationError,
)


class FakeClock:
    def __init__(self, start_time: float = 1_000.0) -> None:
        self.current_time = start_time

    def __call__(self) -> float:
        return self.current_time

    def advance(self, delta_seconds: float) -> None:
        self.current_time += delta_seconds


class TestAntiReplayFilter:
    """Verifies sequence sliding window and timestamp validation."""

    def test_strictly_monotonic_sequence_accepted(self) -> None:
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(clock_func=clock)

        for seq in range(1, 100):
            ticket = filt.verify_candidate("sender_1", seq, 1_000.0)
            filt.commit_ticket(ticket)

        # highest_seq is tracked internally; last committed is 99
        state = filt._states["sender_1"]
        assert state.highest_seq == 99

    def test_duplicate_sequence_rejected(self) -> None:
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(clock_func=clock)

        ticket = filt.verify_candidate("sender_1", 10, 1_000.0)
        filt.commit_ticket(ticket)

        with pytest.raises(ReplayVerificationError) as exc_info:
            filt.verify_candidate("sender_1", 10, 1_000.0)
        # Actual code from implementation
        assert exc_info.value.code == "REPLAY_ATTACK_DETECTED"

    def test_out_of_order_within_window_accepted(self) -> None:
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(clock_func=clock)

        # Advance to 10
        ticket10 = filt.verify_candidate("sender_1", 10, 1_000.0)
        filt.commit_ticket(ticket10)

        # Out-of-order sequence 8 arrives (within 64-window of 10)
        ticket8 = filt.verify_candidate("sender_1", 8, 1_000.0)
        filt.commit_ticket(ticket8)

        # Sequence 8 cannot be submitted again
        with pytest.raises(ReplayVerificationError) as exc_info:
            filt.verify_candidate("sender_1", 8, 1_000.0)
        assert exc_info.value.code == "REPLAY_ATTACK_DETECTED"

        # Out-of-order sequence 5 arrives
        ticket5 = filt.verify_candidate("sender_1", 5, 1_000.0)
        filt.commit_ticket(ticket5)

    def test_sequence_behind_window_rejected(self) -> None:
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(window_size=64, clock_func=clock)

        # Advance to 100
        ticket100 = filt.verify_candidate("sender_1", 100, 1_000.0)
        filt.commit_ticket(ticket100)

        # Window horizon = highest - window_size + 1 = 100 - 64 + 1 = 37
        # Sequence 36 falls outside (horizon-1) -> rejected
        with pytest.raises(ReplayVerificationError) as exc_info:
            filt.verify_candidate("sender_1", 36, 1_000.0)
        assert exc_info.value.code == "REPLAY_ATTACK_DETECTED"

        # Sequence 37 is exactly at the lowest valid edge of the sliding window
        ticket37 = filt.verify_candidate("sender_1", 37, 1_000.0)
        filt.commit_ticket(ticket37)

    def test_timestamp_freshness_tolerance(self) -> None:
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(timestamp_tolerance_seconds=5.0, clock_func=clock)

        # Exactly on time
        ticket = filt.verify_candidate("s1", 1, 1_000.0)
        filt.commit_ticket(ticket)

        # 4.9s in past: allowed
        ticket = filt.verify_candidate("s1", 2, 995.1)
        filt.commit_ticket(ticket)

        # 4.9s in future (clock skew): allowed
        ticket = filt.verify_candidate("s1", 3, 1004.9)
        filt.commit_ticket(ticket)

    def test_stale_timestamp_rejected(self) -> None:
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(timestamp_tolerance_seconds=5.0, clock_func=clock)

        # 5.1s in past: rejected
        with pytest.raises(ReplayVerificationError) as exc_info:
            filt.verify_candidate("s1", 1, 994.9)
        assert exc_info.value.code == "TIMESTAMP_OUT_OF_BOUNDS"

    def test_future_skewed_timestamp_rejected(self) -> None:
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(timestamp_tolerance_seconds=5.0, clock_func=clock)

        # 5.1s in future: rejected
        with pytest.raises(ReplayVerificationError) as exc_info:
            filt.verify_candidate("s1", 1, 1005.1)
        assert exc_info.value.code == "TIMESTAMP_OUT_OF_BOUNDS"

    def test_two_phase_commit_failsafe(self) -> None:
        """Uncommitted tickets must NOT advance or pollute the replay window."""
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(clock_func=clock)

        # Verify candidate 1, but do NOT commit (e.g. crypto signature check failed)
        _ticket1 = filt.verify_candidate("s1", 1, 1_000.0)

        # Window state must remain clean (-1 highest sequence = no sender state committed)
        assert "s1" in filt._states
        assert filt._states["s1"].highest_seq == -1

        # Now a legitimate retry with seq 1 can be successfully verified and committed
        retry_ticket = filt.verify_candidate("s1", 1, 1_000.0)
        filt.commit_ticket(retry_ticket)
        assert filt._states["s1"].highest_seq == 1

    def test_sender_isolation(self) -> None:
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(clock_func=clock)

        ticket_a = filt.verify_candidate("sender_A", 1, 1_000.0)
        filt.commit_ticket(ticket_a)

        # sender_B can use sequence 1 independently
        ticket_b = filt.verify_candidate("sender_B", 1, 1_000.0)
        filt.commit_ticket(ticket_b)

        assert filt._states["sender_A"].highest_seq == 1
        assert filt._states["sender_B"].highest_seq == 1

    def test_negative_sequence_rejected(self) -> None:
        """Implementation rejects negative sequences; sequence 0 is treated as valid first message."""
        clock = FakeClock(1_000.0)
        filt = AntiReplayFilter(clock_func=clock)

        # Negative sequences are always rejected
        with pytest.raises(ReplayVerificationError) as exc_info:
            filt.verify_candidate("s1", -5, 1_000.0)
        assert exc_info.value.code == "REPLAY_ATTACK_DETECTED"

        with pytest.raises(ReplayVerificationError) as exc_info:
            filt.verify_candidate("s1", -1, 1_000.0)
        assert exc_info.value.code == "REPLAY_ATTACK_DETECTED"
