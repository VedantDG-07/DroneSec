"""Dual-verification anti-replay defense: timestamp freshness and 64-bit sliding sequence window."""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


DEFAULT_TIMESTAMP_TOLERANCE_SECONDS: float = 5.0
SLIDING_WINDOW_SIZE: int = 64
BITMASK_64_BITS: int = 0xFFFFFFFFFFFFFFFF


class ReplayVerificationError(Exception):
    """Raised when message timestamp is stale or sequence number is replayed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class _SenderReplayState:
    """Maintains 64-bit sliding window sequence tracking for an authenticated sender."""

    highest_seq: int = -1
    window_bitmask: int = 0  # 64-bit integer bitmask


@dataclass(frozen=True)
class ReplayCheckTicket:
    """Opaque verification ticket used for two-phase replay commit."""

    sender_id: str
    sequence_number: int
    proposed_highest_seq: int
    proposed_bitmask: int


class AntiReplayFilter:
    """Enforces timestamp freshness (|t - now| <= 5s) and 64-bit sliding-window sequence filter.
    
    Guarantees:
    1. Replay window advances only after cryptographic checks succeed (via two-phase commit).
    2. Sequence numbers older than N_max - 64 are dropped.
    3. Duplicate sequence numbers within the window are dropped.
    4. Thread-safe operations with bounded memory.
    """

    def __init__(
        self,
        timestamp_tolerance_seconds: float = DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
        window_size: int = SLIDING_WINDOW_SIZE,
        clock_func: Optional[Callable[[], float]] = None,
        max_senders: int = 1000,
    ) -> None:
        self.timestamp_tolerance = float(timestamp_tolerance_seconds)
        self.window_size = int(window_size)
        self.clock = clock_func or time.time
        self.max_senders = max_senders

        self._states: dict[str, _SenderReplayState] = {}
        self._lock = threading.Lock()

    def get_highest_sequence_number(self, sender_id: str = "DEFAULT") -> int:
        """Return highest sequence number processed for sender."""
        with self._lock:
            state = self._states.get(sender_id)
            return state.highest_seq if state else 0

    def check_freshness(self, timestamp: float) -> None:
        """Verify timestamp freshness against server clock."""
        if not math.isfinite(timestamp):
            raise ReplayVerificationError("TIMESTAMP_OUT_OF_BOUNDS", f"Timestamp must be finite. Got {timestamp}")

        server_time = self.clock()
        drift = abs(server_time - timestamp)
        if drift > self.timestamp_tolerance:
            raise ReplayVerificationError(
                "TIMESTAMP_OUT_OF_BOUNDS",
                f"Message timestamp {timestamp:.3f} deviates from server time {server_time:.3f} "
                f"by {drift:.3f}s (tolerance: {self.timestamp_tolerance:.1f}s).",
            )

    def verify_candidate(
        self,
        sender_id: str,
        sequence_number: int,
        timestamp: float,
    ) -> ReplayCheckTicket:
        """Stage 1: Verify freshness and sequence without permanently mutating the window.
        
        Returns a ReplayCheckTicket to be committed once crypto authentication passes.
        """
        # Step 1: Timestamp freshness gate
        self.check_freshness(timestamp)

        if sequence_number < 0:
            raise ReplayVerificationError(
                "REPLAY_ATTACK_DETECTED",
                f"Sequence number must be non-negative. Got {sequence_number}",
            )

        with self._lock:
            if sender_id not in self._states:
                if len(self._states) >= self.max_senders:
                    # Prune oldest state to prevent memory leak
                    self._states.pop(next(iter(self._states)))
                self._states[sender_id] = _SenderReplayState()

            state = self._states[sender_id]
            highest = state.highest_seq
            bitmask = state.window_bitmask

            # First message from sender
            if highest < 0:
                return ReplayCheckTicket(
                    sender_id=sender_id,
                    sequence_number=sequence_number,
                    proposed_highest_seq=sequence_number,
                    proposed_bitmask=1,
                )

            # Case A: Sequence is newer than highest seen
            if sequence_number > highest:
                shift = sequence_number - highest
                if shift >= self.window_size:
                    new_bitmask = 1
                else:
                    new_bitmask = ((bitmask << shift) | 1) & BITMASK_64_BITS

                return ReplayCheckTicket(
                    sender_id=sender_id,
                    sequence_number=sequence_number,
                    proposed_highest_seq=sequence_number,
                    proposed_bitmask=new_bitmask,
                )

            # Case B: Sequence is within the sliding window [highest - 63, highest]
            diff = highest - sequence_number
            if diff < self.window_size:
                offset_mask = 1 << diff
                if bitmask & offset_mask:
                    raise ReplayVerificationError(
                        "REPLAY_ATTACK_DETECTED",
                        f"Duplicate sequence number {sequence_number} detected within sliding window.",
                    )
                new_bitmask = bitmask | offset_mask
                return ReplayCheckTicket(
                    sender_id=sender_id,
                    sequence_number=sequence_number,
                    proposed_highest_seq=highest,
                    proposed_bitmask=new_bitmask,
                )

            # Case C: Sequence is older than sliding window horizon
            raise ReplayVerificationError(
                "REPLAY_ATTACK_DETECTED",
                f"Sequence number {sequence_number} is older than sliding window horizon "
                f"({highest - self.window_size + 1}).",
            )

    def commit_ticket(self, ticket: ReplayCheckTicket) -> None:
        """Stage 2: Atomically commit the replay window advance after crypto validation succeeds."""
        with self._lock:
            if ticket.sender_id not in self._states:
                self._states[ticket.sender_id] = _SenderReplayState()
            state = self._states[ticket.sender_id]
            state.highest_seq = ticket.proposed_highest_seq
            state.window_bitmask = ticket.proposed_bitmask

    def verify_and_commit(self, sender_id: str, sequence_number: int, timestamp: float) -> None:
        """Single-step check and commit."""
        ticket = self.verify_candidate(sender_id, sequence_number, timestamp)
        self.commit_ticket(ticket)

    def reset(self, sender_id: Optional[str] = None) -> None:
        """Reset replay tracking (for specific sender or all senders)."""
        with self._lock:
            if sender_id:
                self._states.pop(sender_id, None)
            else:
                self._states.clear()
