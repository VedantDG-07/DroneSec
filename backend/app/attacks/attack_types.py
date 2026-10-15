"""Attack scenario type definitions and result status enumerations.

All scenarios are strictly local-only simulations against the embedded drone engine.
"""

from __future__ import annotations

from enum import Enum


class AttackScenarioType(str, Enum):
    """Canonical identifiers for the six supported attack scenarios (ATK-01 to ATK-06)."""

    UNAUTHORIZED_COMMAND = "ATK-01"       # Missing / invalid / wrong-sender credentials
    MESSAGE_TAMPERING = "ATK-02"          # Bit-flip ciphertext, tag, or HMAC payload
    COMMAND_REPLAY = "ATK-03"             # Re-submit a previously captured valid frame
    SENDER_SPOOFING = "ATK-04"            # Claim a different authorized sender_id
    MALFORMED_FUZZING = "ATK-05"          # Invalid JSON, bad types, unknown commands
    BOUNDED_FLOODING = "ATK-06"           # Configurable rate-limit exhaustion burst

    def __str__(self) -> str:  # pragma: no cover
        return self.value

    @classmethod
    def description(cls, scenario: "AttackScenarioType") -> str:
        return {
            cls.UNAUTHORIZED_COMMAND: (
                "ATK-01: Unauthorized Command Injection — "
                "Submits commands without, or with invalid, Bearer credentials."
            ),
            cls.MESSAGE_TAMPERING: (
                "ATK-02: Message Tampering (Bit-Flip) — "
                "Intercepts and mutates a valid AES-GCM or HMAC-signed envelope."
            ),
            cls.COMMAND_REPLAY: (
                "ATK-03: Command Replay Attack — "
                "Re-submits a captured valid frame after its freshness window expires."
            ),
            cls.SENDER_SPOOFING: (
                "ATK-04: Spoofed GCS Identity — "
                "Uses a valid token but claims a different sender_id in the header."
            ),
            cls.MALFORMED_FUZZING: (
                "ATK-05: Malformed Payload & Fuzzing — "
                "Injects structurally corrupt or semantically invalid payloads."
            ),
            cls.BOUNDED_FLOODING: (
                "ATK-06: Bounded Flooding / Rate-Limit Exhaustion — "
                "Sends a capped burst of requests to exercise token-bucket enforcement."
            ),
        }[scenario]

    @classmethod
    def from_string(cls, value: str) -> "AttackScenarioType":
        """Resolve scenario type from various naming conventions (e.g. 'unauthorized_command', 'ATK-01', 'UNAUTHORIZED_COMMAND')."""
        normalized = value.strip().upper().replace("-", "_")
        aliases = {
            "ATK_01": cls.UNAUTHORIZED_COMMAND,
            "ATK_1": cls.UNAUTHORIZED_COMMAND,
            "UNAUTHORIZED_COMMAND": cls.UNAUTHORIZED_COMMAND,
            "UNAUTHORIZED": cls.UNAUTHORIZED_COMMAND,
            "ATK_02": cls.MESSAGE_TAMPERING,
            "ATK_2": cls.MESSAGE_TAMPERING,
            "MESSAGE_TAMPERING": cls.MESSAGE_TAMPERING,
            "TAMPERING": cls.MESSAGE_TAMPERING,
            "ATK_03": cls.COMMAND_REPLAY,
            "ATK_3": cls.COMMAND_REPLAY,
            "COMMAND_REPLAY": cls.COMMAND_REPLAY,
            "REPLAY_ATTACK": cls.COMMAND_REPLAY,
            "REPLAY": cls.COMMAND_REPLAY,
            "ATK_04": cls.SENDER_SPOOFING,
            "ATK_4": cls.SENDER_SPOOFING,
            "SENDER_SPOOFING": cls.SENDER_SPOOFING,
            "SPOOFED_IDENTITY": cls.SENDER_SPOOFING,
            "SPOOFING": cls.SENDER_SPOOFING,
            "ATK_05": cls.MALFORMED_FUZZING,
            "ATK_5": cls.MALFORMED_FUZZING,
            "MALFORMED_FUZZING": cls.MALFORMED_FUZZING,
            "MALFORMED_PAYLOAD": cls.MALFORMED_FUZZING,
            "FUZZING": cls.MALFORMED_FUZZING,
            "ATK_06": cls.BOUNDED_FLOODING,
            "ATK_6": cls.BOUNDED_FLOODING,
            "BOUNDED_FLOODING": cls.BOUNDED_FLOODING,
            "COMMAND_FLOOD": cls.BOUNDED_FLOODING,
            "FLOODING": cls.BOUNDED_FLOODING,
        }
        if normalized in aliases:
            return aliases[normalized]
        raise ValueError(f"Unknown attack scenario type: '{value}'. Supported: {list(aliases.keys())}")


class AttackStatus(str, Enum):
    """Outcome classification of a single attack attempt."""

    SUCCESSFUL_EXPLOIT = "SUCCESSFUL_EXPLOIT"      # Security OFF: state mutated
    BLOCKED_BY_DEFENSE = "BLOCKED_BY_DEFENSE"      # Security ON: request rejected
    ATTACK_BLOCKED = "BLOCKED_BY_DEFENSE"          # Alias for backward compatibility
    BASELINE_REJECTED = "BASELINE_REJECTED"        # Rejected by schema/engine regardless
    RESOURCE_SATURATION = "RESOURCE_SATURATION"    # Flooding accepted but not blocked
    ATTACK_MITIGATED = "ATTACK_MITIGATED"          # Rate-limiting engaged and blocked
    INVARIANT_FAILED = "INVARIANT_FAILED"          # Unexpected state mutation detected



class ScenarioRunStatus(str, Enum):
    """Lifecycle state of an attack scenario run."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


# Hard upper-bound safety limits enforced by the API.
# These cannot be overridden by user input.
MAX_ATTEMPTS: int = 200
MAX_CONCURRENCY: int = 1
MAX_PAYLOAD_BYTES: int = 8_192  # 8 KiB per payload
MAX_FLOOD_REQUESTS: int = 100
ALLOWED_TARGET_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})
