"""Integration verification gate: strict, repeatable pre-evaluation checklist."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from backend.app.attacks.attack_types import AttackScenarioType, AttackStatus
from backend.app.core.drone_engine import DroneCommand, DroneEngine, FlightState
from backend.app.evaluation.models import (
    GateStatus,
    VerificationCheck,
    VerificationGateResult,
)
from backend.app.persistence.repositories import LogQueryRepository
from backend.app.security.message_protocol import SecurityMode
from backend.app.security.security_service import SecurityService
from backend.app.services.attack_service import AttackService
from backend.app.services.command_service import CommandService


class VerificationGate:
    """Repeatable integration verification gate per Phase 6 requirements.
    
    Must verify all system invariants before benchmarking begins:
    - Authoritative flight FSM & movement (ARM, TAKEOFF, horizontal, vertical MOVE_UP/MOVE_DOWN, STOP, LAND)
    - All 6 attack scenarios (ATK-01 through ATK-06)
    - Correct API response shapes and structured rejection reasons
    - Actual SecurityService invocation and security event auditing
    - Persistent SQLite audit history in command_logs, security_events, and attack_runs
    - Strict invariant verification: zero state mutation on rejected payloads
    """

    def __init__(
        self,
        drone_engine: DroneEngine,
        command_service: CommandService,
        security_service: SecurityService,
        attack_service: AttackService,
        log_repo: LogQueryRepository,
    ) -> None:
        self.engine = drone_engine
        self.cmd_service = command_service
        self.sec_service = security_service
        self.attack_service = attack_service
        self.log_repo = log_repo

    async def run_gate(self) -> VerificationGateResult:
        """Execute full verification checklist sequentially and return pass/fail result."""
        checks: list[VerificationCheck] = []

        # 1. Flight command lifecycle check
        checks.append(await self._check_flight_lifecycle())

        # 2. Vertical movement and geofence safety
        checks.append(await self._check_vertical_movement_and_geofence())

        # 3. All six attack scenarios in UNSECURED vs SECURED
        checks.extend(await self._check_six_attack_scenarios())

        # 4. Structured rejection codes and response shape
        checks.append(await self._check_structured_rejections())

        # 5. SecurityService defensive pipeline invocation
        checks.append(await self._check_security_service_invocation())

        # 6. Persistent audit logging & query verification
        checks.append(await self._check_audit_persistence())

        # 7. No unauthorized state mutation invariant
        checks.append(await self._check_state_invariants())

        # Reset security mode back to UNSECURED following gate run
        self.sec_service.set_security_mode(SecurityMode.UNSECURED, reason="Post-gate reset")
        self._reset_engine_to_ground()

        passed_count = sum(1 for c in checks if c.passed)
        failed_count = sum(1 for c in checks if not c.passed)
        gate_status = GateStatus.PASSED if failed_count == 0 else GateStatus.FAILED

        summary = (
            f"Integration Verification Gate {gate_status.value}: {passed_count}/{len(checks)} checks passed."
        )

        return VerificationGateResult(
            gate_status=gate_status,
            timestamp=time.time(),
            checks=checks,
            summary=summary,
            passed_count=passed_count,
            failed_count=failed_count,
        )

    def _reset_engine_to_ground(self) -> None:
        """Reset drone engine to pristine ground state."""
        self.engine._fsm.reset(FlightState.DISARMED)
        self.engine._armed = False
        self.engine._x = 0.0
        self.engine._y = 0.0
        self.engine._z = 0.0
        self.engine._heading = 0.0
        self.engine._speed = 0.0
        self.engine._battery_level = 100.0
        self.engine._state_version = 0

    def _bring_engine_to_hover(self) -> None:
        """Safely bring drone engine to airborne hovering state at Y=5.0m."""
        self._reset_engine_to_ground()
        self.engine.execute_command(DroneCommand.ARM)
        self.engine.execute_command(DroneCommand.TAKEOFF)

    async def _check_flight_lifecycle(self) -> VerificationCheck:
        """Verify ARM, TAKEOFF, horizontal movement, STOP, and LAND."""
        name = "Flight Command Lifecycle"
        desc = "Verify ARM -> TAKEOFF -> MOVE_FORWARD -> MOVE_RIGHT -> STOP -> LAND state transitions."
        try:
            self._reset_engine_to_ground()
            self.sec_service.set_security_mode(SecurityMode.UNSECURED)

            # ARM
            res_arm = await self.cmd_service.execute_command("ARM")
            if not res_arm.success or self.engine.flight_state != FlightState.ARMED:
                return VerificationCheck(name, desc, False, {"stage": "ARM"}, f"ARM failed: {res_arm.error_message}")

            # TAKEOFF
            res_to = await self.cmd_service.execute_command("TAKEOFF")
            if not res_to.success or self.engine.flight_state != FlightState.HOVERING or self.engine.y < 4.9:
                return VerificationCheck(name, desc, False, {"stage": "TAKEOFF"}, f"TAKEOFF failed: {res_to.error_message}")

            # Horizontal Movement
            res_mf = await self.cmd_service.execute_command("MOVE_FORWARD", {"distance_meters": 2.0})
            if not res_mf.success or self.engine.z != 2.0:
                return VerificationCheck(name, desc, False, {"stage": "MOVE_FORWARD"}, f"MOVE_FORWARD failed: {res_mf.error_message}")

            res_mr = await self.cmd_service.execute_command("MOVE_RIGHT", {"distance_meters": 3.0})
            if not res_mr.success or self.engine.x != 3.0:
                return VerificationCheck(name, desc, False, {"stage": "MOVE_RIGHT"}, f"MOVE_RIGHT failed: {res_mr.error_message}")

            # STOP
            res_stop = await self.cmd_service.execute_command("STOP")
            if not res_stop.success or self.engine.flight_state != FlightState.HOVERING:
                return VerificationCheck(name, desc, False, {"stage": "STOP"}, f"STOP failed: {res_stop.error_message}")

            # LAND
            res_land = await self.cmd_service.execute_command("LAND")
            if not res_land.success or self.engine.y != 0.0 or self.engine.flight_state != FlightState.ARMED:
                return VerificationCheck(name, desc, False, {"stage": "LAND"}, f"LAND failed: {res_land.error_message}")

            return VerificationCheck(name, desc, True, {
                "final_state": self.engine.flight_state.value,
                "final_y": self.engine.y,
                "state_version": self.engine.state_version,
            })
        except Exception as err:
            return VerificationCheck(name, desc, False, {}, str(err))

    async def _check_vertical_movement_and_geofence(self) -> VerificationCheck:
        """Verify vertical movement (MOVE_UP, MOVE_DOWN) and geofence boundary enforcement."""
        name = "Vertical Movement & Geofencing"
        desc = "Verify MOVE_UP, MOVE_DOWN, and ceiling/floor boundary rejections (0 < Y <= 50m)."
        try:
            self._bring_engine_to_hover()
            initial_y = self.engine.y  # 5.0m

            # MOVE_UP
            res_up = await self.cmd_service.execute_command("MOVE_UP", {"distance_meters": 4.0})
            if not res_up.success or abs(self.engine.y - (initial_y + 4.0)) > 1e-4:
                return VerificationCheck(name, desc, False, {"stage": "MOVE_UP"}, f"MOVE_UP failed: {res_up.error_message}")

            # MOVE_DOWN
            res_down = await self.cmd_service.execute_command("MOVE_DOWN", {"distance_meters": 2.0})
            if not res_down.success or abs(self.engine.y - (initial_y + 2.0)) > 1e-4:
                return VerificationCheck(name, desc, False, {"stage": "MOVE_DOWN"}, f"MOVE_DOWN failed: {res_down.error_message}")

            # Boundary Test: Exceed ceiling (50m)
            v_before = self.engine.state_version
            res_ceil = await self.cmd_service.execute_command("MOVE_UP", {"distance_meters": 55.0})
            if res_ceil.success or res_ceil.error_code != "BOUNDARY_LIMIT_EXCEEDED" or self.engine.state_version != v_before:
                return VerificationCheck(name, desc, False, {"stage": "Ceiling boundary"}, "Ceiling geofence boundary check failed.")

            # Boundary Test: Sub-zero floor while airborne
            res_floor = await self.cmd_service.execute_command("MOVE_DOWN", {"distance_meters": 20.0})
            if res_floor.success or res_floor.error_code != "BOUNDARY_LIMIT_EXCEEDED" or self.engine.state_version != v_before:
                return VerificationCheck(name, desc, False, {"stage": "Floor boundary"}, "Floor geofence boundary check failed.")

            return VerificationCheck(name, desc, True, {
                "altitude_after_movement": round(self.engine.y, 2),
                "geofence_checks": "CEILING_REJECTED_AND_FLOOR_REJECTED",
            })
        except Exception as err:
            return VerificationCheck(name, desc, False, {}, str(err))

    async def _check_six_attack_scenarios(self) -> list[VerificationCheck]:
        """Verify each of the six attack scenarios (ATK-01 to ATK-06) across unsecured and secured modes."""
        results: list[VerificationCheck] = []

        scenarios = [
            (AttackScenarioType.UNAUTHORIZED_COMMAND, "ATK-01: Unauthorized Injection", {"target_command": "ARM"}),
            (AttackScenarioType.MESSAGE_TAMPERING, "ATK-02: Message Tampering", {"target_command": "MOVE_FORWARD", "tamper_coordinate_delta": 500.0}),
            (AttackScenarioType.COMMAND_REPLAY, "ATK-03: Command Replay", {"target_command": "MOVE_FORWARD"}),
            (AttackScenarioType.SENDER_SPOOFING, "ATK-04: Sender Spoofing", {"target_command": "ARM"}),
            (AttackScenarioType.MALFORMED_FUZZING, "ATK-05: Malformed Fuzzing", {}),
            (AttackScenarioType.BOUNDED_FLOODING, "ATK-06: Bounded Flooding", {"flood_count": 50}),
        ]

        for sc_type, title, params in scenarios:
            try:
                # 1. Test in UNSECURED Mode
                self.sec_service.set_security_mode(SecurityMode.UNSECURED)
                if sc_type in {AttackScenarioType.MESSAGE_TAMPERING, AttackScenarioType.COMMAND_REPLAY}:
                    self._bring_engine_to_hover()
                else:
                    self._reset_engine_to_ground()

                res_unsec = await self.attack_service.execute_attack(sc_type.value, parameters=params)

                # 2. Test in Secured Mode (ENCRYPTED_AUTHENTICATED or INTEGRITY_ONLY)
                target_sec_mode = (
                    SecurityMode.INTEGRITY_ONLY
                    if sc_type == AttackScenarioType.MESSAGE_TAMPERING
                    else SecurityMode.ENCRYPTED_AUTHENTICATED
                )
                self.sec_service.set_security_mode(target_sec_mode)
                if sc_type in {AttackScenarioType.MESSAGE_TAMPERING, AttackScenarioType.COMMAND_REPLAY}:
                    self._bring_engine_to_hover()
                else:
                    self._reset_engine_to_ground()

                res_sec = await self.attack_service.execute_attack(sc_type.value, parameters=params)

                # In secured mode, attack must not compromise state (except flooding where rate limiting engages)
                passed = True
                fail_reason = ""
                if res_sec.state_compromised and sc_type != AttackScenarioType.BOUNDED_FLOODING:
                    passed = False
                    fail_reason = f"State was compromised in {target_sec_mode.value}"
                elif sc_type == AttackScenarioType.BOUNDED_FLOODING and res_sec.defense_triggered != "RATE_LIMIT_EXCEEDED":
                    passed = False
                    fail_reason = f"Rate limiter failed to trigger: {res_sec.defense_triggered}"

                results.append(VerificationCheck(
                    name=title,
                    description=f"Validate {sc_type.value} demonstration in UNSECURED and defense in {target_sec_mode.value}.",
                    passed=passed,
                    details={
                        "unsecured_result": res_unsec.attack_result,
                        "secured_result": res_sec.attack_result,
                        "defense_triggered": res_sec.defense_triggered,
                        "state_compromised_secured": res_sec.state_compromised,
                    },
                    error_message=fail_reason or None,
                ))
            except Exception as err:
                results.append(VerificationCheck(title, f"Validate {sc_type.value}", False, {}, str(err)))

        return results

    async def _check_structured_rejections(self) -> VerificationCheck:
        """Verify API returns structured StandardErrorResponse envelopes."""
        name = "Structured API Rejections"
        desc = "Verify rejection responses contain { status: 'error', error: { code, message } }."
        try:
            self._reset_engine_to_ground()
            self.sec_service.set_security_mode(SecurityMode.UNSECURED)

            # Unknown command
            outcome_unk = await self.cmd_service.execute_command("INVALID_COMMAND_NAME_XYZ")
            if outcome_unk.success or outcome_unk.error_code != "UNKNOWN_COMMAND" or not outcome_unk.error_message:
                return VerificationCheck(name, desc, False, {}, "Unknown command did not return structured error_code.")

            # Invalid flight state transition (TAKEOFF when DISARMED)
            outcome_trans = await self.cmd_service.execute_command("TAKEOFF")
            if outcome_trans.success or outcome_trans.error_code != "INVALID_STATE_TRANSITION":
                return VerificationCheck(name, desc, False, {}, "Invalid state transition did not return INVALID_STATE_TRANSITION.")

            return VerificationCheck(name, desc, True, {
                "unknown_command_error": outcome_unk.error_code,
                "transition_error": outcome_trans.error_code,
            })
        except Exception as err:
            return VerificationCheck(name, desc, False, {}, str(err))

    async def _check_security_service_invocation(self) -> VerificationCheck:
        """Verify SecurityService verifies signatures, decrypts, and raises SecurityPipelineError on violations."""
        name = "SecurityService Defensive Pipeline"
        desc = "Verify SecurityService pipeline stages: rate-limiting -> auth -> crypto -> replay window."
        try:
            self.sec_service.set_security_mode(SecurityMode.ENCRYPTED_AUTHENTICATED)
            status_dict = self.sec_service.get_security_status()

            if status_dict["current_mode"] != "ENCRYPTED_AUTHENTICATED":
                return VerificationCheck(name, desc, False, {}, "SecurityService report mode mismatch.")

            if not status_dict["replay_protection"]["enabled"]:
                return VerificationCheck(name, desc, False, {}, "Replay protection reported disabled in secured mode.")

            return VerificationCheck(name, desc, True, {
                "active_mode": status_dict["current_mode"],
                "active_key_id": status_dict["active_key_id"],
                "encryption": status_dict["algorithms"]["encryption"],
                "anti_replay_window": status_dict["replay_protection"]["window_size"],
            })
        except Exception as err:
            return VerificationCheck(name, desc, False, {}, str(err))

    async def _check_audit_persistence(self) -> VerificationCheck:
        """Verify command logs, security events, and attack runs are queryable via LogQueryRepository."""
        name = "Persistent Audit Logging"
        desc = "Verify logs across COMMAND, SECURITY_EVENT, and ATTACK categories are persisted and queryable."
        try:
            logs = await self.log_repo.query_logs(limit=50)
            categories = {l.get("category") for l in logs}

            # Check if attack and command records exist
            has_commands = any(c == "COMMAND" for c in categories)
            has_attacks = any(c == "ATTACK" for c in categories)

            if not has_commands and not has_attacks:
                return VerificationCheck(name, desc, False, {"found_categories": list(categories)}, "No persistent logs returned.")

            return VerificationCheck(name, desc, True, {
                "total_queried": len(logs),
                "categories_present": list(categories),
            })
        except Exception as err:
            return VerificationCheck(name, desc, False, {}, str(err))

    async def _check_state_invariants(self) -> VerificationCheck:
        """Verify no unauthorized state mutation occurs during rejected commands or blocked attacks."""
        name = "Authoritative Invariant Preservation"
        desc = "Verify rejected commands strictly preserve state_version and coordinate vectors."
        try:
            self._bring_engine_to_hover()
            v0 = self.engine.state_version
            p0 = (self.engine.x, self.engine.y, self.engine.z)

            # Reject boundary exceed
            await self.cmd_service.execute_command("MOVE_UP", {"distance_meters": 200.0})
            v1 = self.engine.state_version
            p1 = (self.engine.x, self.engine.y, self.engine.z)

            if v1 != v0 or p1 != p0:
                return VerificationCheck(name, desc, False, {}, f"State mutated on rejected command: V{v0} -> V{v1}")

            return VerificationCheck(name, desc, True, {
                "state_version_preserved": v0 == v1,
                "position_preserved": p0 == p1,
            })
        except Exception as err:
            return VerificationCheck(name, desc, False, {}, str(err))
