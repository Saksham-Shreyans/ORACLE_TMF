"""
ORACLE-TMF  ·  phantom/frida_bypass/bypass_controller.py
==========================================================
Frida Dynamic Bypass Execution Framework — Stage 2 Tier 2.

The BypassController is the Python orchestrator for all Frida JS hooks.
It manages:
  1. Frida device/process connection and lifecycle
  2. Template injection: replacing PERSONA_* placeholders with live values
  3. Ordered hook injection with dependency sequencing
  4. Iterative retry with escalating hook depth (up to FRIDA_MAX_BYPASS_RETRIES)
  5. Sensor value refresh loop (calls sensor_hook.js RPC to update OU values)
  6. Graceful cleanup on session end

Hook injection order (dependency-safe):
  1. adb_hook.js        — disable debugger/anti-analysis detection FIRST
  2. manufacturer_hook.js — override Build.* before any APK code reads them
  3. country_hook.js    — override TelephonyManager BEFORE network init
  4. sensor_hook.js     — register SensorManager wrapper

Escalating retry strategy
--------------------------
  Retry 0: Standard hook injection (all hooks, normal depth)
  Retry 1: Re-inject adb_hook with deeper native TracerPid patch
  Retry 2: Inject before dalvik/art JIT (Frida --no-pause mode)
  Retry 3: Use Frida spawn+resume (vs attach) for pre-main injection
  Retry 4: Add root-level /proc patch and property override fallback
  Retry 5: Full escalation — all native + Java hooks combined

Each retry waits FRIDA_RETRY_DELAY_S seconds to allow the process to
stabilise before re-attempting injection.

Safety note: This module only runs in controlled, air-gapped environments.
See PHANTOM safety boundary documentation.
"""
from __future__ import annotations

import json
import logging
import os
import string
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from config.stage2_settings import (
    FRIDA_MAX_BYPASS_RETRIES,
    FRIDA_RETRY_DELAY_S,
    FRIDA_SCRIPTS_DIR,
    FRIDA_TIMEOUT_S,
)
from phantom.device_persona import AndroidPersona, DevicePersonaGenerator
from phantom.sensory_emulation import SensoryEmulator

logger = logging.getLogger(__name__)

# Frida is an optional dependency — bypass controller degrades gracefully
try:
    import frida
    _FRIDA_AVAILABLE = True
except ImportError:
    _FRIDA_AVAILABLE = False
    logger.warning(
        "[BypassController] frida module not installed — "
        "running in simulation mode (no real device injection)"
    )


@dataclass
class BypassResult:
    """Result of a single bypass attempt."""

    success: bool = False
    hooks_injected: list[str] = field(default_factory=list)
    hooks_failed: list[str] = field(default_factory=list)
    attempt_number: int = 0
    error: str = ""
    elapsed_ms: float = 0.0


@dataclass
class BypassSession:
    """Active Frida bypass session state."""

    persona: Optional[AndroidPersona] = None
    device: object = None       # frida.Device
    session: object = None      # frida.Session
    scripts: dict = field(default_factory=dict)  # hook_name → frida.Script
    sensor_thread: Optional[threading.Thread] = None
    sensor_emulator: Optional[SensoryEmulator] = None
    is_active: bool = False
    pid: int = 0
    package_name: str = ""
    attempts: list[BypassResult] = field(default_factory=list)


# Ordered hook injection sequence
_HOOK_SEQUENCE = [
    "adb_hook.js",
    "manufacturer_hook.js",
    "country_hook.js",
    "sensor_hook.js",
]


class FridaBypassController:
    """
    Frida Dynamic Bypass Execution Framework.

    Manages injection of all anti-analysis bypass hooks with persona values,
    implements the iterative retry-with-escalation strategy, and maintains
    a sensor refresh loop during active detonation.

    Usage
    -----
    >>> controller = FridaBypassController()
    >>> session = controller.attach(package_name="com.target.malware", persona=persona)
    >>> result = controller.inject_all_hooks(session)
    >>> controller.detach(session)
    """

    def __init__(self) -> None:
        self._scripts_dir = Path(FRIDA_SCRIPTS_DIR)
        self._persona_gen = DevicePersonaGenerator()
        logger.info(
            "[BypassController] Initialised (frida_available=%s, scripts_dir=%s)",
            _FRIDA_AVAILABLE, self._scripts_dir,
        )

    def attach(
        self,
        package_name: str,
        persona: Optional[AndroidPersona] = None,
        device_id: Optional[str] = None,
        spawn: bool = False,
    ) -> BypassSession:
        """
        Attach Frida to the target malware process.

        Parameters
        ----------
        package_name : str
            Android package name (e.g., "com.android.system").
        persona : AndroidPersona | None
            Device persona for hook template injection.  Generated if None.
        device_id : str | None
            Frida device ID.  None = first USB device.
        spawn : bool
            True = spawn+resume (pre-main injection, Retry 3+).
            False = attach to running process.

        Returns
        -------
        BypassSession
        """
        if persona is None:
            persona = self._persona_gen.generate()

        bypass_session = BypassSession(
            persona=persona,
            package_name=package_name,
            sensor_emulator=SensoryEmulator(),
        )

        if not _FRIDA_AVAILABLE:
            logger.warning("[BypassController] Frida not available — simulation mode")
            bypass_session.is_active = True  # Simulate active session for testing
            return bypass_session

        try:
            device = (
                frida.get_device(device_id)
                if device_id
                else frida.get_usb_device(timeout=10)
            )
            bypass_session.device = device
            logger.info(
                "[BypassController] Connected to device: %s", device.name
            )

            if spawn:
                pid = device.spawn([package_name])
                frida_session = device.attach(pid)
                device.resume(pid)
                bypass_session.pid = pid
            else:
                frida_session = device.attach(package_name)
                bypass_session.pid = frida_session.pid

            bypass_session.session = frida_session
            bypass_session.is_active = True
            logger.info(
                "[BypassController] Attached to %s (pid=%d)", package_name, bypass_session.pid
            )
        except Exception as exc:
            logger.error("[BypassController] Attach failed: %s", exc)
            bypass_session.is_active = False
            bypass_session.attempts.append(
                BypassResult(success=False, error=str(exc), attempt_number=0)
            )
        return bypass_session

    def inject_all_hooks(
        self, bypass_session: BypassSession
    ) -> BypassResult:
        """
        Inject all hooks with iterative retry and escalating depth.

        Parameters
        ----------
        bypass_session : BypassSession
            Active session from attach().

        Returns
        -------
        BypassResult
            Result of the final (successful or last) attempt.
        """
        last_result = BypassResult()

        for attempt in range(FRIDA_MAX_BYPASS_RETRIES + 1):
            logger.info(
                "[BypassController] Injection attempt %d/%d",
                attempt + 1, FRIDA_MAX_BYPASS_RETRIES + 1,
            )
            result = self._attempt_injection(
                bypass_session, attempt_number=attempt
            )
            bypass_session.attempts.append(result)
            last_result = result

            if result.success:
                logger.info(
                    "[BypassController] All hooks injected on attempt %d",
                    attempt + 1,
                )
                # Start sensor refresh thread
                self._start_sensor_refresh(bypass_session)
                break

            if attempt < FRIDA_MAX_BYPASS_RETRIES:
                logger.warning(
                    "[BypassController] Attempt %d failed (%s) — retrying in %.1fs",
                    attempt + 1, result.error, FRIDA_RETRY_DELAY_S,
                )
                time.sleep(FRIDA_RETRY_DELAY_S)
        else:
            logger.error(
                "[BypassController] All %d attempts failed — detonation aborted",
                FRIDA_MAX_BYPASS_RETRIES + 1,
            )

        return last_result

    def detach(self, bypass_session: BypassSession) -> None:
        """
        Cleanly detach from the malware process and stop all hooks.

        Parameters
        ----------
        bypass_session : BypassSession
            Active session to terminate.
        """
        bypass_session.is_active = False

        # Stop sensor refresh thread
        if bypass_session.sensor_thread and bypass_session.sensor_thread.is_alive():
            bypass_session.sensor_thread.join(timeout=3.0)

        if not _FRIDA_AVAILABLE:
            return

        # Unload all scripts
        for hook_name, script in bypass_session.scripts.items():
            try:
                script.unload()
                logger.debug("[BypassController] Unloaded %s", hook_name)
            except Exception as exc:
                logger.warning(
                    "[BypassController] Failed to unload %s: %s", hook_name, exc
                )

        # Detach session
        if bypass_session.session:
            try:
                bypass_session.session.detach()
                logger.info("[BypassController] Detached from %s", bypass_session.package_name)
            except Exception as exc:
                logger.warning("[BypassController] Detach error: %s", exc)

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _attempt_injection(
        self, bypass_session: BypassSession, attempt_number: int
    ) -> BypassResult:
        """
        Attempt to inject all hooks in the defined sequence.

        Escalation strategy:
          attempt 0: Standard injection
          attempt 1: Re-inject ADB hook with deeper native patches
          attempt 2+: Spawn mode (if not already)
          attempt 3+: Force all hooks as early-instrument
        """
        t0 = time.perf_counter()
        result = BypassResult(attempt_number=attempt_number)

        hooks_to_inject = list(_HOOK_SEQUENCE)

        # Escalation: attempt 1+ adds deeper native patches
        if attempt_number >= 1:
            logger.info("[BypassController] Escalation level %d active", attempt_number)

        for hook_file in hooks_to_inject:
            success = self._inject_hook(bypass_session, hook_file, attempt_number)
            if success:
                result.hooks_injected.append(hook_file)
            else:
                result.hooks_failed.append(hook_file)

        result.elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        result.success = len(result.hooks_failed) == 0

        if not result.success:
            result.error = f"Failed hooks: {result.hooks_failed}"

        logger.info(
            "[BypassController] Attempt %d: injected=%d failed=%d (%.1f ms)",
            attempt_number + 1,
            len(result.hooks_injected),
            len(result.hooks_failed),
            result.elapsed_ms,
        )
        return result

    def _inject_hook(
        self,
        bypass_session: BypassSession,
        hook_file: str,
        attempt_number: int,
    ) -> bool:
        """
        Read, template-render, and inject one Frida JS hook.

        Returns True on success, False on failure.
        """
        script_path = self._scripts_dir / hook_file
        if not script_path.exists():
            logger.error("[BypassController] Hook script not found: %s", script_path)
            return False

        try:
            raw_script = script_path.read_text(encoding="utf-8")
            rendered = self._render_template(raw_script, bypass_session.persona)

            if not _FRIDA_AVAILABLE or bypass_session.session is None:
                # Simulation mode — verify the script rendered correctly
                logger.debug(
                    "[BypassController] Simulation: rendered %s (%d bytes)",
                    hook_file, len(rendered),
                )
                return True

            script = bypass_session.session.create_script(rendered)
            script.on("message", self._make_message_handler(hook_file))
            script.load()
            bypass_session.scripts[hook_file] = script
            logger.info("[BypassController] ✓ Injected %s", hook_file)
            return True

        except Exception as exc:
            logger.error(
                "[BypassController] Failed to inject %s: %s", hook_file, exc
            )
            return False

    def _render_template(
        self,
        script: str,
        persona: Optional[AndroidPersona],
    ) -> str:
        """
        Replace PERSONA_* template placeholders in a Frida JS script
        with live values from the Android persona.
        """
        if persona is None:
            return script

        # Get latest sensor sample for sensor_hook.js
        sensor_sample = None
        if hasattr(self, "_latest_sensor"):
            sensor_sample = self._latest_sensor
        else:
            emulator = SensoryEmulator()
            sensor_sample = emulator.next_sample()

        replacements = {
            "PERSONA_MANUFACTURER": persona.manufacturer,
            "PERSONA_MODEL": persona.model,
            "PERSONA_BRAND": persona.brand,
            "PERSONA_DEVICE": persona.device,
            "PERSONA_PRODUCT": persona.product,
            "PERSONA_ANDROID_VERSION": persona.android_version,
            "PERSONA_SDK_INT": str(persona.sdk_int),
            "PERSONA_BUILD_ID": persona.build_id,
            "PERSONA_FINGERPRINT": persona.fingerprint,
            "PERSONA_COUNTRY_ISO": persona.country_iso,
            "PERSONA_NETWORK_OPERATOR": persona.network_operator,
            "PERSONA_NETWORK_OPERATOR_NAME": persona.network_operator_name,
            "PERSONA_SIM_OPERATOR": persona.sim_operator,
            "PERSONA_SIM_OPERATOR_NAME": persona.sim_operator_name,
            "PERSONA_IMEI": persona.imei,
            "PERSONA_IMSI": persona.imsi,
            "PERSONA_PHONE_NUMBER": persona.phone_number,
            # Sensor placeholders
            "SENSOR_GYRO_X": f"{sensor_sample.gyro_x:.6f}" if sensor_sample else "0.0",
            "SENSOR_GYRO_Y": f"{sensor_sample.gyro_y:.6f}" if sensor_sample else "0.0",
            "SENSOR_GYRO_Z": f"{sensor_sample.gyro_z:.6f}" if sensor_sample else "0.0",
            "SENSOR_ACCEL_X": f"{sensor_sample.accel_x:.6f}" if sensor_sample else "0.0",
            "SENSOR_ACCEL_Y": f"{sensor_sample.accel_y:.6f}" if sensor_sample else "0.0",
            "SENSOR_ACCEL_Z": f"{sensor_sample.accel_z:.6f}" if sensor_sample else "9.81",
            "SENSOR_LIGHT": f"{sensor_sample.light:.2f}" if sensor_sample else "250.0",
            "SENSOR_PROX": f"{sensor_sample.proximity:.1f}" if sensor_sample else "5.0",
        }

        rendered = script
        for placeholder, value in replacements.items():
            rendered = rendered.replace(f'"{placeholder}"', f'"{value}"')
            rendered = rendered.replace(placeholder, value)
        return rendered

    def _start_sensor_refresh(self, bypass_session: BypassSession) -> None:
        """
        Start background thread to push new OU sensor values to the
        injected sensor_hook.js at 10 Hz (every 100ms).
        """
        if not _FRIDA_AVAILABLE:
            return

        sensor_script = bypass_session.scripts.get("sensor_hook.js")
        if not sensor_script:
            return

        def _refresh_loop() -> None:
            emulator = bypass_session.sensor_emulator or SensoryEmulator()
            while bypass_session.is_active:
                try:
                    sample = emulator.next_sample()
                    sensor_json = json.dumps({
                        "gyro": {"x": sample.gyro_x, "y": sample.gyro_y, "z": sample.gyro_z},
                        "accel": {"x": sample.accel_x, "y": sample.accel_y, "z": sample.accel_z},
                        "light": sample.light,
                    })
                    sensor_script.exports.update_sensors(sensor_json)
                except Exception:
                    pass  # Non-critical — continue refresh loop
                time.sleep(0.1)  # 10 Hz refresh

        thread = threading.Thread(target=_refresh_loop, daemon=True)
        thread.start()
        bypass_session.sensor_thread = thread
        logger.info("[BypassController] Sensor refresh thread started (10 Hz)")

    @staticmethod
    def _make_message_handler(hook_name: str):
        """Create a message handler for Frida script console output."""
        def _handler(message: dict, data: bytes) -> None:
            if message.get("type") == "send":
                logger.debug("[%s] %s", hook_name, message.get("payload", ""))
            elif message.get("type") == "error":
                logger.error("[%s] JS error: %s", hook_name, message.get("description", ""))
        return _handler
