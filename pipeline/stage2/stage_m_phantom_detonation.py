"""
ORACLE-TMF  ·  pipeline/stage2/stage_m_phantom_detonation.py
==============================================================
Stage M: PHANTOM Active Deception Detonation — Stage 2 Tier 2.

Integrates the PHANTOM deception engine into the Stage 1 pipeline as an
optional, post-static-analysis detonation step.  Stage M is only run when:
  (a) The operator explicitly enables it (phantom_enabled=True in config)
  (b) Stage K produced at least one forecast above the confidence gate
  (c) The APK is flagged as having a dormant payload (DTE SCAFFOLDING hit)

Stage M output enriches the Stage K forecasts with:
  • Confirmed behaviors (what the malware actually DID during detonation)
  • Exfiltration attempts (which honeytokens were targeted)
  • Dynamic C2 traffic analysis (what network calls were made)

Output feeds back into Stage K for a confidence boost on confirmed behaviors
and into Stage L (STIX/YARA) for dynamic indicator enrichment.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from config.stage2_settings import PHANTOM_MAX_SESSION_TURNS
from models.mutation_artifact_graph import MutationArtifactGraph, MutationForecast
from phantom.deception_engine import PhantomDeceptionEngine, PhantomSession

logger = logging.getLogger(__name__)


@dataclass
class StageMResult:
    """Output of Stage M PHANTOM detonation."""

    session: Optional[PhantomSession] = None
    behaviors_confirmed: list[str] = field(default_factory=list)
    exfiltration_detected: bool = False
    exfiltration_items: list[str] = field(default_factory=list)
    dynamic_c2_hosts: list[str] = field(default_factory=list)
    confidence_boosts: dict[str, float] = field(default_factory=dict)  # technique → boost
    detonation_duration_s: float = 0.0
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""


class StageMPhantomDetonation:
    """
    Stage M: PHANTOM Active Deception Detonation.

    Usage
    -----
    >>> stage = StageMPhantomDetonation()
    >>> result = stage.run(mag, forecasts, apk_path)
    """

    STAGE_ID = "M"
    STAGE_NAME = "PHANTOM_DETONATION"

    def __init__(self, enabled: bool = False) -> None:
        self._enabled = enabled
        self._engine: Optional[PhantomDeceptionEngine] = None
        if enabled:
            self._engine = PhantomDeceptionEngine()
        logger.info("[Stage M] Initialised (enabled=%s)", enabled)

    def run(
        self,
        mag: MutationArtifactGraph,
        forecasts: list[MutationForecast],
        apk_path: str = "",
        simulated_commands: Optional[list[str]] = None,
    ) -> StageMResult:
        """
        Run Stage M detonation.

        Parameters
        ----------
        mag : MutationArtifactGraph
            The fully-analysed APK's MAG (Stages A–L must be complete).
        forecasts : list[MutationForecast]
            Stage K forecast output.
        apk_path : str
            Path to the APK file for detonation logging.
        simulated_commands : list[str] | None
            For unit testing: override the C2 command sequence instead of
            using a real Frida-connected device.

        Returns
        -------
        StageMResult
        """
        t0 = time.perf_counter()
        result = StageMResult()

        # Gate check 1: enabled?
        if not self._enabled or self._engine is None:
            result.skipped = True
            result.skip_reason = "PHANTOM not enabled — set phantom_enabled=True in config"
            logger.info("[Stage M] Skipped: disabled")
            return result

        # Gate check 2: any forecasts above confidence gate?
        active_forecasts = [f for f in forecasts if f.passes_gate]
        if not active_forecasts:
            result.skipped = True
            result.skip_reason = "No forecasts above confidence gate — detonation not warranted"
            logger.info("[Stage M] Skipped: no qualifying forecasts")
            return result

        # Gate check 3: dormant payload likely?
        has_scaffolding = any(
            dc.dte_label == "SCAFFOLDING"
            for dc in mag.dead_code
        )
        if not has_scaffolding and not simulated_commands:
            result.skipped = True
            result.skip_reason = "No SCAFFOLDING artifacts detected — detonation unlikely to succeed"
            logger.info("[Stage M] Skipped: no scaffolding detected")
            return result

        try:
            # Start PHANTOM session
            session = self._engine.start_session(apk_path=apk_path or mag.apk_metadata.sha256)

            # Run detonation: process simulated commands or default probe sequence
            commands = simulated_commands or self._build_probe_sequence(mag, forecasts)
            for cmd in commands[:PHANTOM_MAX_SESSION_TURNS]:
                if not session.is_active:
                    break
                self._engine.respond(session, cmd)

            # End session and collect results
            self._engine.end_session(session)
            result.session = session

            # Extract confirmed behaviors
            result.behaviors_confirmed = list(set(session.behaviors_captured))

            # Extract exfiltration attempts
            all_exfil = [
                ex for turn in session.turns for ex in turn.exfiltration_attempts
            ]
            result.exfiltration_detected = len(all_exfil) > 0
            result.exfiltration_items = all_exfil[:20]

            # Extract C2 hosts from commands that contained URLs
            result.dynamic_c2_hosts = self._extract_c2_hosts(session)

            # Compute confidence boosts for confirmed behaviors
            result.confidence_boosts = self._compute_confidence_boosts(
                result.behaviors_confirmed, forecasts
            )

        except Exception as exc:
            logger.error("[Stage M] Detonation failed: %s", exc)
            result.error = str(exc)

        result.detonation_duration_s = round(time.perf_counter() - t0, 2)
        logger.info(
            "[Stage M] Complete: behaviors=%d exfil=%s boosts=%d (%.1fs)",
            len(result.behaviors_confirmed),
            result.exfiltration_detected,
            len(result.confidence_boosts),
            result.detonation_duration_s,
        )
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_probe_sequence(
        mag: MutationArtifactGraph,
        forecasts: list[MutationForecast],
    ) -> list[str]:
        """
        Build a probe command sequence based on what the APK is suspected of.
        Probes are generic Android API simulation requests.
        """
        probes = [
            '{"action": "LAUNCH_MAIN_ACTIVITY"}',
            '{"action": "REQUEST_SMS_PERMISSION_GRANTED"}',
            '{"action": "REQUEST_ACCESSIBILITY_PERMISSION_GRANTED"}',
            '{"action": "RECEIVE_SMS", "sender": "VM-SBIBNK", '
            '"body": "SBI: OTP for login is 123456. Valid 10 mins."}',
            '{"action": "CONTACT_LIST_QUERIED", "count": 150}',
            '{"action": "CLIPBOARD_READ", "content": "4111111111111234"}',
            '{"action": "SCREEN_ON", "app_foreground": "com.sbi.lotusintouch"}',
        ]
        # Add technique-specific probes
        for forecast in forecasts[:2]:
            if "ATS" in forecast.predicted_technique or "Accessibility" in forecast.predicted_technique:
                probes.append('{"action": "ACCESSIBILITY_EVENT", "eventType": 1, '
                              '"packageName": "com.sbi.lotusintouch"}')
            if "SMS" in forecast.predicted_technique:
                probes.append('{"action": "SMS_RECEIVED", "address": "VM-HDFCBK", '
                              '"body": "HDFC: OTP 789012 for transaction Rs 25000"}')
        return probes

    @staticmethod
    def _extract_c2_hosts(session: PhantomSession) -> list[str]:
        """Extract unique C2 hostnames from commands sent during detonation."""
        import re
        hosts: set[str] = set()
        for turn in session.turns:
            matches = re.findall(r"https?://([^/\"'\\s]+)", turn.malware_command)
            hosts.update(matches)
        return sorted(hosts)

    @staticmethod
    def _compute_confidence_boosts(
        confirmed_behaviors: list[str],
        forecasts: list[MutationForecast],
    ) -> dict[str, float]:
        """
        Map confirmed behaviors to forecast techniques and compute confidence boosts.
        Dynamic evidence of a behavior provides a 0.10 confidence bonus.
        """
        boosts: dict[str, float] = {}
        behavior_to_technique = {
            "SMS_READ": "T1636.004",
            "OTP_INTERCEPT": "T1636.004",
            "ACCESSIBILITY_ABUSE": "T1417",
            "OVERLAY_ATTACK": "T1417",
            "SCREEN_CAPTURE": "T1513",
            "CONTACTS_READ": "T1636.003",
            "LOCATION_HARVEST": "T1430",
            "UPI_FRAUD": "T1640",
        }
        for behavior in confirmed_behaviors:
            technique_id = behavior_to_technique.get(behavior)
            if technique_id:
                for forecast in forecasts:
                    if technique_id in forecast.predicted_technique:
                        boosts[forecast.predicted_technique] = boosts.get(
                            forecast.predicted_technique, 0.0
                        ) + 0.10
        return boosts
