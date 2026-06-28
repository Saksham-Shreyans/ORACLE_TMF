"""
ORACLE-TMF  ·  pipeline/stage2/stage_n_nav_analysis.py
========================================================
Stage N: Negative Artifact Vector Analysis — Stage 2 Tier 2.

Runs the NAV engine on the current version pair (mag_curr, mag_prev)
and feeds the nav_adjustment into the Stage K Bayesian formula.

This is the only Stage 2 component that modifies existing Stage K output:
all other Stage 2 components are additive.

Integration point:
  • Receives: mag_curr (Stage A–I), mag_prev (from family knowledge base)
  • Produces: NAVResult attached to mag_curr.nav_result
  • Side effect: adjusts forecast.confidence_score for each MutationForecast
    by nav_result.nav_adjustment
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from engines.nav.nav_engine import NAVEngine
from models.mutation_artifact_graph import MutationArtifactGraph, MutationForecast
from models.nav_models import NAVHistory, NAVResult, NAVRedirectionHypothesis

logger = logging.getLogger(__name__)


@dataclass
class StageNResult:
    """Output of Stage N NAV Analysis."""

    nav_result: Optional[NAVResult] = None
    forecasts_adjusted: int = 0
    redirection_applied: bool = False
    primary_redirection: Optional[NAVRedirectionHypothesis] = None
    history_map_updated: bool = False
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""
    elapsed_ms: float = 0.0


class StageNNAVAnalysis:
    """
    Stage N: Negative Artifact Vector Analysis.

    Usage
    -----
    >>> stage = StageNNAVAnalysis()
    >>> result = stage.run(mag_curr, mag_prev, forecasts, history_map)
    """

    STAGE_ID = "N"
    STAGE_NAME = "NAV_ANALYSIS"

    def __init__(self) -> None:
        self._engine = NAVEngine()
        logger.info("[Stage N] Initialised")

    def run(
        self,
        mag_curr: MutationArtifactGraph,
        mag_prev: Optional[MutationArtifactGraph],
        forecasts: list[MutationForecast],
        history_map: Optional[dict[str, NAVHistory]] = None,
        family: str = "",
    ) -> StageNResult:
        """
        Run NAV analysis and apply confidence adjustments to Stage K forecasts.

        Parameters
        ----------
        mag_curr : MutationArtifactGraph
            Current version MAG (output of Stages A–I and K).
        mag_prev : MutationArtifactGraph | None
            Previous version MAG.  None → NAV not applicable (first version).
        forecasts : list[MutationForecast]
            Stage K output to adjust.
        history_map : dict[str, NAVHistory] | None
            Multi-version artifact history.  Updated in-place.
        family : str
            Malware family name for history tracking.

        Returns
        -------
        StageNResult
        """
        t0 = time.perf_counter()
        result = StageNResult()

        if mag_prev is None:
            result.skipped = True
            result.skip_reason = "No previous version available — NAV requires v_n-1"
            logger.info("[Stage N] Skipped: first version")
            return result

        try:
            # Run NAV engine
            nav_result = self._engine.run(
                mag_curr=mag_curr,
                mag_prev=mag_prev,
                history_map=history_map,
            )
            result.nav_result = nav_result
            mag_curr.nav_result = nav_result  # Attach to MAG

            # Apply confidence adjustment to all Stage K forecasts
            if nav_result.nav_adjustment != 0.0 and forecasts:
                for forecast in forecasts:
                    original = forecast.confidence_score
                    forecast.confidence_score = round(
                        max(0.0, min(1.0, forecast.confidence_score + nav_result.nav_adjustment)),
                        4,
                    )
                    logger.debug(
                        "[Stage N] Adjusted %s: %.3f → %.3f",
                        forecast.predicted_technique[:30],
                        original,
                        forecast.confidence_score,
                    )
                result.forecasts_adjusted = len(forecasts)

            # Apply redirection: boost the redirected technique's forecast
            if nav_result.primary_redirection:
                result.redirection_applied = True
                result.primary_redirection = nav_result.primary_redirection
                self._apply_redirection_boost(nav_result.primary_redirection, forecasts)

            # Update history map
            if history_map is not None:
                self._engine.update_history(
                    family=family or mag_curr.malware_family,
                    mag=mag_curr,
                    history_map=history_map,
                    version=mag_curr.family_version or "v_n",
                )
                result.history_map_updated = True

        except Exception as exc:
            logger.error("[Stage N] NAV analysis failed: %s", exc)
            result.error = str(exc)

        result.elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        logger.info(
            "[Stage N] Complete: events=%d adjustment=%.3f redirection=%s (%.1f ms)",
            len(result.nav_result.nav_events) if result.nav_result else 0,
            result.nav_result.nav_adjustment if result.nav_result else 0.0,
            result.primary_redirection.value if result.primary_redirection else "none",
            result.elapsed_ms,
        )
        return result

    @staticmethod
    def _apply_redirection_boost(
        redirection: NAVRedirectionHypothesis,
        forecasts: list[MutationForecast],
    ) -> None:
        """Boost the forecast that corresponds to the NAV redirection hypothesis."""
        # Map redirection hypothesis to MITRE technique fragments
        redirection_map = {
            NAVRedirectionHypothesis.OVERLAY_TO_ACCESSIBILITY: ["T1417", "Accessibility"],
            NAVRedirectionHypothesis.C2_PROTOCOL_SHIFT: ["T1521", "Encrypted Channel"],
            NAVRedirectionHypothesis.DGA_ADOPTION: ["DGA", "T1637"],
            NAVRedirectionHypothesis.STEALTH_UPGRADE: ["T1406", "Obfuscat"],
        }
        technique_hints = redirection_map.get(redirection, [])
        if not technique_hints:
            return

        for forecast in forecasts:
            if any(h in forecast.predicted_technique for h in technique_hints):
                forecast.confidence_score = round(
                    min(1.0, forecast.confidence_score + 0.08), 4
                )
                logger.debug(
                    "[Stage N] Redirection boost applied to %s",
                    forecast.predicted_technique[:40],
                )
