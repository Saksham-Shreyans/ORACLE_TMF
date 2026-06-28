"""
ORACLE-TMF  ·  pipeline/stage2/stage_o_cabal_analysis.py
==========================================================
Stage O: CABAL Cross-App Collusion Analysis — Stage 2 Tier 3.

Optional stage — requires multiple APK MAGs from the same threat actor
or the same app ecosystem.  Skipped automatically during single-APK analysis.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from models.mutation_artifact_graph import MutationArtifactGraph
from research.cabal.collusion_engine import CABALEngine, CABALResult

logger = logging.getLogger(__name__)


@dataclass
class StageOResult:
    """Output of Stage O CABAL analysis."""

    cabal_result: Optional[CABALResult] = None
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""
    elapsed_ms: float = 0.0


class StageOCABALAnalysis:
    """
    Stage O: CABAL Cross-App Collusion Analysis.

    Usage
    -----
    >>> stage = StageOCABALAnalysis()
    >>> result = stage.run([mag_a, mag_b, mag_c])
    """

    STAGE_ID = "O"
    STAGE_NAME = "CABAL_COLLUSION_ANALYSIS"

    def __init__(self, use_llm: bool = True) -> None:
        self._engine = CABALEngine()
        self._use_llm = use_llm
        logger.info("[Stage O] Initialised (use_llm=%s)", use_llm)

    def run(
        self,
        mag_list: list[MutationArtifactGraph],
    ) -> StageOResult:
        """
        Run CABAL collusion analysis on a set of APK MAGs.

        Parameters
        ----------
        mag_list : list[MutationArtifactGraph]
            At least 2 APK MAGs required.

        Returns
        -------
        StageOResult
        """
        t0 = time.perf_counter()
        result = StageOResult()

        if len(mag_list) < 2:
            result.skipped = True
            result.skip_reason = "CABAL requires ≥2 APK MAGs — single-APK analysis"
            logger.info("[Stage O] Skipped: insufficient APK count (%d)", len(mag_list))
            return result

        try:
            cabal_result = self._engine.run(mag_list, use_llm=self._use_llm)
            result.cabal_result = cabal_result
        except Exception as exc:
            logger.error("[Stage O] CABAL analysis failed: %s", exc)
            result.error = str(exc)

        result.elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        if result.cabal_result:
            logger.info(
                "[Stage O] Complete: paths=%d high_conf=%d (%.1f ms)",
                result.cabal_result.total_edges_found,
                len(result.cabal_result.high_confidence_paths),
                result.elapsed_ms,
            )
        return result
