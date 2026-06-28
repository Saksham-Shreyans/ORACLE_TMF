"""
ORACLE-TMF  ·  pipeline/stage2/stage_r_ouroboros_coevolution.py
=================================================================
Stage R: OUROBOROS-TMF Co-Evolution — Stage 2 Tier 3 (research mode only).

Disabled by default — only active when ouroboros_enabled=True in config.
Requires labeled ground-truth data or labeled corpus for meaningful co-evolution.

When enabled, this stage:
  1. Runs OUROBOROS co-evolution for the current APK
  2. Generates devolution training pairs for future model improvement
  3. Appends prompt refinements to the Stage J refinement log
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from models.mutation_artifact_graph import MutationArtifactGraph, MutationForecast
from research.ouroboros.coevolution_loop import OuroborosTMF, OuroborosResult, DevolusionPair

logger = logging.getLogger(__name__)


@dataclass
class StageRResult:
    """Output of Stage R OUROBOROS co-evolution."""

    ouroboros_result: Optional[OuroborosResult] = None
    devolution_pairs: list[DevolusionPair] = field(default_factory=list)
    accuracy_improvement: float = 0.0
    prompt_refinements: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""
    elapsed_ms: float = 0.0


class StageROuroborosCoevolution:
    """
    Stage R: OUROBOROS-TMF Closed-Loop Co-Evolution.

    Research/training mode only.  Runs the OUROBOROS loop to iteratively
    improve Stage J prompt quality and generate devolution training pairs.

    Usage
    -----
    >>> stage = StageROuroborosCoevolution(enabled=True)
    >>> result = stage.run(mag, forecasts, ground_truth="T1417 - GUI Input Capture")
    """

    STAGE_ID = "R"
    STAGE_NAME = "OUROBOROS_COEVOLUTION"

    def __init__(self, enabled: bool = False) -> None:
        self._enabled = enabled
        self._engine = OuroborosTMF() if enabled else None
        logger.info("[Stage R] Initialised (enabled=%s)", enabled)

    def run(
        self,
        mag: MutationArtifactGraph,
        forecasts: list[MutationForecast],
        ground_truth_technique: Optional[str] = None,
        mature_corpus: Optional[list[MutationArtifactGraph]] = None,
    ) -> StageRResult:
        """
        Run OUROBOROS co-evolution loop.

        Parameters
        ----------
        mag : MutationArtifactGraph
            Staging APK MAG.
        forecasts : list[MutationForecast]
            Stage K output.
        ground_truth_technique : str | None
            Known mature technique label (from labeled dataset).
        mature_corpus : list[MutationArtifactGraph] | None
            Corpus of mature APK MAGs for devolution pair generation.

        Returns
        -------
        StageRResult
        """
        t0 = time.perf_counter()
        result = StageRResult()

        if not self._enabled or self._engine is None:
            result.skipped = True
            result.skip_reason = "OUROBOROS disabled — set ouroboros_enabled=True for research mode"
            logger.info("[Stage R] Skipped: disabled")
            return result

        if not forecasts:
            result.skipped = True
            result.skip_reason = "No forecasts available — Stage K must run first"
            return result

        try:
            # Run co-evolution loop
            ouroboros_result = self._engine.run(
                mag_staging=mag,
                forecasts=forecasts,
                ground_truth_technique=ground_truth_technique,
            )
            result.ouroboros_result = ouroboros_result
            result.accuracy_improvement = ouroboros_result.accuracy_improvement
            result.prompt_refinements = ouroboros_result.prompt_refinements

            # Generate devolution training pairs from mature corpus
            if mature_corpus:
                result.devolution_pairs = self._engine.generate_devolution_pairs(
                    mature_corpus
                )

        except Exception as exc:
            logger.error("[Stage R] OUROBOROS failed: %s", exc)
            result.error = str(exc)

        result.elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        if result.ouroboros_result:
            logger.info(
                "[Stage R] Complete: cycles=%d accuracy=%.3f→%.3f pairs=%d (%.1f ms)",
                len(result.ouroboros_result.cycles),
                result.ouroboros_result.initial_accuracy,
                result.ouroboros_result.final_accuracy,
                len(result.devolution_pairs),
                result.elapsed_ms,
            )
        return result
