"""
ORACLE-TMF  ·  pipeline/stage2/stage_p_kinship_fingerprint.py
===============================================================
Stage P: KINSHIP Builder DNA Fingerprinting — Stage 2 Tier 3.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from models.mutation_artifact_graph import MutationArtifactGraph
from research.kinship.builder_dna import KINSHIPEngine, KINSHIPResult, BuilderDNAVector

logger = logging.getLogger(__name__)


@dataclass
class StagePResult:
    """Output of Stage P KINSHIP fingerprinting."""

    kinship_result: Optional[KINSHIPResult] = None
    primary_bdv: Optional[BuilderDNAVector] = None
    cluster_id: int = -1
    similar_apk_hashes: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""
    elapsed_ms: float = 0.0


class StagePKINSHIPFingerprint:
    """
    Stage P: KINSHIP Builder DNA Fingerprinting.

    Usage
    -----
    >>> stage = StagePKINSHIPFingerprint()
    >>> result = stage.run(mag)                    # single APK
    >>> result = stage.run(mag, corpus_mags)       # attribution against corpus
    """

    STAGE_ID = "P"
    STAGE_NAME = "KINSHIP_FINGERPRINT"

    def __init__(self) -> None:
        self._engine = KINSHIPEngine()
        logger.info("[Stage P] Initialised")

    def run(
        self,
        mag: MutationArtifactGraph,
        corpus_mags: Optional[list[MutationArtifactGraph]] = None,
    ) -> StagePResult:
        """
        Run KINSHIP fingerprinting for attribution.

        Parameters
        ----------
        mag : MutationArtifactGraph
            The APK to fingerprint.
        corpus_mags : list[MutationArtifactGraph] | None
            Known-attributed APK corpus for comparison.
            None = fingerprint only, no clustering.

        Returns
        -------
        StagePResult
        """
        t0 = time.perf_counter()
        result = StagePResult()

        try:
            all_mags = [mag] + (corpus_mags or [])
            kinship_result = self._engine.run(all_mags)
            result.kinship_result = kinship_result

            # The primary BDV is always the first one (the target APK)
            if kinship_result.bdv_list:
                bdv = kinship_result.bdv_list[0]
                result.primary_bdv = bdv
                result.cluster_id = kinship_result.cluster_assignments.get(bdv.apk_hash, -1)
                result.similar_apk_hashes = bdv.similar_apks

        except Exception as exc:
            logger.error("[Stage P] KINSHIP failed: %s", exc)
            result.error = str(exc)

        result.elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        logger.info(
            "[Stage P] Complete: cluster=%d similar=%d (%.1f ms)",
            result.cluster_id, len(result.similar_apk_hashes), result.elapsed_ms,
        )
        return result
