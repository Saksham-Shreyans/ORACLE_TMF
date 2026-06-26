"""
ORACLE-TMF  ·  pipeline/stage_k_bayesian_scorer.py
====================================================
STAGE K — Probabilistic Mutation Forecast Generator (Bayesian Scoring)

Responsibility:
  • Apply the Bayesian ensemble formula to each MutationForecast from Stage J
  • Compute the final confidence score C for each forecast
  • Apply the gating threshold (C > 0.72) to filter low-confidence predictions
  • Retrieve the historical prior H_prior from the RAG for the family

Confidence Formula (ORACLE-TMF Stage 1 Specification):
  C = (0.45 × P_LLM) + (0.35 × D_artifact × MVV_norm) + (0.20 × H_prior)

Where:
  P_LLM        : Normalised logprob confidence from Agent 3 (Skeptical Validator)
  D_artifact   : Artifact density score [0.33, 0.66, 1.00] based on convergence
  MVV_norm     : Mutation Velocity Vector from Stage I, clipped to [0.5, 1.5]
  H_prior      : RAG-retrieved historical frequency of this technique in the family

Gating: Forecasts are suppressed if C ≤ 0.72

Inputs:
  forecasts : list[MutationForecast]  — from Stage J (p_llm populated)
  mag       : MutationArtifactGraph   — for artifact density + MAG data
  rag       : Optional RAGRetriever   — for H_prior lookup

Outputs: list[MutationForecast]  — with confidence_score and passes_gate set
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from config.settings import (
    ARTIFACT_DENSITY_SCORES,
    BAYESIAN_WEIGHT_D_ARTIFACT,
    BAYESIAN_WEIGHT_H_PRIOR,
    BAYESIAN_WEIGHT_P_LLM,
    CONFIDENCE_GATE_THRESHOLD,
    MVV_CLIP_HIGH,
    MVV_CLIP_LOW,
)
from models.mutation_artifact_graph import (
    MutationArtifactGraph,
    MutationForecast,
    VersionDelta,
)

logger = logging.getLogger(__name__)

# Sanity check: weights must sum to 1.0
assert abs(
    BAYESIAN_WEIGHT_P_LLM + BAYESIAN_WEIGHT_D_ARTIFACT + BAYESIAN_WEIGHT_H_PRIOR - 1.0
) < 1e-6, "Bayesian weights do not sum to 1.0"


class BayesianScorer:
    """
    Stage K: Probabilistic Mutation Forecast Generator.

    Applies the Bayesian ensemble formula and gates low-confidence forecasts.

    Usage
    -----
    >>> scorer = BayesianScorer()
    >>> scored = scorer.run(forecasts, mag)
    """

    STAGE_NAME = "STAGE_K"

    def __init__(self) -> None:
        self._rag: Optional[object] = None   # Populated lazily from Stage J's RAGRetriever

    # ─────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────

    def run(
        self,
        forecasts: list[MutationForecast],
        mag: MutationArtifactGraph,
        rag: Optional[object] = None,
    ) -> list[MutationForecast]:
        """
        Execute Stage K.

        Parameters
        ----------
        forecasts : list[MutationForecast]
            Output of Stage J with p_llm populated.
        mag : MutationArtifactGraph
            Used to compute D_artifact and retrieve MVV_norm.
        rag : Optional RAGRetriever
            For H_prior lookup from historical family data.

        Returns
        -------
        list[MutationForecast]
            All forecasts with confidence_score and passes_gate set.
            Sorted by confidence descending.
        """
        t0 = time.perf_counter()
        logger.info("[Stage K] Starting Bayesian confidence scoring for %d forecast(s)", len(forecasts))

        if not forecasts:
            return []

        self._rag = rag

        # Precompute shared components
        d_artifact  = self._compute_artifact_density(mag)
        mvv_norm    = self._get_mvv_norm(mag.version_delta)

        logger.debug(
            "[Stage K] D_artifact=%.3f | MVV_norm=%.3f",
            d_artifact, mvv_norm,
        )

        scored: list[MutationForecast] = []
        for forecast in forecasts:
            self._score_forecast(forecast, d_artifact, mvv_norm, mag)
            scored.append(forecast)
            logger.debug(
                "[Stage K] Technique=%s | P_LLM=%.3f | C=%.3f | gate=%s",
                forecast.predicted_technique,
                forecast.p_llm,
                forecast.confidence_score,
                forecast.passes_gate,
            )

        # Sort by confidence descending
        scored.sort(key=lambda f: f.confidence_score, reverse=True)

        passed = sum(1 for f in scored if f.passes_gate)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[Stage K] Complete in %.1f ms | scored=%d | passed_gate=%d",
            elapsed_ms, len(scored), passed,
        )
        return scored

    # ─────────────────────────────────────────────────────────
    #  SCORING LOGIC
    # ─────────────────────────────────────────────────────────

    def _score_forecast(
        self,
        forecast: MutationForecast,
        d_artifact: float,
        mvv_norm: float,
        mag: MutationArtifactGraph,
    ) -> None:
        """
        Apply the Bayesian formula to a single forecast in-place.

        C = (w₁ × P_LLM) + (w₂ × D_artifact × MVV_norm) + (w₃ × H_prior)
        w₁=0.45, w₂=0.35, w₃=0.20
        """
        p_llm = self._sanitise_probability(forecast.p_llm)

        # Refine artifact density using the forecast's supporting artifact classes
        d_artifact_refined = self._refine_artifact_density(
            d_artifact, forecast.supporting_artifacts
        )

        # Retrieve historical prior for this technique + family
        h_prior = self._get_historical_prior(
            technique       = forecast.predicted_technique,
            family          = mag.malware_family,
        )

        # Compute weighted sum
        confidence = (
            BAYESIAN_WEIGHT_P_LLM      * p_llm
            + BAYESIAN_WEIGHT_D_ARTIFACT * d_artifact_refined * mvv_norm
            + BAYESIAN_WEIGHT_H_PRIOR    * h_prior
        )
        confidence = self._sanitise_probability(confidence)

        # Populate forecast
        forecast.artifact_density  = round(d_artifact_refined, 4)
        forecast.mvv_normalized    = round(mvv_norm, 4)
        forecast.h_prior           = round(h_prior, 4)
        forecast.confidence_score  = round(confidence, 4)
        forecast.passes_gate       = confidence > CONFIDENCE_GATE_THRESHOLD

    # ─────────────────────────────────────────────────────────
    #  COMPONENT COMPUTATIONS
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _compute_artifact_density(mag: MutationArtifactGraph) -> float:
        """
        D_artifact: multi-artifact convergence score.

        Counts how many distinct artifact classes have ≥1 detected artifact.
        Maps to: 1 class→0.33, 2 classes→0.66, 3+ classes→1.00
        """
        active = sum([
            1 if mag.dead_code           else 0,
            1 if mag.unused_permissions  else 0,
            1 if mag.placeholder_strings else 0,
            1 if mag.c2_stubs            else 0,
            1 if mag.partial_apis        else 0,
            1 if mag.unfinished_ui_flows else 0,
            1 if mag.genai_scaffolds     else 0,
        ])
        n_active = min(active, 3)   # Cap at 3 for scoring
        return ARTIFACT_DENSITY_SCORES.get(n_active, 0.0)

    @staticmethod
    def _refine_artifact_density(
        base_density: float, supporting_classes: list[str]
    ) -> float:
        """
        Refine D_artifact based on the forecast's specific supporting artifact classes.
        If the hypothesis cites more artifact types, increase density slightly.
        """
        n_supporting = len(set(supporting_classes))
        if n_supporting >= 3:
            return min(1.0, base_density + 0.10)
        elif n_supporting == 2:
            return min(1.0, base_density + 0.05)
        return base_density

    @staticmethod
    def _get_mvv_norm(delta: Optional[VersionDelta]) -> float:
        """
        Retrieve the normalised Mutation Velocity Vector from the version delta.
        Returns 1.0 if no prior version is available (neutral velocity).
        """
        if delta is None:
            return 1.0   # No prior version — neutral
        mvv = delta.mvv_normalized
        # Clip to [MVV_CLIP_LOW, MVV_CLIP_HIGH] as specified
        return max(MVV_CLIP_LOW, min(MVV_CLIP_HIGH, mvv))

    def _get_historical_prior(self, technique: str, family: str) -> float:
        """
        H_prior: frequency of this technique in the historical evolution of
        the identified malware family.

        Queried from the RAG vector store.  Falls back to a default prior
        (0.3) if RAG is unavailable or the family is unknown.
        """
        DEFAULT_PRIOR = 0.30   # Moderate default prior

        if self._rag is None or not technique:
            return DEFAULT_PRIOR

        try:
            query = f"{family} malware {technique} historical precedent evolution"
            docs  = self._rag.retrieve(query, top_k=3)  # type: ignore
            if not docs:
                return DEFAULT_PRIOR

            # Heuristic: if the technique ID appears in the retrieved documents,
            # estimate a higher prior
            technique_id = technique.split(" - ")[0].strip() if " - " in technique else technique
            hit_count = sum(
                1 for doc in docs
                if technique_id.lower() in doc.get("text", "").lower()
            )
            if hit_count >= 2:
                return 0.75
            elif hit_count == 1:
                return 0.50
            return DEFAULT_PRIOR

        except Exception as exc:
            logger.debug("[Stage K] H_prior lookup failed: %s", exc)
            return DEFAULT_PRIOR

    # ─────────────────────────────────────────────────────────
    #  UTILITY
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _sanitise_probability(value: float) -> float:
        """Clip a probability value to [0.0, 1.0]."""
        return max(0.0, min(1.0, float(value) if value is not None else 0.0))
