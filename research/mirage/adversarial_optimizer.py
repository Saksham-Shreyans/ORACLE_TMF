"""
ORACLE-TMF  ·  research/mirage/adversarial_optimizer.py
=========================================================
MIRAGE: Adversarial Robustness Framework — Stage 2 Tier 3 / Tier 2.

Formalizes artifact poisoning as a constrained optimization problem:
find the minimum-cost set of injected artifacts that maximally shifts
the ORACLE-TMF predicted MITRE technique away from ground truth.

This serves a DEFENSIVE purpose only:
  • Quantifies how hard it is to fool ORACLE-TMF with each artifact class
  • Identifies which pipeline stages are most adversarially vulnerable
  • Guides hardening effort (where to add robustness, what to prioritize)
  • Generates synthetic adversarial examples for pipeline red-teaming

Artifact injection cost hierarchy (from the spec):
  1. Unused permissions    → EASY   (~2 bytes, no DTE/Validator bypass needed)
  2. C2 stubs (realistic) → MEDIUM (~100-2000 bytes, Validator bypass needed)
  3. Dead code (Scaffold) → HARD   (must pass DTE AND Skeptical Validator)

MIRAGE does NOT produce injection templates or evasion code.
It produces hardness scores and pipeline vulnerability reports.
All publication findings exclude implementation-ready attack vectors.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from config.stage2_settings import (
    MIRAGE_INJECTION_COSTS,
    MIRAGE_MAX_TECHNIQUE_SHIFT_COST,
)
from models.mutation_artifact_graph import MutationArtifactGraph, MutationForecast

logger = logging.getLogger(__name__)


@dataclass
class PoisoningCandidate:
    """
    A candidate artifact injection that could shift the forecast.

    Represents ONE type of artifact that an adversary could inject
    to attempt to manipulate the ORACLE-TMF output.

    Used for internal red-teaming and pipeline hardening analysis ONLY.
    """

    artifact_class: str = ""
    hardness: str = ""          # "easy", "medium", "hard"
    min_bytes: int = 0
    max_bytes: int = 0
    requires_dte_bypass: bool = False
    requires_validator_bypass: bool = False
    estimated_shift: float = 0.0   # Expected MITRE technique shift [0.0, 1.0]
    cost_score: float = 0.0        # Normalized cost [0.0, 1.0], higher = harder


@dataclass
class MIRAGEResult:
    """Output of the MIRAGE adversarial robustness analysis."""

    apk_hash: str = ""

    # Per-class poisoning difficulty scores
    poisoning_candidates: list[PoisoningCandidate] = field(default_factory=list)

    # Overall robustness score [0.0, 1.0] — higher = harder to fool
    robustness_score: float = 0.0

    # Most vulnerable artifact class (lowest cost to shift forecast)
    most_vulnerable_class: str = ""
    most_vulnerable_cost: float = 0.0

    # Hardening recommendations
    recommendations: list[str] = field(default_factory=list)

    # Which pipeline stages are most susceptible to poisoning
    vulnerable_stages: list[str] = field(default_factory=list)

    runtime_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "apk_hash": self.apk_hash,
            "robustness_score": round(self.robustness_score, 4),
            "most_vulnerable_class": self.most_vulnerable_class,
            "most_vulnerable_cost": round(self.most_vulnerable_cost, 4),
            "vulnerable_stages": self.vulnerable_stages,
            "recommendations": self.recommendations,
            "runtime_ms": round(self.runtime_ms, 2),
            "candidates": [
                {
                    "class": c.artifact_class,
                    "hardness": c.hardness,
                    "cost_score": round(c.cost_score, 4),
                    "estimated_shift": round(c.estimated_shift, 4),
                    "requires_dte_bypass": c.requires_dte_bypass,
                    "requires_validator_bypass": c.requires_validator_bypass,
                }
                for c in self.poisoning_candidates
            ],
        }


class MIRAGEEngine:
    """
    MIRAGE Adversarial Robustness Framework.

    Quantifies the effort required to poison ORACLE-TMF's forecast
    for a given APK, guiding pipeline hardening decisions.

    Usage
    -----
    >>> engine = MIRAGEEngine()
    >>> result = engine.analyze(mag, forecasts)
    """

    ENGINE_NAME = "MIRAGE"

    # Pipeline stage vulnerability map: which stages can be influenced by each class
    _STAGE_VULNERABILITY_MAP: dict[str, list[str]] = {
        "unused_permissions": ["STAGE_E", "STAGE_K"],
        "placeholder_strings": ["STAGE_F", "STAGE_J", "STAGE_K"],
        "c2_stubs": ["STAGE_G", "STAGE_J", "STAGE_K"],
        "dead_code_scaffolding": ["STAGE_D", "DTE", "STAGE_J", "STAGE_K"],
    }

    # Hardening recommendations per vulnerability class
    _RECOMMENDATIONS: dict[str, str] = {
        "unused_permissions": (
            "HARDEN: Require ≥2 corroborating artifact classes before any "
            "unused permission influences the forecast (raise D_artifact threshold)."
        ),
        "placeholder_strings": (
            "HARDEN: Apply entropy-based whitelist to placeholder strings — "
            "strings with entropy <3.5 or matching SDK patterns should not "
            "raise the confidence score independently."
        ),
        "c2_stubs": (
            "HARDEN: C2 stubs must pass Skeptical Validator topology check "
            "— require realistic URL patterns AND matching Smali call chain "
            "evidence before contributing to confidence."
        ),
        "dead_code_scaffolding": (
            "HARDEN: DTE Scaffolding class requires cross-validation with RAG "
            "historical precedent.  Isolated Scaffolding artifacts without "
            "corroborating classes should not pass the confidence gate."
        ),
    }

    def __init__(self) -> None:
        logger.info("[MIRAGE] Adversarial robustness engine initialised")

    def analyze(
        self,
        mag: MutationArtifactGraph,
        forecasts: Optional[list[MutationForecast]] = None,
    ) -> MIRAGEResult:
        """
        Analyze adversarial robustness of the ORACLE-TMF pipeline for this APK.

        Parameters
        ----------
        mag : MutationArtifactGraph
            The analysed APK's MAG with existing artifacts.
        forecasts : list[MutationForecast] | None
            Existing forecasts from Stage K.

        Returns
        -------
        MIRAGEResult
        """
        t0 = time.perf_counter()
        apk_hash = mag.apk_metadata.sha256[:16] or "unknown"
        logger.info("[MIRAGE] Analyzing robustness for APK %s", apk_hash)

        result = MIRAGEResult(apk_hash=apk_hash)

        # Step 1: For each artifact class, compute poisoning cost and impact
        candidates: list[PoisoningCandidate] = []
        for class_key, cost_spec in MIRAGE_INJECTION_COSTS.items():
            candidate = self._evaluate_poisoning_candidate(
                class_key=class_key,
                cost_spec=cost_spec,
                mag=mag,
                forecasts=forecasts or [],
            )
            candidates.append(candidate)

        result.poisoning_candidates = candidates

        # Step 2: Find most vulnerable class
        if candidates:
            most_vulnerable = min(candidates, key=lambda c: c.cost_score)
            result.most_vulnerable_class = most_vulnerable.artifact_class
            result.most_vulnerable_cost = most_vulnerable.cost_score

        # Step 3: Compute overall robustness score
        # Mean cost score across all classes — higher mean = more robust
        if candidates:
            result.robustness_score = round(
                sum(c.cost_score for c in candidates) / len(candidates), 4
            )

        # Step 4: Identify vulnerable stages
        vulnerable_stages: set[str] = set()
        for candidate in candidates:
            if candidate.cost_score < 0.5:  # Below-median robustness
                for stage in self._STAGE_VULNERABILITY_MAP.get(
                    candidate.artifact_class, []
                ):
                    vulnerable_stages.add(stage)
        result.vulnerable_stages = sorted(vulnerable_stages)

        # Step 5: Generate hardening recommendations
        recommendations: list[str] = []
        for candidate in candidates:
            if candidate.cost_score < 0.6:
                rec = self._RECOMMENDATIONS.get(candidate.artifact_class)
                if rec:
                    recommendations.append(rec)
        result.recommendations = recommendations

        elapsed_ms = (time.perf_counter() - t0) * 1000
        result.runtime_ms = round(elapsed_ms, 2)
        logger.info(
            "[MIRAGE] Complete in %.1f ms | robustness=%.3f | most_vulnerable=%s",
            elapsed_ms, result.robustness_score, result.most_vulnerable_class,
        )
        return result

    def compute_injection_cost(self, artifact_class: str) -> float:
        """
        Return the normalized injection cost [0.0, 1.0] for an artifact class.
        Higher = harder to inject (more robust against that attack vector).

        Used by OUROBOROS for synthetic devolution cost estimation.
        """
        cost_spec = MIRAGE_INJECTION_COSTS.get(artifact_class, {})
        if not cost_spec:
            return 0.5
        hardness_scores = {"easy": 0.2, "medium": 0.5, "hard": 0.9}
        return hardness_scores.get(cost_spec.get("hardness", "medium"), 0.5)

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _evaluate_poisoning_candidate(
        self,
        class_key: str,
        cost_spec: dict,
        mag: MutationArtifactGraph,
        forecasts: list[MutationForecast],
    ) -> PoisoningCandidate:
        """
        Evaluate the cost and impact of injecting artifacts of one class.

        Cost factors:
          1. Base hardness (easy/medium/hard)
          2. DTE bypass requirement (doubles cost if needed)
          3. Validator bypass requirement (1.5× cost increase)
          4. Current artifact density (denser = harder to stand out)
          5. Existing confidence level (high confidence = less susceptible to shift)
        """
        base_cost = {"easy": 0.2, "medium": 0.5, "hard": 0.85}.get(
            cost_spec.get("hardness", "medium"), 0.5
        )

        # DTE bypass penalty
        dte_penalty = 0.25 if cost_spec.get("bypass_dte", False) else 0.0

        # Validator bypass penalty
        validator_penalty = 0.15 if cost_spec.get("bypass_validator", False) else 0.0

        # Existing confidence penalty (hard to shift a confident forecast)
        max_confidence = max(
            (f.confidence_score for f in forecasts if f.passes_gate), default=0.0
        )
        confidence_penalty = max_confidence * 0.1

        total_cost = min(
            1.0,
            base_cost + dte_penalty + validator_penalty + confidence_penalty,
        )

        # Estimated shift: how much this injection could move the prediction
        # Easier injections have more impact potential (adversary can inject more)
        estimated_shift = max(0.0, 1.0 - total_cost) * 0.6  # Max 60% shift

        return PoisoningCandidate(
            artifact_class=class_key,
            hardness=cost_spec.get("hardness", "medium"),
            min_bytes=cost_spec.get("bytes_min", 0),
            max_bytes=cost_spec.get("bytes_max", 0),
            requires_dte_bypass=cost_spec.get("bypass_dte", False),
            requires_validator_bypass=cost_spec.get("bypass_validator", False),
            estimated_shift=round(estimated_shift, 4),
            cost_score=round(total_cost, 4),
        )
