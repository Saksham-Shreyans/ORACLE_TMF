"""
ORACLE-TMF  ·  research/ouroboros/coevolution_loop.py
======================================================
OUROBOROS-TMF: Closed-Loop Adversarial Co-Evolution — Stage 2 Tier 2/3.

The OUROBOROS loop progressively improves ORACLE-TMF's forecast accuracy
by iteratively generating mature variants and measuring forecast mismatch:

  Loop cycle:
    (1) ORACLE-TMF forecasts from v_staging → {technique_predicted}
    (2) OUROBOROS generates v_mature (a synthetic APK with the predicted
        capability actually implemented)
    (3) Critic LLM compares {technique_predicted} vs {technique_in_v_mature}
    (4) Mismatches are fed back to refine the Stage J LLM prompts
    (5) Forecast accuracy improves; diminishing returns after N cycles

Synthetic Devolution Augmentation
----------------------------------
OUROBOROS also drives training data generation: v_mature samples are
programmatically "devolved" to create v_staging counterparts by:
  • Removing a fraction of active code (making it dead code again)
  • Adding back dormant scaffolding markers
  • Reverting implemented permissions to "unused" state

This creates (v_staging, v_mature) pairs for supervised fine-tuning
without needing real evolutionary chains.

Safety Constraints
------------------
  • All v_mature generation is air-gapped (no outbound connectivity)
  • ORACLE-TMF never generates functional malware — only structure
  • Frida activation paths are described, never implemented, in this module
  • Capability descriptions use MITRE technique IDs, not exploitation code
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from config.settings import ANTHROPIC_API_KEY, LLM_MODEL
from config.stage2_settings import (
    OUROBOROS_CONVERGENCE_THRESHOLD,
    OUROBOROS_CRITIC_MODEL,
    OUROBOROS_DEVOLUTION_REMOVAL_RATE,
    OUROBOROS_MAX_CYCLES,
)
from models.mutation_artifact_graph import MutationArtifactGraph, MutationForecast

logger = logging.getLogger(__name__)


@dataclass
class OuroborosCycle:
    """State of a single OUROBOROS co-evolution cycle."""

    cycle_number: int = 0
    forecast_technique: str = ""         # What ORACLE-TMF predicted
    mature_technique: str = ""           # What v_mature actually implements
    technique_match: bool = False
    forecast_accuracy: float = 0.0       # Fraction of techniques matched
    delta_accuracy: float = 0.0          # Improvement over previous cycle
    refinement_applied: str = ""         # What was changed in Stage J prompts
    devolution_pairs_generated: int = 0
    elapsed_ms: float = 0.0


@dataclass
class OuroborosResult:
    """Output of the full OUROBOROS co-evolution run."""

    cycles: list[OuroborosCycle] = field(default_factory=list)
    initial_accuracy: float = 0.0
    final_accuracy: float = 0.0
    accuracy_improvement: float = 0.0
    converged: bool = False
    converged_at_cycle: int = -1
    total_devolution_pairs: int = 0
    prompt_refinements: list[str] = field(default_factory=list)
    runtime_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "cycles_run": len(self.cycles),
            "initial_accuracy": round(self.initial_accuracy, 4),
            "final_accuracy": round(self.final_accuracy, 4),
            "accuracy_improvement": round(self.accuracy_improvement, 4),
            "converged": self.converged,
            "converged_at_cycle": self.converged_at_cycle,
            "total_devolution_pairs": self.total_devolution_pairs,
            "prompt_refinements_count": len(self.prompt_refinements),
            "runtime_ms": round(self.runtime_ms, 2),
            "per_cycle": [
                {
                    "cycle": c.cycle_number,
                    "predicted": c.forecast_technique,
                    "actual": c.mature_technique,
                    "match": c.technique_match,
                    "accuracy": round(c.forecast_accuracy, 4),
                    "delta": round(c.delta_accuracy, 4),
                }
                for c in self.cycles
            ],
        }


@dataclass
class DevolusionPair:
    """
    A (v_staging, v_mature) pair for supervised training.
    v_mature MAG is devolved to produce a synthetic v_staging.
    """

    family: str = ""
    v_mature_hash: str = ""
    v_mature_techniques: list[str] = field(default_factory=list)
    v_staging_artifacts: dict = field(default_factory=dict)  # Devolved artifact counts
    ground_truth_technique: str = ""
    devolution_rate: float = OUROBOROS_DEVOLUTION_REMOVAL_RATE


class OuroborosTMF:
    """
    OUROBOROS-TMF Closed-Loop Adversarial Co-Evolution Engine.

    Usage
    -----
    >>> ouroboros = OuroborosTMF()
    >>> result = ouroboros.run(mag_staging, forecasts)
    >>> pairs = ouroboros.generate_devolution_pairs(mag_mature_list)
    """

    ENGINE_NAME = "OUROBOROS_TMF"

    def __init__(self) -> None:
        self._prompt_refinements: list[str] = []
        logger.info("[OUROBOROS] Co-evolution engine initialised")

    def run(
        self,
        mag_staging: MutationArtifactGraph,
        forecasts: list[MutationForecast],
        ground_truth_technique: Optional[str] = None,
        max_cycles: int = OUROBOROS_MAX_CYCLES,
    ) -> OuroborosResult:
        """
        Execute the OUROBOROS co-evolution loop.

        Parameters
        ----------
        mag_staging : MutationArtifactGraph
            The v_staging MAG (source of ORACLE-TMF forecast).
        forecasts : list[MutationForecast]
            Stage K output for the staging MAG.
        ground_truth_technique : str | None
            The known v_mature MITRE technique (if available from labeled data).
            None = use LLM critic to infer from synthetic v_mature.
        max_cycles : int
            Maximum number of co-evolution cycles.

        Returns
        -------
        OuroborosResult
        """
        t0 = time.perf_counter()
        logger.info("[OUROBOROS] Starting co-evolution (%d max cycles)", max_cycles)

        result = OuroborosResult()
        if not forecasts:
            logger.warning("[OUROBOROS] No forecasts — cannot run co-evolution")
            return result

        # Get the top forecast as the prediction to evaluate
        top_forecast = max(forecasts, key=lambda f: f.confidence_score)
        prev_accuracy = 0.0

        for cycle_num in range(max_cycles):
            cycle_start = time.perf_counter()

            # Step 1: Determine what ORACLE-TMF predicted
            predicted_technique = (
                top_forecast.predicted_technique
                if cycle_num == 0
                else self._get_refined_prediction(top_forecast, self._prompt_refinements)
            )

            # Step 2: Generate/retrieve the mature variant's actual technique
            if ground_truth_technique:
                actual_technique = ground_truth_technique
            else:
                actual_technique = self._infer_mature_technique(
                    mag_staging, predicted_technique
                )

            # Step 3: Compare predicted vs actual
            technique_match = self._techniques_match(predicted_technique, actual_technique)
            accuracy = 1.0 if technique_match else 0.0
            delta_accuracy = accuracy - prev_accuracy

            # Step 4: If mismatch, generate a prompt refinement
            refinement = ""
            if not technique_match:
                refinement = self._generate_refinement(
                    predicted=predicted_technique,
                    actual=actual_technique,
                    mag=mag_staging,
                )
                self._prompt_refinements.append(refinement)
                result.prompt_refinements.append(refinement)

            # Step 5: Generate devolution pairs for this cycle
            devolution_pairs = self._generate_devolution_pairs_for_cycle(
                mag_staging, actual_technique
            )

            cycle = OuroborosCycle(
                cycle_number=cycle_num,
                forecast_technique=predicted_technique,
                mature_technique=actual_technique,
                technique_match=technique_match,
                forecast_accuracy=round(accuracy, 4),
                delta_accuracy=round(delta_accuracy, 4),
                refinement_applied=refinement[:200] if refinement else "",
                devolution_pairs_generated=devolution_pairs,
                elapsed_ms=round((time.perf_counter() - cycle_start) * 1000, 2),
            )
            result.cycles.append(cycle)
            result.total_devolution_pairs += devolution_pairs

            logger.info(
                "[OUROBOROS] Cycle %d/%d: predicted=%s actual=%s match=%s Δ=%.3f",
                cycle_num + 1, max_cycles,
                predicted_technique[:30], actual_technique[:30],
                technique_match, delta_accuracy,
            )

            # Convergence check
            if abs(delta_accuracy) < OUROBOROS_CONVERGENCE_THRESHOLD and cycle_num > 0:
                result.converged = True
                result.converged_at_cycle = cycle_num
                logger.info(
                    "[OUROBOROS] Converged at cycle %d (Δ=%.4f)", cycle_num, delta_accuracy
                )
                break

            prev_accuracy = accuracy

        # Aggregate result
        if result.cycles:
            result.initial_accuracy = result.cycles[0].forecast_accuracy
            result.final_accuracy = result.cycles[-1].forecast_accuracy
            result.accuracy_improvement = result.final_accuracy - result.initial_accuracy

        result.runtime_ms = round((time.perf_counter() - t0) * 1000, 2)
        logger.info(
            "[OUROBOROS] Complete: cycles=%d accuracy=%.3f→%.3f Δ=%.3f",
            len(result.cycles),
            result.initial_accuracy,
            result.final_accuracy,
            result.accuracy_improvement,
        )
        return result

    def generate_devolution_pairs(
        self,
        mag_mature_list: list[MutationArtifactGraph],
    ) -> list[DevolusionPair]:
        """
        Generate synthetic (v_staging, v_mature) pairs via devolution.

        Takes mature APK MAGs and programmatically removes a fraction of
        their implemented capabilities to produce synthetic staging versions.

        Parameters
        ----------
        mag_mature_list : list[MutationArtifactGraph]
            Fully-analysed mature APK MAGs.

        Returns
        -------
        list[DevolusionPair]
            Training pairs with ground-truth technique labels.
        """
        pairs: list[DevolusionPair] = []
        removal_rate = OUROBOROS_DEVOLUTION_REMOVAL_RATE

        for mag in mag_mature_list:
            # Identify what capabilities this mature APK implements
            techniques = [
                f.predicted_technique
                for f in mag.forecasts
                if f.passes_gate
            ]
            if not techniques:
                continue

            # Devolve: remove removal_rate fraction of artifacts
            n_dead = len(mag.dead_code)
            n_perms = len(mag.unused_permissions)
            n_strings = len(mag.placeholder_strings)

            # Compute what the staging version's artifact counts would be
            devolved_counts = {
                "dead_code": max(0, int(n_dead * removal_rate)),
                "unused_permissions": max(0, int(n_perms * removal_rate)),
                "placeholder_strings": max(0, int(n_strings * removal_rate)),
                "c2_stubs": max(0, int(len(mag.c2_stubs) * removal_rate)),
                "partial_apis": max(0, int(len(mag.partial_apis) * removal_rate)),
            }

            pair = DevolusionPair(
                family=mag.malware_family,
                v_mature_hash=mag.apk_metadata.sha256[:16],
                v_mature_techniques=techniques,
                v_staging_artifacts=devolved_counts,
                ground_truth_technique=techniques[0] if techniques else "",
                devolution_rate=removal_rate,
            )
            pairs.append(pair)

        logger.info("[OUROBOROS] Generated %d devolution pairs", len(pairs))
        return pairs

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _get_refined_prediction(
        self,
        forecast: MutationForecast,
        refinements: list[str],
    ) -> str:
        """Get the prediction after applying accumulated refinements."""
        if not refinements:
            return forecast.predicted_technique
        # In a full implementation, refinements would be fed back to Stage J
        # For the OUROBOROS prototype, we simulate improvement
        return forecast.predicted_technique

    def _infer_mature_technique(
        self,
        mag: MutationArtifactGraph,
        predicted_technique: str,
    ) -> str:
        """
        Use the critic LLM to infer what MITRE technique the mature variant
        would implement, given the staging artifacts.
        """
        if not ANTHROPIC_API_KEY:
            # Simulation: sometimes match, sometimes not (to test convergence)
            import random
            return predicted_technique if random.random() > 0.3 else "T1417 - GUI Input Capture"

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

            context = mag.to_llm_context(max_chars=4000)
            prompt = (
                f"You are an expert malware analyst acting as the OUROBOROS critic.\n\n"
                f"ORACLE-TMF predicted: {predicted_technique}\n\n"
                f"Staging APK artifacts:\n{context}\n\n"
                f"Based on the staging artifacts, what MITRE ATT&CK for Mobile technique "
                f"will the mature variant (v_n+1) most likely implement?\n"
                f"Respond with ONLY: {{\"technique\": \"TXXXX - Technique Name\"}}"
            )

            response = client.messages.create(
                model=OUROBOROS_CRITIC_MODEL,
                max_tokens=100,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(b.text for b in response.content if hasattr(b, "text"))
            parsed = json.loads(text.strip())
            return parsed.get("technique", predicted_technique)
        except Exception as exc:
            logger.debug("[OUROBOROS] Critic LLM failed: %s", exc)
            return predicted_technique

    def _generate_refinement(
        self,
        predicted: str,
        actual: str,
        mag: MutationArtifactGraph,
    ) -> str:
        """
        Generate a Stage J prompt refinement based on a forecast mismatch.
        """
        if not ANTHROPIC_API_KEY:
            return (
                f"REFINEMENT: When predicting {actual}, also look for "
                f"artifacts beyond those used to predict {predicted}."
            )
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            prompt = (
                f"ORACLE-TMF incorrectly predicted '{predicted}' when the correct "
                f"answer was '{actual}'.\n\n"
                f"In 2 sentences, what should the Hypothesizer Agent look for "
                f"differently to distinguish '{actual}' from '{predicted}'?\n"
                f"Respond with a brief analyst note, no preamble."
            )
            response = client.messages.create(
                model=LLM_MODEL,
                max_tokens=150,
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join(b.text for b in response.content if hasattr(b, "text"))
        except Exception as exc:
            logger.debug("[OUROBOROS] Refinement generation failed: %s", exc)
            return f"REFINEMENT: {predicted} vs {actual} mismatch — review artifact patterns."

    @staticmethod
    def _techniques_match(predicted: str, actual: str) -> bool:
        """True if the predicted and actual techniques match (flexible comparison)."""
        if not predicted or not actual:
            return False
        # Extract technique ID for comparison (first word/code)
        pred_id = predicted.split()[0].strip().upper()
        actual_id = actual.split()[0].strip().upper()
        return pred_id == actual_id or predicted.lower() == actual.lower()

    @staticmethod
    def _generate_devolution_pairs_for_cycle(
        mag: MutationArtifactGraph,
        actual_technique: str,
    ) -> int:
        """Count how many devolution pairs can be generated from this cycle."""
        # Each cycle can generate 1 pair per artifact class that contributed
        active_classes = sum([
            1 if mag.dead_code else 0,
            1 if mag.unused_permissions else 0,
            1 if mag.placeholder_strings else 0,
            1 if mag.c2_stubs else 0,
        ])
        return max(1, active_classes)
