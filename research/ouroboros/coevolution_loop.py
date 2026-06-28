from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass,field
from typing import Optional
from config.settings import ANTHROPIC_API_KEY,LLM_MODEL
from config.stage2_settings import(
    OUROBOROS_CONVERGENCE_THRESHOLD,
    OUROBOROS_CRITIC_MODEL,
    OUROBOROS_DEVOLUTION_REMOVAL_RATE,
    OUROBOROS_MAX_CYCLES,
)
from models.mutation_artifact_graph import MutationArtifactGraph,MutationForecast
logger=logging.getLogger(__name__)
@dataclass
class OuroborosCycle:
    cycle_number:int=0
    forecast_technique:str=""
    mature_technique:str=""
    technique_match:bool=False
    forecast_accuracy:float=0.0
    delta_accuracy:float=0.0
    refinement_applied:str=""
    devolution_pairs_generated:int=0
    elapsed_ms:float=0.0
@dataclass
class OuroborosResult:
    cycles:list[OuroborosCycle]=field(default_factory=list)
    initial_accuracy:float=0.0
    final_accuracy:float=0.0
    accuracy_improvement:float=0.0
    converged:bool=False
    converged_at_cycle:int=-1
    total_devolution_pairs:int=0
    prompt_refinements:list[str]=field(default_factory=list)
    runtime_ms:float=0.0
    def to_dict(self)->dict:
        return{
            "cycles_run":len(self.cycles),
            "initial_accuracy":round(self.initial_accuracy,4),
            "final_accuracy":round(self.final_accuracy,4),
            "accuracy_improvement":round(self.accuracy_improvement,4),
            "converged":self.converged,
            "converged_at_cycle":self.converged_at_cycle,
            "total_devolution_pairs":self.total_devolution_pairs,
            "prompt_refinements_count":len(self.prompt_refinements),
            "runtime_ms":round(self.runtime_ms,2),
            "per_cycle":[
                {
                    "cycle":c.cycle_number,
                    "predicted":c.forecast_technique,
                    "actual":c.mature_technique,
                    "match":c.technique_match,
                    "accuracy":round(c.forecast_accuracy,4),
                    "delta":round(c.delta_accuracy,4),
                }
                for c in self.cycles
            ],
        }
@dataclass
class DevolusionPair:
    family:str=""
    v_mature_hash:str=""
    v_mature_techniques:list[str]=field(default_factory=list)
    v_staging_artifacts:dict=field(default_factory=dict)
    ground_truth_technique:str=""
    devolution_rate:float=OUROBOROS_DEVOLUTION_REMOVAL_RATE
class OuroborosTMF:
    ENGINE_NAME="OUROBOROS_TMF"
    def __init__(self)->None:
        self._prompt_refinements:list[str]=[]
        logger.info("[OUROBOROS] Co-evolution engine initialised")
    def run(
        self,
        mag_staging:MutationArtifactGraph,
        forecasts:list[MutationForecast],
        ground_truth_technique:Optional[str]=None,
        max_cycles:int=OUROBOROS_MAX_CYCLES,
    )->OuroborosResult:
        t0=time.perf_counter()
        logger.info("[OUROBOROS] Starting co-evolution (%d max cycles)",max_cycles)
        result=OuroborosResult()
        if not forecasts:
            logger.warning("[OUROBOROS] No forecasts — cannot run co-evolution")
            return result
        top_forecast=max(forecasts,key=lambda f:f.confidence_score)
        prev_accuracy=0.0
        for cycle_num in range(max_cycles):
            cycle_start=time.perf_counter()
            predicted_technique=(
                top_forecast.predicted_technique
                if cycle_num==0
                else self._get_refined_prediction(top_forecast,self._prompt_refinements)
            )
            if ground_truth_technique:
                actual_technique=ground_truth_technique
            else:
                actual_technique=self._infer_mature_technique(
                    mag_staging,predicted_technique
                )
            technique_match=self._techniques_match(predicted_technique,actual_technique)
            accuracy=1.0 if technique_match else 0.0
            delta_accuracy=accuracy-prev_accuracy
            refinement=""
            if not technique_match:
                refinement=self._generate_refinement(
                    predicted=predicted_technique,
                    actual=actual_technique,
                    mag=mag_staging,
                )
                self._prompt_refinements.append(refinement)
                result.prompt_refinements.append(refinement)
            devolution_pairs=self._generate_devolution_pairs_for_cycle(
                mag_staging,actual_technique
            )
            cycle=OuroborosCycle(
                cycle_number=cycle_num,
                forecast_technique=predicted_technique,
                mature_technique=actual_technique,
                technique_match=technique_match,
                forecast_accuracy=round(accuracy,4),
                delta_accuracy=round(delta_accuracy,4),
                refinement_applied=refinement[:200]if refinement else "",
                devolution_pairs_generated=devolution_pairs,
                elapsed_ms=round((time.perf_counter()-cycle_start)*1000,2),
            )
            result.cycles.append(cycle)
            result.total_devolution_pairs+=devolution_pairs
            logger.info(
                "[OUROBOROS] Cycle %d/%d: predicted=%s actual=%s match=%s Δ=%.3f",
                cycle_num+1,max_cycles,
                predicted_technique[:30],actual_technique[:30],
                technique_match,delta_accuracy,
            )
            if abs(delta_accuracy)<OUROBOROS_CONVERGENCE_THRESHOLD and cycle_num>0:
                result.converged=True
                result.converged_at_cycle=cycle_num
                logger.info(
                    "[OUROBOROS] Converged at cycle %d (Δ=%.4f)",cycle_num,delta_accuracy
                )
                break
            prev_accuracy=accuracy
        if result.cycles:
            result.initial_accuracy=result.cycles[0].forecast_accuracy
            result.final_accuracy=result.cycles[-1].forecast_accuracy
            result.accuracy_improvement=result.final_accuracy-result.initial_accuracy
        result.runtime_ms=round((time.perf_counter()-t0)*1000,2)
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
        mag_mature_list:list[MutationArtifactGraph],
    )->list[DevolusionPair]:
        pairs:list[DevolusionPair]=[]
        removal_rate=OUROBOROS_DEVOLUTION_REMOVAL_RATE
        for mag in mag_mature_list:
            techniques=[
                f.predicted_technique
                for f in mag.forecasts
                if f.passes_gate
            ]
            if not techniques:
                continue
            n_dead=len(mag.dead_code)
            n_perms=len(mag.unused_permissions)
            n_strings=len(mag.placeholder_strings)
            devolved_counts={
                "dead_code":max(0,int(n_dead*removal_rate)),
                "unused_permissions":max(0,int(n_perms*removal_rate)),
                "placeholder_strings":max(0,int(n_strings*removal_rate)),
                "c2_stubs":max(0,int(len(mag.c2_stubs)*removal_rate)),
                "partial_apis":max(0,int(len(mag.partial_apis)*removal_rate)),
            }
            pair=DevolusionPair(
                family=mag.malware_family,
                v_mature_hash=mag.apk_metadata.sha256[:16],
                v_mature_techniques=techniques,
                v_staging_artifacts=devolved_counts,
                ground_truth_technique=techniques[0]if techniques else "",
                devolution_rate=removal_rate,
            )
            pairs.append(pair)
        logger.info("[OUROBOROS] Generated %d devolution pairs",len(pairs))
        return pairs
    def _get_refined_prediction(
        self,
        forecast:MutationForecast,
        refinements:list[str],
    )->str:
        if not refinements:
            return forecast.predicted_technique
        if not ANTHROPIC_API_KEY:
            return forecast.predicted_technique
        try:
            import anthropic
            client=anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            prompt=(
                f"Original prediction: {forecast.predicted_technique}\n"
                f"Refinements: {refinements}\n"
                f"Refine the prediction based on the refinements.\n"
                f"Respond with ONLY: {{\"technique\": \"TXXXX - Technique Name\"}}"
            )
            response=client.messages.create(
                model=LLM_MODEL,
                max_tokens=100,
                messages=[{"role":"user","content":prompt}],
            )
            import json
            text="".join(b.text for b in response.content if hasattr(b,"text"))
            parsed=json.loads(text.strip())
            return parsed.get("technique",forecast.predicted_technique)
        except Exception as exc:
            logger.debug("[OUROBOROS] Refined prediction LLM failed: %s",exc)
            return forecast.predicted_technique
    def _infer_mature_technique(
        self,
        mag:MutationArtifactGraph,
        predicted_technique:str,
    )->str:
        if not ANTHROPIC_API_KEY:
            import random
            return predicted_technique if random.random()>0.3 else "T1417 - GUI Input Capture"
        try:
            import anthropic
            client=anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            context=mag.to_llm_context(max_chars=4000)
            prompt=(
                f"You are an expert malware analyst acting as the OUROBOROS critic.\n\n"
                f"ORACLE-TMF predicted:{predicted_technique}\n\n"
                f"Staging APK artifacts:\n{context}\n\n"
                f"Based on the staging artifacts,what MITRE ATT&CK for Mobile technique "
                f"will the mature variant(v_n+1)most likely implement?\n"
                f"Respond with ONLY:{{\"technique\":\"TXXXX-Technique Name\"}}"
            )
            response=client.messages.create(
                model=OUROBOROS_CRITIC_MODEL,
                max_tokens=100,
                messages=[{"role":"user","content":prompt}],
            )
            text="".join(b.text for b in response.content if hasattr(b,"text"))
            parsed=json.loads(text.strip())
            return parsed.get("technique",predicted_technique)
        except Exception as exc:
            logger.debug("[OUROBOROS] Critic LLM failed: %s",exc)
            return predicted_technique
    def _generate_refinement(
        self,
        predicted:str,
        actual:str,
        mag:MutationArtifactGraph,
    )->str:
        if not ANTHROPIC_API_KEY:
            return(
                f"REFINEMENT:When predicting{actual},also look for "
                f"artifacts beyond those used to predict{predicted}."
            )
        try:
            import anthropic
            client=anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            prompt=(
                f"ORACLE-TMF incorrectly predicted '{predicted}' when the correct "
                f"answer was '{actual}'.\n\n"
                f"In 2 sentences,what should the Hypothesizer Agent look for "
                f"differently to distinguish '{actual}' from '{predicted}'?\n"
                f"Respond with a brief analyst note,no preamble."
            )
            response=client.messages.create(
                model=LLM_MODEL,
                max_tokens=150,
                messages=[{"role":"user","content":prompt}],
            )
            return "".join(b.text for b in response.content if hasattr(b,"text"))
        except Exception as exc:
            logger.debug("[OUROBOROS] Refinement generation failed: %s",exc)
            return f"REFINEMENT:{predicted}vs{actual}mismatch — review artifact patterns."
    @staticmethod
    def _techniques_match(predicted:str,actual:str)->bool:
        if not predicted or not actual:
            return False
        pred_id=predicted.split()[0].strip().upper()
        actual_id=actual.split()[0].strip().upper()
        return pred_id==actual_id or predicted.lower()==actual.lower()
    @staticmethod
    def _generate_devolution_pairs_for_cycle(
        mag:MutationArtifactGraph,
        actual_technique:str,
    )->int:
        active_classes=sum([
            1 if mag.dead_code else 0,
            1 if mag.unused_permissions else 0,
            1 if mag.placeholder_strings else 0,
            1 if mag.c2_stubs else 0,
        ])
        return max(1,active_classes)
