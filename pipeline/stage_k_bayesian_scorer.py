from __future__ import annotations
import logging
import time
from typing import Optional
from config.settings import(
    ARTIFACT_DENSITY_SCORES,
    BAYESIAN_WEIGHT_D_ARTIFACT,
    BAYESIAN_WEIGHT_H_PRIOR,
    BAYESIAN_WEIGHT_P_LLM,
    CONFIDENCE_GATE_THRESHOLD,
    MVV_CLIP_HIGH,
    MVV_CLIP_LOW,
)
from models.mutation_artifact_graph import(
    MutationArtifactGraph,
    MutationForecast,
    VersionDelta,
)
logger=logging.getLogger(__name__)
assert abs(
    BAYESIAN_WEIGHT_P_LLM+BAYESIAN_WEIGHT_D_ARTIFACT+BAYESIAN_WEIGHT_H_PRIOR-1.0
)<1e-6,"Bayesian weights do not sum to 1.0"
class BayesianScorer:
    STAGE_NAME="STAGE_K"
    def __init__(self)->None:
        self._rag:Optional[object]=None
    def run(
        self,
        forecasts:list[MutationForecast],
        mag:MutationArtifactGraph,
        rag:Optional[object]=None,
    )->list[MutationForecast]:
        t0=time.perf_counter()
        logger.info("[Stage K] Starting Bayesian confidence scoring for %d forecast(s)",len(forecasts))
        if not forecasts:
            return[]
        self._rag=rag
        d_artifact=self._compute_artifact_density(mag)
        mvv_norm=self._get_mvv_norm(mag.version_delta)
        logger.debug(
            "[Stage K] D_artifact=%.3f | MVV_norm=%.3f",
            d_artifact,mvv_norm,
        )
        scored:list[MutationForecast]=[]
        for forecast in forecasts:
            self._score_forecast(forecast,d_artifact,mvv_norm,mag)
            scored.append(forecast)
            logger.debug(
                "[Stage K] Technique=%s | P_LLM=%.3f | C=%.3f | gate=%s",
                forecast.predicted_technique,
                forecast.p_llm,
                forecast.confidence_score,
                forecast.passes_gate,
            )
        scored.sort(key=lambda f:f.confidence_score,reverse=True)
        passed=sum(1 for f in scored if f.passes_gate)
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage K] Complete in %.1f ms | scored=%d | passed_gate=%d",
            elapsed_ms,len(scored),passed,
        )
        return scored
    def _score_forecast(
        self,
        forecast:MutationForecast,
        d_artifact:float,
        mvv_norm:float,
        mag:MutationArtifactGraph,
    )->None:
        p_llm=self._sanitise_probability(forecast.p_llm)
        d_artifact_refined=self._refine_artifact_density(
            d_artifact,forecast.supporting_artifacts
        )
        h_prior=self._get_historical_prior(
            technique=forecast.predicted_technique,
            family=mag.malware_family,
        )
        confidence=(
            BAYESIAN_WEIGHT_P_LLM*p_llm
            +BAYESIAN_WEIGHT_D_ARTIFACT*d_artifact_refined*mvv_norm
            +BAYESIAN_WEIGHT_H_PRIOR*h_prior
        )
        confidence=self._sanitise_probability(confidence)
        forecast.artifact_density=round(d_artifact_refined,4)
        forecast.mvv_normalized=round(mvv_norm,4)
        forecast.h_prior=round(h_prior,4)
        forecast.confidence_score=round(confidence,4)
        forecast.passes_gate=confidence>CONFIDENCE_GATE_THRESHOLD
    @staticmethod
    def _compute_artifact_density(mag:MutationArtifactGraph)->float:
        active=sum([
            1 if mag.dead_code else 0,
            1 if mag.unused_permissions else 0,
            1 if mag.placeholder_strings else 0,
            1 if mag.c2_stubs else 0,
            1 if mag.partial_apis else 0,
            1 if mag.unfinished_ui_flows else 0,
            1 if mag.genai_scaffolds else 0,
        ])
        n_active=min(active,3)
        return ARTIFACT_DENSITY_SCORES.get(n_active,0.0)
    @staticmethod
    def _refine_artifact_density(
        base_density:float,supporting_classes:list[str]
    )->float:
        n_supporting=len(set(supporting_classes))
        if n_supporting>=3:
            return min(1.0,base_density+0.10)
        elif n_supporting==2:
            return min(1.0,base_density+0.05)
        return base_density
    @staticmethod
    def _get_mvv_norm(delta:Optional[VersionDelta])->float:
        if delta is None:
            return 1.0
        mvv=delta.mvv_normalized
        return max(MVV_CLIP_LOW,min(MVV_CLIP_HIGH,mvv))
    def _get_historical_prior(self,technique:str,family:str)->float:
        DEFAULT_PRIOR=0.30
        if self._rag is None or not technique:
            return DEFAULT_PRIOR
        try:
            query=f"{family} malware {technique} historical precedent evolution"
            docs=self._rag.retrieve(query,top_k=3)
            if not docs:
                return DEFAULT_PRIOR
            technique_id=technique.split(" - ")[0].strip()if " - "in technique else technique
            hit_count=sum(
                1 for doc in docs
                if technique_id.lower()in doc.get("text","").lower()
            )
            if hit_count>=2:
                return 0.75
            elif hit_count==1:
                return 0.50
            return DEFAULT_PRIOR
        except Exception as exc:
            logger.debug("[Stage K] H_prior lookup failed: %s",exc)
            return DEFAULT_PRIOR
    @staticmethod
    def _sanitise_probability(value:float)->float:
        return max(0.0,min(1.0,float(value)if value is not None else 0.0))
