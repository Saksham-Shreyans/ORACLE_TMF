from __future__ import annotations
import logging
import time
from dataclasses import dataclass,field
from typing import Optional
from models.mutation_artifact_graph import MutationArtifactGraph,MutationForecast
from research.mirage.adversarial_optimizer import MIRAGEEngine,MIRAGEResult
logger=logging.getLogger(__name__)
@dataclass
class StageQResult:
    mirage_result:Optional[MIRAGEResult]=None
    robustness_score:float=0.0
    most_vulnerable_class:str=""
    recommendations:list[str]=field(default_factory=list)
    error:str=""
    elapsed_ms:float=0.0
class StageQMIRAGERobustness:
    STAGE_ID="Q"
    STAGE_NAME="MIRAGE_ROBUSTNESS"
    def __init__(self)->None:
        self._engine=MIRAGEEngine()
        logger.info("[Stage Q] Initialised")
    def run(
        self,
        mag:MutationArtifactGraph,
        forecasts:Optional[list[MutationForecast]]=None,
    )->StageQResult:
        t0=time.perf_counter()
        result=StageQResult()
        try:
            mirage_result=self._engine.analyze(mag,forecasts=forecasts or[])
            result.mirage_result=mirage_result
            result.robustness_score=mirage_result.robustness_score
            result.most_vulnerable_class=mirage_result.most_vulnerable_class
            result.recommendations=mirage_result.recommendations
        except Exception as exc:
            logger.error("[Stage Q] MIRAGE analysis failed: %s",exc)
            result.error=str(exc)
        result.elapsed_ms=round((time.perf_counter()-t0)*1000,2)
        logger.info(
            "[Stage Q] Complete: robustness=%.3f vulnerable=%s recs=%d (%.1f ms)",
            result.robustness_score,
            result.most_vulnerable_class,
            len(result.recommendations),
            result.elapsed_ms,
        )
        return result
