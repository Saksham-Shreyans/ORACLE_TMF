from __future__ import annotations
import logging
import time
from dataclasses import dataclass,field
from typing import Optional
from models.mutation_artifact_graph import MutationArtifactGraph,MutationForecast
from research.ouroboros.coevolution_loop import OuroborosTMF,OuroborosResult,DevolusionPair
logger=logging.getLogger(__name__)
@dataclass
class StageRResult:
    ouroboros_result:Optional[OuroborosResult]=None
    devolution_pairs:list[DevolusionPair]=field(default_factory=list)
    accuracy_improvement:float=0.0
    prompt_refinements:list[str]=field(default_factory=list)
    skipped:bool=False
    skip_reason:str=""
    error:str=""
    elapsed_ms:float=0.0
class StageROuroborosCoevolution:
    STAGE_ID="R"
    STAGE_NAME="OUROBOROS_COEVOLUTION"
    def __init__(self,enabled:bool=False)->None:
        self._enabled=enabled
        self._engine=OuroborosTMF()if enabled else None
        logger.info("[Stage R] Initialised (enabled=%s)",enabled)
    def run(
        self,
        mag:MutationArtifactGraph,
        forecasts:list[MutationForecast],
        ground_truth_technique:Optional[str]=None,
        mature_corpus:Optional[list[MutationArtifactGraph]]=None,
    )->StageRResult:
        t0=time.perf_counter()
        result=StageRResult()
        if not self._enabled or self._engine is None:
            result.skipped=True
            result.skip_reason="OUROBOROS disabled — set ouroboros_enabled=True for research mode"
            logger.info("[Stage R] Skipped: disabled")
            return result
        if not forecasts:
            result.skipped=True
            result.skip_reason="No forecasts available — Stage K must run first"
            return result
        try:
            ouroboros_result=self._engine.run(
                mag_staging=mag,
                forecasts=forecasts,
                ground_truth_technique=ground_truth_technique,
            )
            result.ouroboros_result=ouroboros_result
            result.accuracy_improvement=ouroboros_result.accuracy_improvement
            result.prompt_refinements=ouroboros_result.prompt_refinements
            if mature_corpus:
                result.devolution_pairs=self._engine.generate_devolution_pairs(
                    mature_corpus
                )
        except Exception as exc:
            logger.error("[Stage R] OUROBOROS failed: %s",exc)
            result.error=str(exc)
        result.elapsed_ms=round((time.perf_counter()-t0)*1000,2)
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
