"""
ORACLE-TMF  Â·  orchestrator_stage2.py
=======================================
Stage 2 Orchestrator â€” integrates all Tier 2 and Tier 3 engines
around the existing Stage 1 pipeline output (Stages Aâ€“L).

Design principle: Stage 2 is additive.  It NEVER modifies Stage 1 files.
Each engine runs in isolation; failure in one does not propagate.

Execution order (all optional, controlled by Stage2Config):
  Stage M  â€” PHANTOM detonation (requires phantom_enabled=True)
  Stage N  â€” NAV analysis (always runs if mag_prev is provided)
  Stage O  â€” CABAL collusion (requires â‰¥2 APKs in mag_list)
  Stage P  â€” KINSHIP fingerprinting
  Stage Q  â€” MIRAGE robustness analysis
  Stage R  â€” OUROBOROS co-evolution (requires ouroboros_enabled=True)
  Network  â€” DDoS/ANC signature detection
  Synth    â€” Synthetic variant generation (research mode)

Usage
-----
>>> from orchestrator_stage2 import Stage2Orchestrator, Stage2Config
>>> cfg = Stage2Config()
>>> orch = Stage2Orchestrator(cfg)
>>> report = orch.run(mag, mag_prev=mag_prev, forecasts=forecasts)
"""
from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass,field
from pathlib import Path
from typing import Optional
from config.settings import CONFIDENCE_GATE_THRESHOLD
from models.mutation_artifact_graph import MutationArtifactGraph,MutationForecast
from models.nav_models import NAVHistory
from pipeline.stage2.stage_m_phantom_detonation import StageMPhantomDetonation,StageMResult
from pipeline.stage2.stage_n_nav_analysis import StageNNAVAnalysis,StageNResult
from pipeline.stage2.stage_o_cabal_analysis import StageOCABALAnalysis,StageOResult
from pipeline.stage2.stage_p_kinship_fingerprint import StagePKINSHIPFingerprint,StagePResult
from pipeline.stage2.stage_q_mirage_robustness import StageQMIRAGERobustness,StageQResult
from pipeline.stage2.stage_r_ouroboros_coevolution import StageROuroborosCoevolution,StageRResult
from research.network_attack.ddos_analyzer import NetworkAttackAnalyzer,NetworkAttackResult
from research.synthetic_variant.variant_generator import SyntheticVariantGenerator
logger=logging.getLogger(__name__)
@dataclass
class Stage2Config:
    """
    Configuration for Stage 2 pipeline execution.

    All Stage 2 components are opt-in.  Only NAV runs by default
    (it is the only Stage 2 component that modifies Stage K output).
    """
    phantom_enabled:bool=False
    nav_enabled:bool=True
    use_llm_for_cabal:bool=True
    cabal_enabled:bool=False
    kinship_enabled:bool=True
    mirage_enabled:bool=True
    ouroboros_enabled:bool=False
    network_attack_enabled:bool=True
    synthetic_variant_enabled:bool=False
    output_dir:str="stage2_output"
    save_json_reports:bool=True
@dataclass
class Stage2Report:
    """
    Complete Stage 2 analysis report.

    Contains results from all enabled engines and a combined
    summary for the Stage L PDF report integration.
    """
    apk_hash:str=""
    family:str=""
    analysis_timestamp:float=0.0
    stage_m:Optional[StageMResult]=None
    stage_n:Optional[StageNResult]=None
    stage_o:Optional[StageOResult]=None
    stage_p:Optional[StagePResult]=None
    stage_q:Optional[StageQResult]=None
    stage_r:Optional[StageRResult]=None
    network_attack:Optional[NetworkAttackResult]=None
    confirmed_behaviors:list[str]=field(default_factory=list)
    collusion_paths_found:int=0
    builder_cluster_id:int=-1
    robustness_score:float=0.0
    highest_ddos_threat:str="NONE"
    nav_redirection:str=""
    adjusted_forecasts:list[MutationForecast]=field(default_factory=list)
    total_elapsed_ms:float=0.0
    def to_dict(self)->dict:
        """Serialise to dict for JSON output and Stage L/report integration."""
        network_summary=self.network_attack.to_dict()if self.network_attack else{}
        suricata_rules_count=int(network_summary.get("suricata_rules_count",0)or 0)
        stix_indicators_count=len(self.network_attack.stix_indicators)if self.network_attack else 0
        network_threat_count=int(network_summary.get("threat_count",0)or 0)
        max_amplification_factor=float(network_summary.get("max_amplification_factor",0.0)or 0.0)
        has_dga=bool(network_summary.get("has_dga",False))
        safety_mode="LAB_DYNAMIC_OPT_IN" if self.confirmed_behaviors else "SAFE_STATIC_DEFAULT"
        return{
            "apk_hash":self.apk_hash,
            "family":self.family,
            "analysis_timestamp":self.analysis_timestamp,
            "confirmed_behaviors":self.confirmed_behaviors,
            "collusion_paths_found":self.collusion_paths_found,
            "builder_cluster_id":self.builder_cluster_id,
            "robustness_score":round(self.robustness_score,4),
            "highest_ddos_threat":self.highest_ddos_threat,
            "highest_network_threat":self.highest_ddos_threat,
            "network_threat_count":network_threat_count,
            "max_amplification_factor":round(max_amplification_factor,1),
            "has_dga":has_dga,
            "suricata_rules_count":suricata_rules_count,
            "stix_indicators_count":stix_indicators_count,
            "safety_mode":safety_mode,
            "nav_redirection":self.nav_redirection,
            "total_elapsed_ms":round(self.total_elapsed_ms,2),
            "stage_results":{
                "M_PHANTOM":{
                    "skipped":self.stage_m.skipped if self.stage_m else True,
                    "behaviors":self.stage_m.behaviors_confirmed if self.stage_m else[],
                    "exfil_detected":self.stage_m.exfiltration_detected if self.stage_m else False,
                }if self.stage_m else None,
                "N_NAV":self.stage_n.nav_result.to_dict()if(
                    self.stage_n and self.stage_n.nav_result
                )else{"skipped":True},
                "O_CABAL":self.stage_o.cabal_result.to_dict()if(
                    self.stage_o and self.stage_o.cabal_result
                )else{"skipped":True},
                "P_KINSHIP":self.stage_p.primary_bdv.to_dict()if(
                    self.stage_p and self.stage_p.primary_bdv
                )else{"skipped":True},
                "Q_MIRAGE":self.stage_q.mirage_result.to_dict()if(
                    self.stage_q and self.stage_q.mirage_result
                )else{"skipped":True},
                "R_OUROBOROS":self.stage_r.ouroboros_result.to_dict()if(
                    self.stage_r and self.stage_r.ouroboros_result
                )else{"skipped":True},
                "NETWORK_ATTACK":network_summary if self.network_attack else None,
            },
            "adjusted_forecasts":[
                {
                    "technique":f.predicted_technique,
                    "confidence":round(f.confidence_score,4),
                    "passes_gate":f.passes_gate,
                }
                for f in self.adjusted_forecasts
            ],
        }
class Stage2Orchestrator:
    """
    ORACLE-TMF Stage 2 Orchestrator.

    Coordinates all Stage 2 engines around the Stage 1 pipeline output.
    Each engine failure is isolated â€” the report is always returned.

    Usage
    -----
    >>> from orchestrator_stage2 import Stage2Orchestrator, Stage2Config
    >>> cfg = Stage2Config(kinship_enabled=True, mirage_enabled=True)
    >>> orch = Stage2Orchestrator(cfg)
    >>> report = orch.run(mag, forecasts=forecasts)
    """
    def __init__(self,config:Optional[Stage2Config]=None)->None:
        self.config=config or Stage2Config()
        self._stage_m=StageMPhantomDetonation(enabled=self.config.phantom_enabled)
        self._stage_n=StageNNAVAnalysis()
        self._stage_o=StageOCABALAnalysis(use_llm=self.config.use_llm_for_cabal)
        self._stage_p=StagePKINSHIPFingerprint()
        self._stage_q=StageQMIRAGERobustness()
        self._stage_r=StageROuroborosCoevolution(enabled=self.config.ouroboros_enabled)
        self._net_analyzer=NetworkAttackAnalyzer()
        self._synth_gen:Optional[SyntheticVariantGenerator]=(
            SyntheticVariantGenerator()if self.config.synthetic_variant_enabled else None
        )
        self._nav_history:dict[str,NAVHistory]={}
        logger.info("[Stage2Orchestrator] Initialised with config: %s",{
            k:v for k,v in vars(self.config).items()
            if isinstance(v,bool)
        })
    def run(
        self,
        mag:MutationArtifactGraph,
        forecasts:Optional[list[MutationForecast]]=None,
        mag_prev:Optional[MutationArtifactGraph]=None,
        mag_list:Optional[list[MutationArtifactGraph]]=None,
        apk_path:str="",
        ground_truth_technique:Optional[str]=None,
        corpus_mags:Optional[list[MutationArtifactGraph]]=None,
    )->Stage2Report:
        """
        Run the full Stage 2 analysis pipeline.

        Parameters
        ----------
        mag : MutationArtifactGraph
            Primary APK MAG (Stages Aâ€“L already complete).
        forecasts : list[MutationForecast] | None
            Stage K output.  Will be adjusted by Stage N (NAV).
        mag_prev : MutationArtifactGraph | None
            Previous version MAG for NAV analysis.
        mag_list : list[MutationArtifactGraph] | None
            Multi-APK list for CABAL collusion analysis.
        apk_path : str
            Path to APK file (used by Stage M for PHANTOM session).
        ground_truth_technique : str | None
            Known mature technique label (for OUROBOROS).
        corpus_mags : list[MutationArtifactGraph] | None
            Attribution corpus for KINSHIP.

        Returns
        -------
        Stage2Report
        """
        t0=time.perf_counter()
        forecasts=forecasts or[]
        working_forecasts=list(forecasts)
        report=Stage2Report(
            apk_hash=mag.apk_metadata.sha256[:16]or "unknown",
            family=mag.malware_family or "unknown",
            analysis_timestamp=time.time(),
        )
        logger.info(
            "[Stage2Orchestrator] Starting Stage 2 for %s (family=%s)",
            report.apk_hash,report.family,
        )
        if self.config.phantom_enabled:
            logger.info("[Stage2Orchestrator] Running Stage M (PHANTOM)")
            try:
                report.stage_m=self._stage_m.run(
                    mag=mag,
                    forecasts=working_forecasts,
                    apk_path=apk_path,
                )
                if report.stage_m and not report.stage_m.skipped:
                    report.confirmed_behaviors=report.stage_m.behaviors_confirmed
                    for technique,boost in report.stage_m.confidence_boosts.items():
                        for f in working_forecasts:
                            if technique in f.predicted_technique:
                                f.confidence_score=min(1.0,f.confidence_score+boost)
            except Exception as exc:
                logger.error("[Stage2Orchestrator] Stage M failed: %s",exc)
        if self.config.nav_enabled:
            logger.info("[Stage2Orchestrator] Running Stage N (NAV)")
            try:
                report.stage_n=self._stage_n.run(
                    mag_curr=mag,
                    mag_prev=mag_prev,
                    forecasts=working_forecasts,
                    history_map=self._nav_history,
                    family=report.family,
                )
                if report.stage_n and report.stage_n.primary_redirection:
                    report.nav_redirection=report.stage_n.primary_redirection.value
            except Exception as exc:
                logger.error("[Stage2Orchestrator] Stage N failed: %s",exc)
        if self.config.cabal_enabled and mag_list and len(mag_list)>=2:
            logger.info("[Stage2Orchestrator] Running Stage O (CABAL)")
            try:
                report.stage_o=self._stage_o.run(mag_list)
                if report.stage_o and report.stage_o.cabal_result:
                    report.collusion_paths_found=len(
                        report.stage_o.cabal_result.high_confidence_paths
                    )
            except Exception as exc:
                logger.error("[Stage2Orchestrator] Stage O failed: %s",exc)
        if self.config.kinship_enabled:
            logger.info("[Stage2Orchestrator] Running Stage P (KINSHIP)")
            try:
                report.stage_p=self._stage_p.run(mag,corpus_mags=corpus_mags)
                if report.stage_p:
                    report.builder_cluster_id=report.stage_p.cluster_id
            except Exception as exc:
                logger.error("[Stage2Orchestrator] Stage P failed: %s",exc)
        if self.config.mirage_enabled:
            logger.info("[Stage2Orchestrator] Running Stage Q (MIRAGE)")
            try:
                report.stage_q=self._stage_q.run(mag,forecasts=working_forecasts)
                if report.stage_q:
                    report.robustness_score=report.stage_q.robustness_score
            except Exception as exc:
                logger.error("[Stage2Orchestrator] Stage Q failed: %s",exc)
        if self.config.ouroboros_enabled:
            logger.info("[Stage2Orchestrator] Running Stage R (OUROBOROS)")
            try:
                report.stage_r=self._stage_r.run(
                    mag=mag,
                    forecasts=working_forecasts,
                    ground_truth_technique=ground_truth_technique,
                    mature_corpus=corpus_mags,
                )
            except Exception as exc:
                logger.error("[Stage2Orchestrator] Stage R failed: %s",exc)
        if self.config.network_attack_enabled:
            logger.info("[Stage2Orchestrator] Running Network Attack Analyzer")
            try:
                report.network_attack=self._net_analyzer.analyze(mag)
                if report.network_attack:
                    report.highest_ddos_threat=report.network_attack.highest_threat_level
            except Exception as exc:
                logger.error("[Stage2Orchestrator] Network Attack analysis failed: %s",exc)
        for f in working_forecasts:
            f.passes_gate=f.confidence_score>=getattr(f,"gate_threshold",CONFIDENCE_GATE_THRESHOLD)
        report.adjusted_forecasts=working_forecasts
        report.total_elapsed_ms=round((time.perf_counter()-t0)*1000,2)
        if self.config.save_json_reports:
            self._save_report(report)
        logger.info(
            "[Stage2Orchestrator] Stage 2 complete: %s | elapsed=%.1f ms | "
            "behaviors=%d | ddos=%s | robustness=%.3f | nav=%s",
            report.apk_hash,
            report.total_elapsed_ms,
            len(report.confirmed_behaviors),
            report.highest_ddos_threat,
            report.robustness_score,
            report.nav_redirection or "none",
        )
        return report
    def _save_report(self,report:Stage2Report)->None:
        """Save the Stage 2 JSON report to disk."""
        try:
            out_dir=Path(self.config.output_dir)
            out_dir.mkdir(parents=True,exist_ok=True)
            out_path=out_dir/f"stage2_{report.apk_hash}_{int(report.analysis_timestamp)}.json"
            out_path.write_text(
                json.dumps(report.to_dict(),indent=2,default=str),
                encoding="utf-8",
            )
            logger.info("[Stage2Orchestrator] Report saved: %s",out_path)
        except Exception as exc:
            logger.warning("[Stage2Orchestrator] Failed to save report: %s",exc)
