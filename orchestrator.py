from __future__ import annotations
import logging
import os
import tempfile
import time
from dataclasses import dataclass,field
from typing import Callable,Optional
from config.settings import LOG_FORMAT,LOG_LEVEL,WORK_DIR
from models.mutation_artifact_graph import MutationArtifactGraph
from security import clean_text
from pipeline.stage_a_ingestion import APKIngestion
from pipeline.stage_b_dex_disassembly import DEXDisassembler
from pipeline.stage_c_manifest_parser import ManifestParser
from pipeline.stage_d_dead_code import DeadCodeDetector
from pipeline.stage_e_unused_perms import UnusedPermissionAnalyzer
from pipeline.stage_f_string_mining import StringMiner
from pipeline.stage_g_c2_stubs import C2StubDetector
from pipeline.stage_h_partial_apis import PartialAPIDetector
from pipeline.stage_i_version_diff import VersionDiffEngine
from pipeline.stage_j_llm_reasoning import LLMReasoningEngine
from pipeline.stage_k_bayesian_scorer import BayesianScorer
from pipeline.stage_l_report_synthesizer import ReportSynthesizer,ReportBundle
from engines.dte_engine import DTEEngine
from engines.tmf_reflect import TMFReflect
from engines.genai_scaffold_detector import GenAIScaffoldDetector
from engines.unfinished_ui_detector import UnfinishedUIDetector
from engines.targeting_intelligence import TargetingIntelligence
from engines.research_readiness import ResearchReadinessEngine
from orchestrator_stage2 import Stage2Orchestrator,Stage2Config,Stage2Report
logging.basicConfig(format=LOG_FORMAT,level=getattr(logging,LOG_LEVEL,logging.INFO))
os.makedirs(WORK_DIR,exist_ok=True)
error_log_path=os.path.join(WORK_DIR,"errors.log")
error_file_handler=logging.FileHandler(error_log_path)
error_file_handler.setLevel(logging.ERROR)
error_file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logging.getLogger().addHandler(error_file_handler)
logger=logging.getLogger(__name__)
@dataclass
class AnalysisResult:
    mag:MutationArtifactGraph
    report_bundle:Optional[ReportBundle]=None
    stage2_report:Optional[Stage2Report]=None
    success:bool=True
    total_time_ms:float=0.0
    error:str=""
class ORACLETMFOrchestrator:
    def __init__(self)->None:
        logger.info("[Orchestrator] Initialising ORACLE-TMF pipeline components")
        os.makedirs(WORK_DIR,exist_ok=True)
        self._stage_a=APKIngestion()
        self._stage_b=DEXDisassembler()
        self._stage_c=ManifestParser()
        self._stage_d=DeadCodeDetector()
        self._stage_e=UnusedPermissionAnalyzer()
        self._stage_f=StringMiner()
        self._stage_g=C2StubDetector()
        self._stage_h=PartialAPIDetector()
        self._stage_i=VersionDiffEngine()
        self._stage_j=LLMReasoningEngine()
        self._stage_k=BayesianScorer()
        self._stage_l=ReportSynthesizer()
        self._dte=DTEEngine()
        self._reflect=TMFReflect()
        self._genai=GenAIScaffoldDetector()
        self._ui_det=UnfinishedUIDetector()
        self._targeting=TargetingIntelligence()
        self._research=ResearchReadinessEngine()
        self._stage2_orch=Stage2Orchestrator()
        logger.info("[Orchestrator] All components initialised â€” ready to analyse")
    def analyze(
        self,
        apk_path:str,
        prev_apk_path:Optional[str]=None,
        progress_callback:Optional[Callable]=None,
        skip_llm:bool=False,
        skip_report:bool=False,
        stage2_config:Optional[Stage2Config]=None,
    )->AnalysisResult:
        pipeline_start=time.perf_counter()
        mag=MutationArtifactGraph()
        try:
            apk_path=os.path.abspath(apk_path)
            logger.info("[Orchestrator] â•â• Analysis started: %s â•â•",apk_path)
            self._progress(progress_callback,"STAGE_A",0.04)
            result_a=self._run_stage(
                "STAGE_A",mag,
                lambda:self._stage_a.run(apk_path),
                default=(None,""),
            )
            extract_dir=""
            if result_a and result_a[0]:
                mag.apk_metadata,extract_dir=result_a
            else:
                logger.warning("[Orchestrator] Stage A failed â€” using default metadata")
            self._progress(progress_callback,"STAGE_B",0.10)
            result_b=self._run_stage(
                "STAGE_B",mag,
                lambda:self._stage_b.run(apk_path),
                default=(None,None),
            )
            analysis=cfg=None
            if result_b:
                analysis,cfg=result_b
            if analysis and cfg:
                self._progress(progress_callback,"TMF_REFLECT",0.14)
                self._run_stage(
                    "TMF_REFLECT",mag,
                    lambda:self._reflect.augment_cfg(analysis,cfg),
                    default=cfg,
                )
            self._progress(progress_callback,"STAGE_C",0.18)
            manifest=self._run_stage(
                "STAGE_C",mag,
                lambda:self._stage_c.run(apk_path),
                default={},
            )or{}
            mag.manifest=manifest
            if not mag.malware_family:
                mag.malware_family=self._infer_family_from_package(
                    manifest.get("package_name",mag.apk_metadata.package_name or "")
                )
            raw_dead=[]
            if analysis and cfg:
                self._progress(progress_callback,"STAGE_D",0.24)
                raw_dead=self._run_stage(
                    "STAGE_D",mag,
                    lambda:self._stage_d.run(analysis,cfg,manifest),
                    default=[],
                )or[]
                self._progress(progress_callback,"DTE",0.30)
                mag.dead_code=self._run_stage(
                    "DTE",mag,
                    lambda:self._dte.classify(raw_dead),
                    default=raw_dead,
                )or raw_dead
            else:
                mag.dead_code=[]
            if analysis and manifest:
                self._progress(progress_callback,"STAGE_E",0.36)
                mag.unused_permissions=self._run_stage(
                    "STAGE_E",mag,
                    lambda:self._stage_e.run(manifest,analysis),
                    default=[],
                )or[]
            if analysis:
                self._progress(progress_callback,"STAGE_F",0.42)
                mag.placeholder_strings=self._run_stage(
                    "STAGE_F",mag,
                    lambda:self._stage_f.run(apk_path,extract_dir,analysis),
                    default=[],
                )or[]
            if analysis:
                self._progress(progress_callback,"STAGE_G",0.47)
                mag.c2_stubs=self._run_stage(
                    "STAGE_G",mag,
                    lambda:self._stage_g.run(mag.dead_code,analysis),
                    default=[],
                )or[]
            if analysis:
                self._progress(progress_callback,"STAGE_H",0.52)
                mag.partial_apis=self._run_stage(
                    "STAGE_H",mag,
                    lambda:self._stage_h.run(analysis),
                    default=[],
                )or[]
            if analysis:
                self._progress(progress_callback,"GENAI_DETECT",0.56)
                mag.genai_scaffolds=self._run_stage(
                    "GENAI_DETECT",mag,
                    lambda:self._genai.run(analysis,mag.dead_code),
                    default=[],
                )or[]
            self._progress(progress_callback,"UI_DETECT",0.59)
            mag.unfinished_ui_flows=self._run_stage(
                "UI_DETECT",mag,
                lambda:self._ui_det.run(apk_path,extract_dir,analysis),
                default=[],
            )or[]
            self._progress(progress_callback,"TARGETING",0.62)
            targeting=self._run_stage(
                "TARGETING",mag,
                lambda:self._targeting.run(mag,extract_dir,analysis),
                default={},
            )or{}
            if targeting.get("family_hint")and not mag.malware_family:
                mag.malware_family=targeting["family_hint"]
            mag.manifest["_targeting"]=targeting
            self._progress(progress_callback,"STAGE_I",0.66)
            if prev_apk_path and os.path.isfile(prev_apk_path):
                prev_mag=self._build_static_mag(prev_apk_path)
                mag.version_delta=self._run_stage(
                    "STAGE_I",mag,
                    lambda:self._stage_i.run(mag,prev_mag),
                    default=None,
                )
            else:
                mag.version_delta=self._run_stage(
                    "STAGE_I",mag,
                    lambda:self._stage_i.run(mag,None),
                    default=None,
                )
            if not skip_llm:
                self._progress(progress_callback,"STAGE_J",0.75)
                forecasts=self._run_stage(
                    "STAGE_J",mag,
                    lambda:self._stage_j.run(mag),
                    default=[],
                )or[]
                mag.forecasts=forecasts
                self._progress(progress_callback,"STAGE_K",0.88)
                rag=getattr(self._stage_j,"_rag",None)
                mag.forecasts=self._run_stage(
                    "STAGE_K",mag,
                    lambda:self._stage_k.run(mag.forecasts,mag,rag),
                    default=mag.forecasts,
                )or mag.forecasts
                self._apply_targeting_to_forecasts(mag,targeting)
            self._progress(progress_callback,"STAGE_2",0.92)
            stage2_report=None
            if stage2_config is not None:
                self._stage2_orch = Stage2Orchestrator()
                self._stage2_orch.config=stage2_config
                prev_mag=self._build_static_mag(prev_apk_path)if prev_apk_path and os.path.isfile(prev_apk_path)else None
                stage2_report=self._run_stage(
                    "STAGE_2",mag,
                    lambda:self._stage2_orch.run(mag,forecasts=mag.forecasts,mag_prev=prev_mag,apk_path=apk_path),
                    default=None
                )
            self._progress(progress_callback,"RESEARCH_READINESS",0.94)
            self._run_stage(
                "RESEARCH_READINESS",mag,
                lambda:self._research.assess(mag,stage2_report=stage2_report),
                default=None
            )
            report_bundle=None
            if not skip_report:
                self._progress(progress_callback,"STAGE_L",0.96)
                report_bundle=self._run_stage(
                    "STAGE_L",mag,
                    lambda:self._stage_l.run(mag,stage2_report=stage2_report),
                    default=None,
                )
            total_ms=(time.perf_counter()-pipeline_start)*1000
            self._progress(progress_callback,"COMPLETE",1.0)
            passed=len(mag.high_confidence_forecasts())
            logger.info(
                "[Orchestrator] â•â• Analysis complete in %.1f s â•â• "
                "artifacts=%d | forecasts_passed=%d | errors=%d",
                total_ms/1000,
                mag.total_artifact_count(),
                passed,
                len(mag.stage_errors),
            )
            return AnalysisResult(
                mag=mag,
                report_bundle=report_bundle,
                stage2_report=stage2_report,
                success=True,
                total_time_ms=total_ms,
            )
        except Exception as exc:
            total_ms=(time.perf_counter()-pipeline_start)*1000
            logger.critical("[Orchestrator] Unhandled pipeline error: %s",exc,exc_info=True)
            return AnalysisResult(
                mag=mag,
                report_bundle=None,
                stage2_report=None,
                success=False,
                total_time_ms=total_ms,
                error=str(exc),
            )
    def _build_static_mag(self,apk_path:str)->Optional[MutationArtifactGraph]:
        mag=MutationArtifactGraph()
        try:
            result_a=self._run_stage("PREV_A",mag,lambda:self._stage_a.run(apk_path),(None,""))
            if result_a and result_a[0]:
                mag.apk_metadata,extract_dir=result_a
            else:
                extract_dir=""
            result_b=self._run_stage("PREV_B",mag,lambda:self._stage_b.run(apk_path),(None,None))
            analysis=cfg=None
            if result_b:
                analysis,cfg=result_b
            if analysis and cfg:
                self._reflect.augment_cfg(analysis,cfg)
            manifest=self._run_stage("PREV_C",mag,lambda:self._stage_c.run(apk_path),{})or{}
            mag.manifest=manifest
            if analysis and cfg:
                raw_dead=self._run_stage("PREV_D",mag,lambda:self._stage_d.run(analysis,cfg,manifest),[])or[]
                mag.dead_code=self._run_stage("PREV_DTE",mag,lambda:self._dte.classify(raw_dead),raw_dead)or raw_dead
                mag.unused_permissions=self._run_stage("PREV_E",mag,lambda:self._stage_e.run(manifest,analysis),[])or[]
                mag.placeholder_strings=self._run_stage("PREV_F",mag,lambda:self._stage_f.run(apk_path,extract_dir,analysis),[])or[]
                mag.c2_stubs=self._run_stage("PREV_G",mag,lambda:self._stage_g.run(mag.dead_code,analysis),[])or[]
                mag.partial_apis=self._run_stage("PREV_H",mag,lambda:self._stage_h.run(analysis),[])or[]
        except Exception as exc:
            logger.warning("[Orchestrator] Static MAG build failed for prev APK: %s",exc)
        return mag
    def _run_stage(self,stage_name:str,mag:MutationArtifactGraph,fn,default=None):
        t0=time.perf_counter()
        try:
            result=fn()
            mag.stage_timings_ms[stage_name]=round(
                (time.perf_counter()-t0)*1000,2
            )
            return result
        except Exception as exc:
            elapsed=(time.perf_counter()-t0)*1000
            mag.stage_errors[stage_name]=clean_text(str(exc),500)
            mag.stage_timings_ms[stage_name]=round(elapsed,2)
            logger.error(
                "[Orchestrator] %s FAILED (%.0f ms): %s",
                stage_name,elapsed,clean_text(str(exc),500),
            )
            return default
    @staticmethod
    def _apply_targeting_to_forecasts(
        mag:MutationArtifactGraph,targeting:dict
    )->None:
        if not targeting:
            return
        targets=targeting.get("predicted_targets",[])
        countries=targeting.get("geographic_expansion",[])
        for forecast in mag.forecasts:
            if not forecast.passes_gate:
                continue
            if not forecast.predicted_target_institutions and targets:
                forecast.predicted_target_institutions=[
                    t["institution_name"]for t in targets[:3]
                ]
            if not forecast.predicted_target_countries and countries:
                forecast.predicted_target_countries=countries[:5]
    @staticmethod
    def _progress(
        callback:Optional[Callable],stage:str,pct:float
    )->None:
        if callback:
            try:
                callback(stage,pct)
            except Exception:
                pass
    @staticmethod
    def _infer_family_from_package(package_name:str)->str:
        if not package_name:
            return ""
        pkg=package_name.lower()
        hints={
            "flubot":["com.tencent.mm","delivery","dhl","fedex"],
            "spynote":["com.android.system","system.manager","mobile.manager"],
            "godfather":["com.google.service","android.update"],
            "cerberus":["cia.service","system.service"],
            "toxicpanda":["payment.app","bank.mobile"],
        }
        for family,patterns in hints.items():
            if any(p in pkg for p in patterns):
                return family.title()
        return ""
