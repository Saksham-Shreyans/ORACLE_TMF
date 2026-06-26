"""
ORACLE-TMF  ·  orchestrator.py
================================
Main Pipeline Orchestrator
Sequences all 12 pipeline stages and 5 engine modules for a single APK
analysis run.  Every stage is isolated: a failure in any stage is captured
in MAG.stage_errors and the pipeline continues with safe defaults.
Pipeline execution order:
  A → B → TMF-REFLECT → C → D → DTE → E → F → G → H
  → GenAI → UI → Targeting → I (optional) → J → K → L
Isolation guarantee:
  Each stage call is wrapped in _run_stage().  This method:
    • Records wall-clock timing in MAG.stage_timings_ms
    • Catches ALL exceptions and logs them to MAG.stage_errors
    • Returns a caller-specified default value on failure
    • Never re-raises exceptions to the caller
  Therefore, if Androguard is not installed, Stages B/D/E/G/H fail
  gracefully, but Stage J still runs (against an empty MAG) and
  Stage L still generates a partial report.
Usage
-----
  from orchestrator import ORACLETMFOrchestrator, AnalysisResult
  orch   = ORACLETMFOrchestrator()
  result = orch.analyze("/path/to/malware.apk")
  print(result.mag.to_json())
  print(result.report_bundle.pdf_path)
"""
from __future__ import annotations
import logging
import os
import tempfile
import time
from dataclasses import dataclass,field
from typing import Callable,Optional
from config.settings import LOG_FORMAT,LOG_LEVEL,WORK_DIR
from models.mutation_artifact_graph import MutationArtifactGraph
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

logging.basicConfig(format=LOG_FORMAT,level=getattr(logging,LOG_LEVEL,logging.INFO))
logger=logging.getLogger(__name__)
@dataclass
class AnalysisResult:
    """
    Returned by ORACLETMFOrchestrator.analyze().
    Contains the fully populated MAG and all generated report files.
    """
    mag:MutationArtifactGraph
    report_bundle:Optional[ReportBundle]=None
    success:bool=True
    total_time_ms:float=0.0
    error:str=""
class ORACLETMFOrchestrator:
    """
    ORACLE-TMF Main Pipeline Orchestrator.
    Initialises all stage and engine objects ONCE at construction time
    (some initialisation is expensive — e.g., DTE trains XGBoost, LLM
    engine loads ChromaDB).  Subsequent calls to analyze() reuse the
    same objects with no re-initialisation cost.
    Thread Safety:
      Not thread-safe.  For concurrent analysis, create one orchestrator
      instance per thread.
    Usage
    -----
    >>> orch   = ORACLETMFOrchestrator()
    >>> result = orch.analyze("malware.apk")
    >>> result = orch.analyze("malware_v2.apk", prev_apk_path="malware_v1.apk")
    """
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
        logger.info("[Orchestrator] All components initialised — ready to analyse")
    
    
    
    def analyze(
        self,
        apk_path:str,
        prev_apk_path:Optional[str]=None,
        progress_callback:Optional[Callable]=None,
        skip_llm:bool=False,
        skip_report:bool=False,
    )->AnalysisResult:
        """
        Run the full ORACLE-TMF 12-stage pipeline on an APK.
        Parameters
        ----------
        apk_path          : str  — absolute path to the target .apk
        prev_apk_path     : str  — optional path to the previous version .apk
                                   (enables Stage I version diff and MVV)
        progress_callback : callable(stage_name: str, pct: float) → None
                            Called after each stage with a 0.0-1.0 progress value.
        skip_llm          : bool — skip Stage J/K (no LLM API calls).
                                   Useful for fast static-only analysis.
        skip_report       : bool — skip Stage L (no file output).
                                   Useful for programmatic/test use.
        Returns
        -------
        AnalysisResult
        """
        pipeline_start=time.perf_counter()
        mag=MutationArtifactGraph()
        try:
            apk_path=os.path.abspath(apk_path)
            logger.info("[Orchestrator] ══ Analysis started: %s ══",apk_path)
            
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
                logger.warning("[Orchestrator] Stage A failed — using default metadata")
            
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
            
            report_bundle=None
            if not skip_report:
                self._progress(progress_callback,"STAGE_L",0.95)
                report_bundle=self._run_stage(
                    "STAGE_L",mag,
                    lambda:self._stage_l.run(mag),
                    default=None,
                )
            total_ms=(time.perf_counter()-pipeline_start)*1000
            self._progress(progress_callback,"COMPLETE",1.0)
            passed=len(mag.high_confidence_forecasts())
            logger.info(
                "[Orchestrator] ══ Analysis complete in %.1f s ══ "
                "artifacts=%d | forecasts_passed=%d | errors=%d",
                total_ms/1000,
                mag.total_artifact_count(),
                passed,
                len(mag.stage_errors),
            )
            return AnalysisResult(
                mag=mag,
                report_bundle=report_bundle,
                success=True,
                total_time_ms=total_ms,
            )
        except Exception as exc:
            total_ms=(time.perf_counter()-pipeline_start)*1000
            logger.critical("[Orchestrator] Unhandled pipeline error: %s",exc,exc_info=True)
            return AnalysisResult(
                mag=mag,
                report_bundle=None,
                success=False,
                total_time_ms=total_ms,
                error=str(exc),
            )
    
    
    
    def _build_static_mag(self,apk_path:str)->Optional[MutationArtifactGraph]:
        """
        Run only the static extraction stages (A-H) on an APK to build
        a baseline MAG for Stage I version diff.
        Does NOT run LLM, Bayesian scoring, or report generation —
        these are not needed for the diff baseline.
        """
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
        """
        Execute a pipeline stage with timing capture and full error isolation.
        On success → records timing, returns result.
        On failure → records error, returns default.
        NEVER propagates an exception.
        """
        t0=time.perf_counter()
        try:
            result=fn()
            mag.stage_timings_ms[stage_name]=round(
                (time.perf_counter()-t0)*1000,2
            )
            return result
        except Exception as exc:
            elapsed=(time.perf_counter()-t0)*1000
            mag.stage_errors[stage_name]=str(exc)
            mag.stage_timings_ms[stage_name]=round(elapsed,2)
            logger.error(
                "[Orchestrator] %s FAILED (%.0f ms): %s",
                stage_name,elapsed,exc,
            )
            return default
    
    
    
    @staticmethod
    def _apply_targeting_to_forecasts(
        mag:MutationArtifactGraph,targeting:dict
    )->None:
        """
        Enrich high-confidence forecasts with targeting intelligence:
          • Predicted target institution names
          • Predicted target country codes
        """
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
        """Invoke the progress callback if provided."""
        if callback:
            try:
                callback(stage,pct)
            except Exception:
                pass
    @staticmethod
    def _infer_family_from_package(package_name:str)->str:
        """
        Heuristically infer the malware family from a disguised package name.
        Real malware rarely uses its own brand — it masquerades as system apps.
        """
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
