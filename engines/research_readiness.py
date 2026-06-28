"""
ORACLE-TMF research readiness engine.

Converts Stage 1 MAG output and optional Stage 2 intelligence into a compact,
paper-friendly quality assessment. The engine is pure Python so it can run in
unit tests and API requests without Android analysis dependencies.
"""
from __future__ import annotations
from typing import Any,Optional
from models.mutation_artifact_graph import(
    MutationArtifactGraph,
    ResearchReadinessReport,
    Stage2IntelligenceSummary,
)
class ResearchReadinessEngine:
    """Score whether an analysis is strong enough for publication-style output."""
    ENGINE_NAME="RESEARCH_READINESS"
    def assess(
        self,
        mag:MutationArtifactGraph,
        stage2_report:Optional[Any]=None,
    )->ResearchReadinessReport:
        stage2_summary=self.summarize_stage2(stage2_report)
        if stage2_summary.available:
            mag.stage2_intelligence=stage2_summary
        elif mag.stage2_intelligence:
            stage2_summary=mag.stage2_intelligence
        else:
            mag.stage2_intelligence=stage2_summary
        counts=self._artifact_counts(mag)
        total_artifacts=sum(counts.values())
        active_classes=sum(1 for value in counts.values()if value>0)
        high_conf=len(mag.high_confidence_forecasts())
        evidence_strength=self._score_evidence_strength(
            active_classes=active_classes,
            total_artifacts=total_artifacts,
            high_confidence_forecasts=high_conf,
            has_version_delta=mag.version_delta is not None,
        )
        novelty=self._score_novelty(mag,stage2_summary)
        reproducibility=self._score_reproducibility(mag)
        stage2_score=self._score_stage2(stage2_summary)
        operational_risk=self._score_operational_risk(mag,stage2_summary)
        publication_score=self._clip(
            0.38*evidence_strength
            +0.22*novelty
            +0.22*reproducibility
            +0.18*stage2_score
        )
        report=ResearchReadinessReport(
            publication_readiness_score=round(publication_score,4),
            evidence_strength_score=round(evidence_strength,4),
            novelty_score=round(novelty,4),
            reproducibility_score=round(reproducibility,4),
            stage2_intelligence_score=round(stage2_score,4),
            operational_risk_score=round(operational_risk,4),
            risk_tier=self._risk_tier(operational_risk),
            paper_readiness=self._paper_readiness(publication_score),
            headline_claim=self._headline_claim(mag,stage2_summary,publication_score),
            evidence_matrix=self._evidence_matrix(mag,counts),
            methodology_cards=self._methodology_cards(mag,stage2_summary),
            key_findings=self._key_findings(mag,stage2_summary),
            limitations=self._limitations(mag,stage2_summary),
            recommended_next_steps=self._recommended_next_steps(mag,stage2_summary),
            reproducibility_checklist=self._reproducibility_checklist(mag,stage2_summary),
            suggested_figures=self._suggested_figures(mag,stage2_summary),
            dataset_card=self._dataset_card(mag,total_artifacts,active_classes),
        )
        mag.research_readiness=report
        return report
    @staticmethod
    def summarize_stage2(stage2_report:Optional[Any])->Stage2IntelligenceSummary:
        """Create the stable Stage 2 aggregate used by reports, API, and UI."""
        if stage2_report is None:
            return Stage2IntelligenceSummary(
                available=False,
                skipped_lab_stages=["M_PHANTOM","O_CABAL","R_OUROBOROS","SYNTHETIC_VARIANT"],
                intelligence_notes=["Stage 2 did not run for this analysis."],
            )
        if isinstance(stage2_report,Stage2IntelligenceSummary):
            return stage2_report
        network=getattr(stage2_report,"network_attack",None)
        network_dict=network.to_dict()if network and hasattr(network,"to_dict")else{}
        enabled_stages:list[str]=[]
        for attr,label in[
            ("stage_m","M_PHANTOM"),
            ("stage_n","N_NAV"),
            ("stage_o","O_CABAL"),
            ("stage_p","P_KINSHIP"),
            ("stage_q","Q_MIRAGE"),
            ("stage_r","R_OUROBOROS"),
        ]:
            if getattr(stage2_report,attr,None)is not None:
                enabled_stages.append(label)
        if network is not None:
            enabled_stages.append("NETWORK_ATTACK")
        confirmed=list(getattr(stage2_report,"confirmed_behaviors",[])or[])
        skipped_lab=[]
        stage_m=getattr(stage2_report,"stage_m",None)
        if stage_m is None or getattr(stage_m,"skipped",True):
            skipped_lab.append("M_PHANTOM")
        if getattr(stage2_report,"stage_o",None)is None:
            skipped_lab.append("O_CABAL")
        if getattr(stage2_report,"stage_r",None)is None:
            skipped_lab.append("R_OUROBOROS")
        skipped_lab.append("SYNTHETIC_VARIANT")
        notes:list[str]=[]
        nav=getattr(stage2_report,"nav_redirection","")or ""
        cluster=int(getattr(stage2_report,"builder_cluster_id",-1)or-1)
        threat=getattr(stage2_report,"highest_ddos_threat","NONE")or "NONE"
        robustness=float(getattr(stage2_report,"robustness_score",0.0)or 0.0)
        if nav:
            notes.append(f"NAV redirection observed:{nav}.")
        if cluster!=-1:
            notes.append(f"KINSHIP builder cluster:{cluster}.")
        if robustness:
            notes.append(f"MIRAGE robustness score:{robustness:.2f}.")
        if threat!="NONE":
            notes.append(f"Network attack threat level:{threat}.")
        if confirmed:
            notes.append(f"PHANTOM confirmed{len(confirmed)}behavior(s).")
        if not notes:
            notes.append("Stage 2 ran but produced low-signal aggregate findings.")
        safety_mode="LAB_DYNAMIC_OPT_IN" if confirmed else "SAFE_STATIC_DEFAULT"
        return Stage2IntelligenceSummary(
            available=True,
            enabled_stages=enabled_stages,
            skipped_lab_stages=skipped_lab,
            nav_redirection=nav,
            builder_cluster_id=cluster,
            robustness_score=self_clip(robustness),
            highest_network_threat=threat,
            network_threat_count=int(network_dict.get("threat_count",0)or 0),
            max_amplification_factor=float(network_dict.get("max_amplification_factor",0.0)or 0.0),
            has_dga=bool(network_dict.get("has_dga",False)),
            suricata_rules_count=int(network_dict.get("suricata_rules_count",0)or 0),
            stix_indicators_count=len(getattr(network,"stix_indicators",[])or[]),
            confirmed_behaviors=confirmed,
            collusion_paths_found=int(getattr(stage2_report,"collusion_paths_found",0)or 0),
            adjusted_forecasts_count=len(getattr(stage2_report,"adjusted_forecasts",[])or[]),
            total_elapsed_ms=float(getattr(stage2_report,"total_elapsed_ms",0.0)or 0.0),
            safety_mode=safety_mode,
            intelligence_notes=notes,
        )
    @staticmethod
    def _artifact_counts(mag:MutationArtifactGraph)->dict[str,int]:
        return{
            "dead_code":len(getattr(mag,"dead_code",[])),
            "unused_permissions":len(getattr(mag,"unused_permissions",[])),
            "placeholder_strings":len(getattr(mag,"placeholder_strings",[])),
            "c2_stubs":len(getattr(mag,"c2_stubs",[])),
            "partial_apis":len(getattr(mag,"partial_apis",[])),
            "unfinished_ui_flows":len(getattr(mag,"unfinished_ui_flows",[])),
            "genai_scaffolds":len(getattr(mag,"genai_scaffolds",[])),
        }
    def _score_evidence_strength(
        self,
        active_classes:int,
        total_artifacts:int,
        high_confidence_forecasts:int,
        has_version_delta:bool,
    )->float:
        score=0.12
        score+=min(active_classes,5)*0.12
        score+=min(total_artifacts/30.0,1.0)*0.18
        score+=min(high_confidence_forecasts,2)*0.10
        if has_version_delta:
            score+=0.10
        return self._clip(score)
    def _score_novelty(self,mag:MutationArtifactGraph,stage2:Stage2IntelligenceSummary)->float:
        score=0.20
        if getattr(mag,"genai_scaffolds",[]):
            score+=0.22
        if getattr(mag,"unfinished_ui_flows",[]):
            score+=0.10
        if getattr(mag,"version_delta",None):
            score+=0.12
        if stage2.available:
            if stage2.builder_cluster_id!=-1:
                score+=0.10
            if stage2.nav_redirection:
                score+=0.10
            if stage2.highest_network_threat!="NONE":
                score+=0.16
            if stage2.has_dga:
                score+=0.06
        return self._clip(score)
    def _score_reproducibility(self,mag:MutationArtifactGraph)->float:
        expected_static=["STAGE_A","STAGE_C","STAGE_F","TARGETING","STAGE_I"]
        timings=getattr(mag,"stage_timings_ms",{})
        completed=sum(1 for stage in expected_static if stage in timings)
        score=0.30+(completed/len(expected_static))*0.40
        if not getattr(mag,"stage_errors",{}):
            score+=0.18
        if getattr(mag.apk_metadata,"sha256",""):
            score+=0.07
        if getattr(mag.apk_metadata,"package_name",""):
            score+=0.05
        return self._clip(score)
    def _score_stage2(self,stage2:Stage2IntelligenceSummary)->float:
        if not stage2.available:
            return 0.0
        score=0.18
        if stage2.nav_redirection:
            score+=0.16
        if stage2.builder_cluster_id!=-1:
            score+=0.14
        score+=min(stage2.robustness_score,1.0)*0.22
        if stage2.highest_network_threat!="NONE":
            score+=0.16
        if stage2.confirmed_behaviors:
            score+=0.14
        return self._clip(score)
    def _score_operational_risk(self,mag:MutationArtifactGraph,stage2:Stage2IntelligenceSummary)->float:
        score=0.08
        score+=min(len(getattr(mag,"dead_code",[]))/12.0,1.0)*0.14
        score+=min(len(getattr(mag,"c2_stubs",[]))/4.0,1.0)*0.20
        score+=min(len(getattr(mag,"genai_scaffolds",[]))/2.0,1.0)*0.18
        score+=min(len(mag.high_confidence_forecasts())/2.0,1.0)*0.18
        if stage2.available:
            threat_weight={"CRITICAL":0.22,"HIGH":0.17,"MEDIUM":0.10,"LOW":0.05}
            score+=threat_weight.get(stage2.highest_network_threat,0.0)
            if stage2.confirmed_behaviors:
                score+=0.12
        return self._clip(score)
    @staticmethod
    def _risk_tier(score:float)->str:
        if score>=0.82:
            return "CRITICAL"
        if score>=0.62:
            return "HIGH"
        if score>=0.38:
            return "MEDIUM"
        return "LOW"
    @staticmethod
    def _paper_readiness(score:float)->str:
        if score>=0.78:
            return "PAPER_READY"
        if score>=0.60:
            return "WORKSHOP_READY"
        if score>=0.42:
            return "CASE_STUDY_READY"
        return "INSUFFICIENT"
    def _headline_claim(
        self,
        mag:MutationArtifactGraph,
        stage2:Stage2IntelligenceSummary,
        score:float,
    )->str:
        family=mag.malware_family or mag.apk_metadata.package_name or "the analyzed APK"
        forecasts=mag.high_confidence_forecasts()
        if forecasts:
            top=forecasts[0]
            return(
                f"{family}contains convergent mutation artifacts forecasting "
                f"{top.predicted_technique or 'a next-version capability'}"
                f"with publication readiness{score:.2f}."
            )
        if stage2.available and stage2.highest_network_threat!="NONE":
            return(
                f"{family}shows Stage 2 network-attack evidence with "
                f"{stage2.highest_network_threat.lower()}operational risk."
            )
        return f"{family}produced a reproducible mutation-artifact case study with readiness{score:.2f}."
    def _evidence_matrix(self,mag:MutationArtifactGraph,counts:dict[str,int])->list[dict]:
        rows=[
            ("CLASS_1_DEAD_CODE","Dormant implementation code",counts["dead_code"],"Stage D + DTE"),
            ("CLASS_2_UNUSED_PERMISSION","Pre-positioned Android permissions",counts["unused_permissions"],"Stage E"),
            ("CLASS_3_PLACEHOLDER_STRING","Staging strings and future feature markers",counts["placeholder_strings"],"Stage F"),
            ("CLASS_4_C2_ENDPOINT_STUB","Inactive command-and-control plumbing",counts["c2_stubs"],"Stage G"),
            ("CLASS_5_PARTIAL_API","Incomplete sensitive framework APIs",counts["partial_apis"],"Stage H"),
            ("CLASS_6_UNFINISHED_UI","Dormant UI or phishing flow assets",counts["unfinished_ui_flows"],"UI Detector"),
            ("CLASS_7_GENAI_SCAFFOLD","LLM or GenAI augmentation scaffolds",counts["genai_scaffolds"],"GenAI Detector"),
        ]
        return[
            {
                "artifact_class":artifact_class,
                "count":count,
                "stage":stage,
                "interpretation":interpretation,
                "strength":self._row_strength(count),
            }
            for artifact_class,interpretation,count,stage in rows
        ]
    @staticmethod
    def _row_strength(count:int)->str:
        if count>=5:
            return "STRONG"
        if count>=2:
            return "MODERATE"
        if count==1:
            return "WEAK"
        return "ABSENT"
    def _methodology_cards(self,mag:MutationArtifactGraph,stage2:Stage2IntelligenceSummary)->list[dict]:
        return[
            {
                "method":"Stage 1 static mutation artifact extraction",
                "purpose":"Recover dormant, partial, and staging features from APK structure and bytecode.",
                "status":"complete" if mag.total_artifact_count()else "low_signal",
            },
            {
                "method":"Bayesian mutation forecasting",
                "purpose":"Fuse LLM hypothesis, artifact density, version velocity, and historical prior.",
                "status":"complete" if getattr(mag,"forecasts",[])else "not_available",
            },
            {
                "method":"Stage 2 intelligence fusion",
                "purpose":"Combine NAV, KINSHIP, MIRAGE, PHANTOM, CABAL, and network attack findings.",
                "status":"complete" if stage2.available else "not_run",
            },
        ]
    def _key_findings(self,mag:MutationArtifactGraph,stage2:Stage2IntelligenceSummary)->list[str]:
        findings:list[str]=[]
        if mag.total_artifact_count():
            active=sum(1 for row in self._artifact_counts(mag).values()if row)
            findings.append(f"Detected{mag.total_artifact_count()}mutation artifacts across{active}active classes.")
        for forecast in mag.high_confidence_forecasts()[:2]:
            findings.append(
                f"High-confidence forecast:{forecast.predicted_technique}"
                f"({forecast.technique_name or 'unnamed technique'})at C={forecast.confidence_score:.3f}."
            )
        if stage2.available:
            if stage2.nav_redirection:
                findings.append(f"NAV evolutionary redirection:{stage2.nav_redirection}.")
            if stage2.builder_cluster_id!=-1:
                findings.append(f"KINSHIP attributed the sample to builder cluster{stage2.builder_cluster_id}.")
            if stage2.highest_network_threat!="NONE":
                findings.append(f"Network attack analyzer reports{stage2.highest_network_threat}threat level.")
            if stage2.suricata_rules_count:
                findings.append(f"Generated{stage2.suricata_rules_count}network detection rule(s)for defenders.")
        if not findings:
            findings.append("No strong mutation evidence was detected; retain as a negative-control sample.")
        return findings
    @staticmethod
    def _limitations(mag:MutationArtifactGraph,stage2:Stage2IntelligenceSummary)->list[str]:
        limitations:list[str]=[]
        if not getattr(mag,"version_delta",None):
            limitations.append("No previous APK was supplied, so MVV is neutral rather than measured.")
        if not getattr(mag,"forecasts",[]):
            limitations.append("Stage J/K forecasts are unavailable; paper claims should avoid next-version assertions.")
        if not stage2.available:
            limitations.append("Stage 2 intelligence was not run or did not return a report.")
        if getattr(mag,"stage_errors",{}):
            limitations.append("Some stages failed; diagnostics must be reported with the result.")
        if not limitations:
            limitations.append("Static analysis cannot prove runtime activation without controlled detonation.")
        return limitations
    @staticmethod
    def _recommended_next_steps(mag:MutationArtifactGraph,stage2:Stage2IntelligenceSummary)->list[str]:
        steps:list[str]=[]
        if not getattr(mag,"version_delta",None):
            steps.append("Upload a previous APK version to strengthen temporal mutation claims.")
        if not getattr(mag,"forecasts",[]):
            steps.append("Run Stage J/K with LLM enabled to generate Bayesian forecasts.")
        if not stage2.available:
            steps.append("Enable safe Stage 2 NAV, KINSHIP, MIRAGE, and Network Attack analysis for publication evidence.")
        elif not stage2.confirmed_behaviors:
            steps.append("Use PHANTOM only in an isolated lab if runtime confirmation is required.")
        steps.append("Export the Markdown paper draft and convert figures from the JSON evidence matrix.")
        return steps
    @staticmethod
    def _reproducibility_checklist(mag:MutationArtifactGraph,stage2:Stage2IntelligenceSummary)->list[dict]:
        return[
            {"item":"APK SHA-256 recorded","passed":bool(getattr(mag.apk_metadata,"sha256",""))},
            {"item":"Package metadata recorded","passed":bool(getattr(mag.apk_metadata,"package_name",""))},
            {"item":"Per-stage timings recorded","passed":bool(getattr(mag,"stage_timings_ms",{}))},
            {"item":"Stage errors disclosed","passed":True},
            {"item":"Version delta available","passed":getattr(mag,"version_delta",None)is not None},
            {"item":"Stage 2 summary available","passed":stage2.available},
        ]
    @staticmethod
    def _suggested_figures(mag:MutationArtifactGraph,stage2:Stage2IntelligenceSummary)->list[str]:
        figures=[
            "Figure 1: Seven-class mutation artifact inventory.",
            "Figure 2: Bayesian confidence decomposition for top forecasts.",
        ]
        if getattr(mag,"version_delta",None):
            figures.append("Figure 3: Mutation velocity vector from prior APK to current APK.")
        if stage2.available:
            figures.append("Figure 4: Stage 2 intelligence fusion panel.")
        return figures
    @staticmethod
    def _dataset_card(mag:MutationArtifactGraph,total_artifacts:int,active_classes:int)->dict:
        return{
            "sample_sha256":getattr(mag.apk_metadata,"sha256",""),
            "package_name":getattr(mag.apk_metadata,"package_name",""),
            "family":getattr(mag,"malware_family","")or "unknown",
            "version_name":getattr(mag.apk_metadata,"version_name",""),
            "version_code":getattr(mag.apk_metadata,"version_code",0),
            "file_size_bytes":getattr(mag.apk_metadata,"file_size_bytes",0),
            "total_artifacts":total_artifacts,
            "active_artifact_classes":active_classes,
            "forecasts_generated":len(getattr(mag,"forecasts",[])),
        }
    @staticmethod
    def _clip(value:float)->float:
        return self_clip(value)
def self_clip(value:float)->float:
    return max(0.0,min(1.0,float(value)))
