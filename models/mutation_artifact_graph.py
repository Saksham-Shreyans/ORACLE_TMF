"""
ORACLE-TMF - models/mutation_artifact_graph.py
==============================================
The Mutation Artifact Graph (MAG) is the canonical JSON-serialisable data
structure passed between pipeline stages.
"""
from __future__ import annotations
import json
from dataclasses import asdict,dataclass,field
from enum import Enum
from typing import Optional
class ArtifactClass(str,Enum):
    """The 7-class mutation artifact taxonomy."""
    DEAD_CODE="CLASS_1_DEAD_CODE"
    UNUSED_PERMISSION="CLASS_2_UNUSED_PERMISSION"
    PLACEHOLDER_STRING="CLASS_3_PLACEHOLDER_STRING"
    C2_ENDPOINT_STUB="CLASS_4_C2_ENDPOINT_STUB"
    PARTIAL_API="CLASS_5_PARTIAL_API"
    UNFINISHED_UI_FLOW="CLASS_6_UNFINISHED_UI"
    GENAI_API_SCAFFOLD="CLASS_7_GENAI_SCAFFOLD"
class DTEClass(str,Enum):
    """Dormancy Taxonomy Engine output labels."""
    REMNANT="REMNANT"
    SCAFFOLDING="SCAFFOLDING"
    LOGIC_BOMB="LOGIC_BOMB"
    ENCRYPTED_DROPPER="ENCRYPTED_DROPPER"
class MITREMobileTactic(str,Enum):
    """MITRE ATT&CK for Mobile top-level tactic identifiers."""
    INITIAL_ACCESS="TA0027"
    EXECUTION="TA0041"
    PERSISTENCE="TA0028"
    PRIVILEGE_ESCALATION="TA0029"
    DEFENSE_EVASION="TA0030"
    CREDENTIAL_ACCESS="TA0031"
    DISCOVERY="TA0032"
    LATERAL_MOVEMENT="TA0033"
    COLLECTION="TA0035"
    COMMAND_AND_CONTROL="TA0011"
    EXFILTRATION="TA0036"
    IMPACT="TA0034"
@dataclass
class DeadCodeArtifact:
    """CLASS 1 - Dead Code / Unreachable Methods."""
    class_name:str
    method_name:str
    smali_code:str
    opcode_count:int
    dte_label:DTEClass=DTEClass.SCAFFOLDING
    dte_confidence:float=0.0
    pseudo_java:str=""
    trigger_depth:int=0
    guard_entropy:float=0.0
    api_sensitivity:float=0.0
    guard_indegree:int=0
@dataclass
class UnusedPermissionArtifact:
    """CLASS 2 - Unused Permission Intents."""
    permission_name:str
    android_permission_group:str=""
    expected_apis:list[str]=field(default_factory=list)
    context_note:str=""
@dataclass
class PlaceholderStringArtifact:
    """CLASS 3 - Placeholder Strings and Resources."""
    value:str
    source:str
    entropy:float=0.0
    matched_pattern:str=""
    key_name:str=""
@dataclass
class C2EndpointStubArtifact:
    """CLASS 4 - C2 Endpoint Stubs."""
    class_name:str
    method_name:str
    framework:str
    extracted_url:str=""
    http_method:str=""
    payload_schema:str=""
@dataclass
class PartialAPIArtifact:
    """CLASS 5 - Partial sensitive framework API implementations."""
    class_name:str
    interface_extended:str
    method_stubs:list[str]=field(default_factory=list)
    opcode_counts:dict[str,int]=field(default_factory=dict)
@dataclass
class UnfinishedUIFlowArtifact:
    """CLASS 6 - Unfinished UI flows."""
    layout_file:str
    layout_id:str=""
    suspected_type:str=""
    asset_refs:list[str]=field(default_factory=list)
@dataclass
class GenAIAPIScaffoldArtifact:
    """CLASS 7 - GenAI API scaffolds."""
    class_name:str
    method_name:str
    provider:str=""
    api_endpoint:str=""
    model_hint:str=""
@dataclass
class VersionDelta:
    """Output of Stage I version diff and Mutation Velocity Vector scoring."""
    artifacts_added:list[dict]=field(default_factory=list)
    artifacts_removed:list[dict]=field(default_factory=list)
    edit_distance:float=0.0
    mvv_raw:float=1.0
    mvv_normalized:float=1.0
@dataclass
class MutationForecast:
    """A single mutation forecast prediction with Bayesian confidence scoring."""
    predicted_tactic:str=""
    predicted_technique:str=""
    technique_name:str=""
    rationale:str=""
    p_llm:float=0.0
    artifact_density:float=0.0
    mvv_normalized:float=1.0
    h_prior:float=0.0
    confidence_score:float=0.0
    passes_gate:bool=False
    supporting_artifacts:list[str]=field(default_factory=list)
    predicted_target_institutions:list[str]=field(default_factory=list)
    predicted_target_countries:list[str]=field(default_factory=list)
@dataclass
class Stage2IntelligenceSummary:
    """
    Compact Stage 2 aggregate for JSON, API, Streamlit, and paper drafts.

    The full Stage2Report can be large and stage-specific. This summary keeps
    the stable high-value fields consumers need without coupling them to every
    research engine implementation detail.
    """
    available:bool=False
    enabled_stages:list[str]=field(default_factory=list)
    skipped_lab_stages:list[str]=field(default_factory=list)
    nav_redirection:str=""
    builder_cluster_id:int=-1
    robustness_score:float=0.0
    highest_network_threat:str="NONE"
    network_threat_count:int=0
    max_amplification_factor:float=0.0
    has_dga:bool=False
    suricata_rules_count:int=0
    stix_indicators_count:int=0
    confirmed_behaviors:list[str]=field(default_factory=list)
    collusion_paths_found:int=0
    adjusted_forecasts_count:int=0
    total_elapsed_ms:float=0.0
    safety_mode:str="SAFE_STATIC_DEFAULT"
    intelligence_notes:list[str]=field(default_factory=list)
@dataclass
class ResearchReadinessReport:
    """Research and publication readiness summary."""
    publication_readiness_score:float=0.0
    evidence_strength_score:float=0.0
    novelty_score:float=0.0
    reproducibility_score:float=0.0
    stage2_intelligence_score:float=0.0
    operational_risk_score:float=0.0
    risk_tier:str="LOW"
    paper_readiness:str="INSUFFICIENT"
    headline_claim:str=""
    evidence_matrix:list[dict]=field(default_factory=list)
    methodology_cards:list[dict]=field(default_factory=list)
    key_findings:list[str]=field(default_factory=list)
    limitations:list[str]=field(default_factory=list)
    recommended_next_steps:list[str]=field(default_factory=list)
    reproducibility_checklist:list[dict]=field(default_factory=list)
    suggested_figures:list[str]=field(default_factory=list)
    dataset_card:dict=field(default_factory=dict)
@dataclass
class APKMetadata:
    """Computed in Stage A and propagated through downstream stages."""
    apk_path:str=""
    package_name:str=""
    version_name:str=""
    version_code:int=0
    sha256:str=""
    md5:str=""
    ssdeep:str=""
    file_size_bytes:int=0
    cert_issuer:str=""
    cert_subject:str=""
    cert_sha256:str=""
    min_sdk:int=0
    target_sdk:int=0
    is_packed:bool=False
    packer_hint:str=""
    entry_points:list[str]=field(default_factory=list)
@dataclass
class MutationArtifactGraph:
    """Canonical analysis graph for one APK analysis run."""
    apk_metadata:APKMetadata=field(default_factory=APKMetadata)
    dead_code:list[DeadCodeArtifact]=field(default_factory=list)
    unused_permissions:list[UnusedPermissionArtifact]=field(default_factory=list)
    placeholder_strings:list[PlaceholderStringArtifact]=field(default_factory=list)
    c2_stubs:list[C2EndpointStubArtifact]=field(default_factory=list)
    partial_apis:list[PartialAPIArtifact]=field(default_factory=list)
    unfinished_ui_flows:list[UnfinishedUIFlowArtifact]=field(default_factory=list)
    genai_scaffolds:list[GenAIAPIScaffoldArtifact]=field(default_factory=list)
    manifest:dict=field(default_factory=dict)
    version_delta:Optional[VersionDelta]=None
    malware_family:str=""
    family_version:str=""
    forecasts:list[MutationForecast]=field(default_factory=list)
    stage2_intelligence:Optional[Stage2IntelligenceSummary]=None
    research_readiness:Optional[ResearchReadinessReport]=None
    stage_errors:dict[str,str]=field(default_factory=dict)
    stage_timings_ms:dict[str,float]=field(default_factory=dict)
    def total_artifact_count(self)->int:
        """Total number of mutation artifacts detected across all 7 classes."""
        return(
            len(self.dead_code)
            +len(self.unused_permissions)
            +len(self.placeholder_strings)
            +len(self.c2_stubs)
            +len(self.partial_apis)
            +len(self.unfinished_ui_flows)
            +len(self.genai_scaffolds)
        )
    def artifact_class_counts(self)->dict[str,int]:
        """Per-class artifact counts for dashboards and reports."""
        return{
            ArtifactClass.DEAD_CODE.value:len(self.dead_code),
            ArtifactClass.UNUSED_PERMISSION.value:len(self.unused_permissions),
            ArtifactClass.PLACEHOLDER_STRING.value:len(self.placeholder_strings),
            ArtifactClass.C2_ENDPOINT_STUB.value:len(self.c2_stubs),
            ArtifactClass.PARTIAL_API.value:len(self.partial_apis),
            ArtifactClass.UNFINISHED_UI_FLOW.value:len(self.unfinished_ui_flows),
            ArtifactClass.GENAI_API_SCAFFOLD.value:len(self.genai_scaffolds),
        }
    def scaffolding_artifacts(self)->list[DeadCodeArtifact]:
        """Dead-code fragments classified as SCAFFOLDING by DTE."""
        return[a for a in self.dead_code if a.dte_label==DTEClass.SCAFFOLDING]
    def high_confidence_forecasts(self,threshold:float=0.72)->list[MutationForecast]:
        """Forecasts above the Bayesian gating threshold."""
        return[f for f in self.forecasts if f.confidence_score>threshold]
    def compute_artifact_density(self)->float:
        """
        D_artifact: multi-artifact convergence score.
        Normalised to 0.33/0.66/1.00 for 1/2/3+ active core classes.
        """
        active_classes=sum([
            1 if self.dead_code else 0,
            1 if self.unused_permissions else 0,
            1 if self.placeholder_strings else 0,
            1 if self.c2_stubs else 0,
            1 if self.partial_apis else 0,
        ])
        if active_classes>=3:
            return 1.00
        if active_classes==2:
            return 0.66
        if active_classes==1:
            return 0.33
        return 0.0
    def to_dict(self)->dict:
        """Full serialisation to a Python dict."""
        def _convert(obj):
            if isinstance(obj,Enum):
                return obj.value
            if isinstance(obj,list):
                return[_convert(i)for i in obj]
            if isinstance(obj,dict):
                return{k:_convert(v)for k,v in obj.items()}
            if hasattr(obj,"__dataclass_fields__"):
                return _convert(asdict(obj))
            return obj
        return{
            "apk_metadata":_convert(self.apk_metadata),
            "mutation_artifacts":{
                "dead_code":[_convert(a)for a in self.dead_code],
                "unused_permissions":[_convert(a)for a in self.unused_permissions],
                "placeholder_strings":[_convert(a)for a in self.placeholder_strings],
                "c2_stubs":[_convert(a)for a in self.c2_stubs],
                "partial_apis":[_convert(a)for a in self.partial_apis],
                "unfinished_ui_flows":[_convert(a)for a in self.unfinished_ui_flows],
                "genai_scaffolds":[_convert(a)for a in self.genai_scaffolds],
            },
            "manifest":_convert(self.manifest),
            "version_delta":_convert(self.version_delta)if self.version_delta else None,
            "malware_family":self.malware_family,
            "family_version":self.family_version,
            "forecasts":[_convert(f)for f in self.forecasts],
            "stage2_intelligence":_convert(self.stage2_intelligence)if self.stage2_intelligence else None,
            "research_readiness":_convert(self.research_readiness)if self.research_readiness else None,
            "artifact_summary":self.artifact_class_counts(),
            "total_artifacts":self.total_artifact_count(),
            "stage_errors":_convert(self.stage_errors),
            "stage_timings_ms":_convert(self.stage_timings_ms),
        }
    def to_json(self,indent:int=2)->str:
        """Serialise to JSON string."""
        return json.dumps(self.to_dict(),indent=indent,default=str)
    def to_llm_context(self,max_chars:int=16_000)->str:
        """Compact JSON for the LLM context window."""
        compact=self.to_dict()
        result=json.dumps(compact,indent=2,default=str)
        if len(result)>max_chars:
            for entry in compact.get("mutation_artifacts",{}).get("dead_code",[]):
                entry.pop("smali_code",None)
            result=json.dumps(compact,indent=2,default=str)
        if len(result)>max_chars:
            result=result[:max_chars-50]+"\n... [TRUNCATED - context limit reached]"
        return result
    @classmethod
    def from_dict(cls,data:dict)->"MutationArtifactGraph":
        """Deserialise from a dict loaded from JSON cache or report output."""
        mag=cls()
        meta=data.get("apk_metadata",{})
        mag.apk_metadata=APKMetadata(**meta)if meta else APKMetadata()
        mag.manifest=data.get("manifest",{})
        mag.malware_family=data.get("malware_family","")
        mag.family_version=data.get("family_version","")
        version_delta=data.get("version_delta")
        if version_delta:
            mag.version_delta=VersionDelta(**version_delta)
        stage2=data.get("stage2_intelligence")or data.get("stage2_summary")
        if stage2:
            mag.stage2_intelligence=Stage2IntelligenceSummary(**stage2)
        rr=data.get("research_readiness")
        if rr:
            mag.research_readiness=ResearchReadinessReport(**rr)
        mag.stage_errors=data.get("stage_errors",{})
        mag.stage_timings_ms=data.get("stage_timings_ms",{})
        artifacts=data.get("mutation_artifacts",{})
        mag.dead_code=[DeadCodeArtifact(**cls._normalise_dead_code(a))for a in artifacts.get("dead_code",[])]
        mag.unused_permissions=[UnusedPermissionArtifact(**a)for a in artifacts.get("unused_permissions",[])]
        mag.placeholder_strings=[PlaceholderStringArtifact(**a)for a in artifacts.get("placeholder_strings",[])]
        mag.c2_stubs=[C2EndpointStubArtifact(**a)for a in artifacts.get("c2_stubs",[])]
        mag.partial_apis=[PartialAPIArtifact(**a)for a in artifacts.get("partial_apis",[])]
        mag.unfinished_ui_flows=[UnfinishedUIFlowArtifact(**a)for a in artifacts.get("unfinished_ui_flows",[])]
        mag.genai_scaffolds=[GenAIAPIScaffoldArtifact(**a)for a in artifacts.get("genai_scaffolds",[])]
        mag.forecasts=[MutationForecast(**f)for f in data.get("forecasts",[])]
        return mag
    @staticmethod
    def _normalise_dead_code(data:dict)->dict:
        item=dict(data)
        label=item.get("dte_label")
        if isinstance(label,str):
            try:
                item["dte_label"]=DTEClass(label)
            except ValueError:
                item["dte_label"]=DTEClass.SCAFFOLDING
        return item
