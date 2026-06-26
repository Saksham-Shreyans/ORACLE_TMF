"""
ORACLE-TMF  ·  models/mutation_artifact_graph.py
=================================================
The Mutation Artifact Graph (MAG) is the canonical data structure that
flows between every pipeline stage.  It is a JSON-serialisable Python
dataclass—completely free of external dependencies so any stage can
import it without circular imports.
Schema reference:  Section 2.3 of the TMF research paper.
"""
from __future__ import annotations
import json
from dataclasses import dataclass,field,asdict
from typing import Optional
from enum import Enum



class ArtifactClass(str,Enum):
    """The 7-class mutation artifact taxonomy (ORACLE-TMF Extended Taxonomy)."""
    DEAD_CODE="CLASS_1_DEAD_CODE"
    UNUSED_PERMISSION="CLASS_2_UNUSED_PERMISSION"
    PLACEHOLDER_STRING="CLASS_3_PLACEHOLDER_STRING"
    C2_ENDPOINT_STUB="CLASS_4_C2_ENDPOINT_STUB"
    PARTIAL_API="CLASS_5_PARTIAL_API"
    UNFINISHED_UI_FLOW="CLASS_6_UNFINISHED_UI"
    GENAI_API_SCAFFOLD="CLASS_7_GENAI_SCAFFOLD"
class DTEClass(str,Enum):
    """Dormancy Taxonomy Engine output labels for dead code classification."""
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
    """
    CLASS 1 — Dead Code / Unreachable Methods.
    Smali methods with zero incoming edges in the global CFG that are
    not standard Android lifecycle callbacks.
    """
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
    """
    CLASS 2 — Unused Permission Intents.
    Android permissions declared in AndroidManifest.xml whose corresponding
    protected framework APIs never appear in the reachable CFG.
    """
    permission_name:str 
    android_permission_group:str=""
    expected_apis:list[str]=field(default_factory=list)
    context_note:str=""
@dataclass
class PlaceholderStringArtifact:
    """
    CLASS 3 — Placeholder Strings & Resources.
    High-entropy or patterned string literals in the string pool or
    res/values/strings.xml that reference unbuilt features or staging infra.
    """
    value:str 
    source:str 
    entropy:float=0.0
    matched_pattern:str=""
    key_name:str=""
@dataclass
class C2EndpointStubArtifact:
    """
    CLASS 4 — C2 Endpoint Stubs.
    Network routing logic (OkHttp/Retrofit) that defines API paths, payload schemas,
    or HTTP methods but is never actually executed (.execute() / .enqueue() absent).
    """
    class_name:str 
    method_name:str 
    framework:str 
    extracted_url:str=""
    http_method:str=""
    payload_schema:str=""
@dataclass
class PartialAPIArtifact:
    """
    CLASS 5 — Partial API Implementations.
    Classes extending sensitive Android framework interfaces (AccessibilityService,
    DeviceAdminReceiver) where overriding methods contain < 10 opcodes and no
    malicious API invocations — indicating architectural groundwork without payload.
    """
    class_name:str 
    interface_extended:str 
    method_stubs:list[str]=field(default_factory=list)
    opcode_counts:dict[str,int]=field(default_factory=dict)
@dataclass
class UnfinishedUIFlowArtifact:
    """
    CLASS 6 — Unfinished UI Flows.
    Activity / Fragment / WebView XML layout files present in res/layout/ that
    are never inflated via setContentView() or Fragment.inflate() in the DEX.
    """
    layout_file:str 
    layout_id:str=""
    suspected_type:str=""
    asset_refs:list[str]=field(default_factory=list)
@dataclass
class GenAIAPIScaffoldArtifact:
    """
    CLASS 7 — GenAI API Scaffolds (TMF-Psi).
    NEW in ORACLE-TMF: Dormant stubs for LLM API endpoints (Gemini, GPT-4,
    Anthropic Claude, Ollama).  Signals the malware is being augmented with
    generative AI for adaptive behaviour.
    """
    class_name:str 
    method_name:str 
    provider:str=""
    api_endpoint:str=""
    model_hint:str=""



@dataclass
class VersionDelta:
    """
    Output of Stage I (Version Diff Engine).
    Records the artifacts added/removed between v_{n-1} and v_n to compute
    the Mutation Velocity Vector (MVV).
    """
    artifacts_added:list[dict]=field(default_factory=list)
    artifacts_removed:list[dict]=field(default_factory=list)
    edit_distance:float=0.0
    mvv_raw:float=1.0
    mvv_normalized:float=1.0



@dataclass
class MutationForecast:
    """
    A single mutation forecast prediction with Bayesian confidence scoring.
    One MAG may produce 1-N forecasts.
    """
    
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
class APKMetadata:
    """Computed in Stage A. Propagated through all downstream stages."""
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
    """
    The Mutation Artifact Graph (MAG) — the canonical data structure
    passed between every pipeline stage.
    Stages populate their relevant fields and pass the enriched MAG forward.
    The orchestrator owns the single MAG instance for an APK analysis run.
    JSON serialisation: call mag.to_json() for the Stage-J context payload.
    """
    
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
        """Per-class artifact counts for the Streamlit dashboard gauges."""
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
        """Dead code fragments classified as SCAFFOLDING by the DTE — sent to Stage J."""
        return[a for a in self.dead_code if a.dte_label==DTEClass.SCAFFOLDING]
    def high_confidence_forecasts(self,threshold:float=0.72)->list[MutationForecast]:
        """Forecasts that passed the Bayesian gating threshold."""
        return[f for f in self.forecasts if f.confidence_score>threshold]
    def compute_artifact_density(self)->float:
        """
        D_artifact: multi-artifact convergence score.
        Counts how many distinct artifact CLASSES point to at least one finding.
        Normalised to [0.33, 0.66, 1.00] based on 1/2/3+ converging classes.
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
        elif active_classes==2:
            return 0.66
        elif active_classes==1:
            return 0.33
        return 0.0
    
    
    
    def to_dict(self)->dict:
        """Full serialisation to a Python dict (recursively converts dataclasses)."""
        def _convert(obj):
            if isinstance(obj,(DeadCodeArtifact,UnusedPermissionArtifact,
                                PlaceholderStringArtifact,C2EndpointStubArtifact,
                                PartialAPIArtifact,UnfinishedUIFlowArtifact,
                                GenAIAPIScaffoldArtifact,VersionDelta,
                                MutationForecast,APKMetadata)):
                d=asdict(obj)
                
                for k,v in d.items():
                    if isinstance(v,Enum):
                        d[k]=v.value
                return d
            elif isinstance(obj,Enum):
                return obj.value
            elif isinstance(obj,list):
                return[_convert(i)for i in obj]
            elif isinstance(obj,dict):
                return{k:_convert(v)for k,v in obj.items()}
            return obj
        result={
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
            "manifest":self.manifest,
            "version_delta":_convert(self.version_delta)if self.version_delta else None,
            "malware_family":self.malware_family,
            "family_version":self.family_version,
            "forecasts":[_convert(f)for f in self.forecasts],
            "artifact_summary":self.artifact_class_counts(),
            "total_artifacts":self.total_artifact_count(),
            "stage_errors":self.stage_errors,
            "stage_timings_ms":self.stage_timings_ms,
        }
        return result
    def to_json(self,indent:int=2)->str:
        """Serialise to JSON string (used as LLM context payload in Stage J)."""
        return json.dumps(self.to_dict(),indent=indent,default=str)
    def to_llm_context(self,max_chars:int=16_000)->str:
        """
        Compact JSON for LLM context window.
        Strips large fields (raw Smali) if total length would exceed max_chars.
        """
        compact=self.to_dict()
        
        for entry in compact.get("mutation_artifacts",{}).get("dead_code",[]):
            if len(self.to_json())>max_chars:
                entry.pop("smali_code",None)
        result=json.dumps(compact,indent=2,default=str)
        if len(result)>max_chars:
            
            result=result[:max_chars-50]+"\n... [TRUNCATED — context limit reached]"
        return result
    @classmethod
    def from_dict(cls,data:dict)->"MutationArtifactGraph":
        """Deserialise from a dict (e.g. loaded from JSON cache)."""
        mag=cls()
        meta=data.get("apk_metadata",{})
        mag.apk_metadata=APKMetadata(**meta)if meta else APKMetadata()
        mag.manifest=data.get("manifest",{})
        mag.malware_family=data.get("malware_family","")
        mag.family_version=data.get("family_version","")
        mag.stage_errors=data.get("stage_errors",{})
        mag.stage_timings_ms=data.get("stage_timings_ms",{})
        artifacts=data.get("mutation_artifacts",{})
        mag.dead_code=[DeadCodeArtifact(**a)for a in artifacts.get("dead_code",[])]
        mag.unused_permissions=[
            UnusedPermissionArtifact(**a)for a in artifacts.get("unused_permissions",[])
        ]
        mag.placeholder_strings=[
            PlaceholderStringArtifact(**a)for a in artifacts.get("placeholder_strings",[])
        ]
        mag.c2_stubs=[
            C2EndpointStubArtifact(**a)for a in artifacts.get("c2_stubs",[])
        ]
        mag.partial_apis=[
            PartialAPIArtifact(**a)for a in artifacts.get("partial_apis",[])
        ]
        return mag
