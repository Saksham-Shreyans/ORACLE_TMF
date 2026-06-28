from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass,field
from itertools import combinations
from typing import Optional
from config.settings import ANTHROPIC_API_KEY,LLM_MODEL
from config.stage2_settings import(
    CABAL_LLM_COMPAT_THRESHOLD,
    CABAL_MAX_APKS,
    CABAL_MAX_HOPS,
)
from models.mutation_artifact_graph import MutationArtifactGraph
logger=logging.getLogger(__name__)
@dataclass
class IntentStub:
    apk_hash:str=""
    apk_package:str=""
    action:str=""
    category:str=""
    data_type:str=""
    extras_schema:dict=field(default_factory=dict)
    source_class:str=""
    source_method:str=""
    confidence:float=0.0
@dataclass
class IntentFilter:
    apk_hash:str=""
    apk_package:str=""
    action:str=""
    category:str=""
    data_type:str=""
    component_class:str=""
    is_exported:bool=True
    grants_permission:str=""
@dataclass
class CABALEdge:
    stub:IntentStub=field(default_factory=IntentStub)
    intent_filter:IntentFilter=field(default_factory=IntentFilter)
    compatibility_score:float=0.0
    collusion_type:str=""
    evidence:list[str]=field(default_factory=list)
@dataclass
class CollusionPath:
    path_id:str=""
    apk_sequence:list[str]=field(default_factory=list)
    edges:list[CABALEdge]=field(default_factory=list)
    total_hops:int=0
    aggregate_score:float=0.0
    predicted_capability:str=""
    mitre_technique:str=""
@dataclass
class CABALResult:
    apks_analysed:int=0
    total_edges_found:int=0
    collusion_paths:list[CollusionPath]=field(default_factory=list)
    high_confidence_paths:list[CollusionPath]=field(default_factory=list)
    runtime_ms:float=0.0
    def to_dict(self)->dict:
        return{
            "apks_analysed":self.apks_analysed,
            "total_edges_found":self.total_edges_found,
            "collusion_path_count":len(self.collusion_paths),
            "high_confidence_count":len(self.high_confidence_paths),
            "runtime_ms":round(self.runtime_ms,2),
            "paths":[
                {
                    "path_id":p.path_id,
                    "apk_sequence":p.apk_sequence,
                    "hops":p.total_hops,
                    "score":round(p.aggregate_score,4),
                    "capability":p.predicted_capability,
                    "mitre":p.mitre_technique,
                }
                for p in self.high_confidence_paths
            ],
        }
class CABALEngine:
    ENGINE_NAME="CABAL"
    _KNOWN_PATTERNS:list[tuple]=[
        ("SMS","RECEIVE_SMS","SMS_BRIDGE"),
        ("CONTACTS","CALL_LOG","DATA_HARVEST_BRIDGE"),
        ("OVERLAY","ACCESSIBILITY","ATS_BRIDGE"),
        ("CLIPBOARD","UPLOAD","CLIPBOARD_EXFIL_BRIDGE"),
        ("SCREEN","RECORD","SCREEN_CAPTURE_BRIDGE"),
        ("ADMIN","DEVICE_ADMIN","PRIVILEGE_BRIDGE"),
        ("UPI","BANKING","FINANCIAL_FRAUD_BRIDGE"),
        ("LOCATION","SEND","LOCATION_EXFIL_BRIDGE"),
    ]
    def __init__(self)->None:
        logger.info("[CABAL] Cross-App Collusion engine initialised")
    def run(
        self,
        mag_list:list[MutationArtifactGraph],
        use_llm:bool=True,
    )->CABALResult:
        t0=time.perf_counter()
        n=len(mag_list)
        if n>CABAL_MAX_APKS:
            logger.warning(
                "[CABAL] Input capped to %d APKs (got %d) — O(n²) tractability limit",
                CABAL_MAX_APKS,n,
            )
            mag_list=mag_list[:CABAL_MAX_APKS]
            n=CABAL_MAX_APKS
        logger.info("[CABAL] Analysing %d APKs for collusion",n)
        stubs:list[IntentStub]=[]
        filters:list[IntentFilter]=[]
        for mag in mag_list:
            stubs.extend(self._extract_intent_stubs(mag))
            filters.extend(self._extract_intent_filters(mag))
        logger.info(
            "[CABAL] Extracted %d stubs | %d filters",len(stubs),len(filters)
        )
        edges:list[CABALEdge]=[]
        for stub in stubs:
            for intent_filter in filters:
                if stub.apk_package==intent_filter.apk_package:
                    continue
                score=self._compute_compatibility(stub,intent_filter,use_llm)
                if score>=CABAL_LLM_COMPAT_THRESHOLD:
                    edge=CABALEdge(
                        stub=stub,
                        intent_filter=intent_filter,
                        compatibility_score=round(score,4),
                        collusion_type=self._classify_collusion(stub,intent_filter),
                        evidence=self._build_evidence(stub,intent_filter,score),
                    )
                    edges.append(edge)
        logger.info("[CABAL] Found %d collusion edges above threshold %.2f",
                    len(edges),CABAL_LLM_COMPAT_THRESHOLD)
        paths=self._find_collusion_paths(edges,mag_list)
        high_conf=[
            p for p in paths
            if p.aggregate_score>=CABAL_LLM_COMPAT_THRESHOLD
        ]
        elapsed_ms=(time.perf_counter()-t0)*1000
        result=CABALResult(
            apks_analysed=n,
            total_edges_found=len(edges),
            collusion_paths=paths,
            high_confidence_paths=high_conf,
            runtime_ms=round(elapsed_ms,2),
        )
        logger.info(
            "[CABAL] Complete in %.1f ms | edges=%d | paths=%d | high_conf=%d",
            elapsed_ms,len(edges),len(paths),len(high_conf),
        )
        return result
    @staticmethod
    def _extract_intent_stubs(mag:MutationArtifactGraph)->list[IntentStub]:
        stubs:list[IntentStub]=[]
        pkg=mag.apk_metadata.package_name
        apk_hash=mag.apk_metadata.sha256[:16]
        for dc in mag.dead_code:
            smali_lower=dc.smali_code.lower()
            if "intent" not in smali_lower:
                continue
            action=""
            if "sms" in smali_lower:
                action="android.provider.Telephony.SMS_RECEIVED"
            elif "contact" in smali_lower:
                action="android.intent.action.PICK"
            elif "clipboard" in smali_lower:
                action="ClipboardManager"
            elif "accessibility" in smali_lower:
                action="android.accessibilityservice"
            elif "overlay" in smali_lower or "alert_window" in smali_lower:
                action="SYSTEM_ALERT_WINDOW"
            if action:
                stubs.append(IntentStub(
                    apk_hash=apk_hash,
                    apk_package=pkg,
                    action=action,
                    source_class=dc.class_name,
                    source_method=dc.method_name,
                    confidence=dc.dte_confidence,
                ))
        for c2 in mag.c2_stubs:
            if "broadcast" in c2.extracted_url.lower():
                stubs.append(IntentStub(
                    apk_hash=apk_hash,
                    apk_package=pkg,
                    action=c2.extracted_url,
                    source_class=c2.class_name,
                    source_method=c2.method_name,
                    confidence=0.7,
                ))
        return stubs
    @staticmethod
    def _extract_intent_filters(mag:MutationArtifactGraph)->list[IntentFilter]:
        filters:list[IntentFilter]=[]
        pkg=mag.apk_metadata.package_name
        apk_hash=mag.apk_metadata.sha256[:16]
        manifest=mag.manifest
        for component_type in("receivers","services","activities"):
            for comp in manifest.get(component_type,[]):
                if not comp.get("exported",False):
                    continue
                for intent_filter in comp.get("intent_filters",[]):
                    action=intent_filter.get("action","")
                    if action:
                        filters.append(IntentFilter(
                            apk_hash=apk_hash,
                            apk_package=pkg,
                            action=action,
                            component_class=comp.get("name",""),
                            is_exported=True,
                        ))
        return filters
    def _compute_compatibility(
        self,
        stub:IntentStub,
        intent_filter:IntentFilter,
        use_llm:bool,
    )->float:
        pattern_score=self._pattern_match_score(stub,intent_filter)
        if not use_llm or not ANTHROPIC_API_KEY:
            return pattern_score
        if pattern_score<0.3:
            return pattern_score
        llm_score=self._llm_compatibility_score(stub,intent_filter)
        return round(pattern_score*0.3+llm_score*0.7,4)
    def _pattern_match_score(
        self,stub:IntentStub,intent_filter:IntentFilter
    )->float:
        stub_action_lower=stub.action.lower()
        filter_action_lower=intent_filter.action.lower()
        if stub.action==intent_filter.action:
            return 1.0
        for stub_hint,filter_hint,_ in self._KNOWN_PATTERNS:
            if(stub_hint.lower()in stub_action_lower and
                    filter_hint.lower()in filter_action_lower):
                return 0.85
        stub_words=set(stub_action_lower.replace("."," ").replace("_"," ").split())
        filter_words=set(filter_action_lower.replace("."," ").replace("_"," ").split())
        overlap=len(stub_words&filter_words)
        if overlap>0:
            return min(0.7,overlap*0.2)
        return 0.0
    def _llm_compatibility_score(
        self,stub:IntentStub,intent_filter:IntentFilter
    )->float:
        try:
            import anthropic
            client=anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            prompt=(
                f"You are a mobile security analyst assessing Android ICC collusion risk.\n\n"
                f"APK A(package:{stub.apk_package})has a dormant Intent stub:\n"
                f"  Action:{stub.action}\n"
                f"  Source:{stub.source_class}.{stub.source_method}\n\n"
                f"APK B(package:{intent_filter.apk_package})has an exported IntentFilter:\n"
                f"  Action:{intent_filter.action}\n"
                f"  Component:{intent_filter.component_class}\n\n"
                f"Score the probability(0.0–1.0)that APK A's stub is designed to "
                f"communicate with APK B's filter for a malicious purpose.\n"
                f"Respond with ONLY a JSON object:{{\"score\":0.XX,\"reason\":\"...\"}}"
            )
            response=client.messages.create(
                model=LLM_MODEL,
                max_tokens=150,
                messages=[{"role":"user","content":prompt}],
            )
            text="".join(
                b.text for b in response.content if hasattr(b,"text")
            )
            parsed=json.loads(text.strip())
            return float(parsed.get("score",0.0))
        except Exception as exc:
            logger.debug("[CABAL] LLM compatibility scoring failed: %s",exc)
            return 0.0
    def _classify_collusion(
        self,stub:IntentStub,intent_filter:IntentFilter
    )->str:
        stub_lower=stub.action.lower()
        filter_lower=intent_filter.action.lower()
        for stub_hint,filter_hint,ctype in self._KNOWN_PATTERNS:
            if stub_hint.lower()in stub_lower or filter_hint.lower()in filter_lower:
                return ctype
        return "GENERIC_ICC_COLLUSION"
    @staticmethod
    def _build_evidence(
        stub:IntentStub,
        intent_filter:IntentFilter,
        score:float,
    )->list[str]:
        return[
            f"Stub in{stub.apk_package}({stub.source_class})sends "
            f"Intent({stub.action})",
            f"Filter in{intent_filter.apk_package}({intent_filter.component_class})"
            f"exports IntentFilter({intent_filter.action})",
            f"Compatibility score:{score:.3f}≥{CABAL_LLM_COMPAT_THRESHOLD}",
        ]
    def _find_collusion_paths(
        self,
        edges:list[CABALEdge],
        mag_list:list[MutationArtifactGraph],
    )->list[CollusionPath]:
        paths:list[CollusionPath]=[]
        for i,edge in enumerate(edges):
            path=CollusionPath(
                path_id=f"CABAL-{i:04d}",
                apk_sequence=[edge.stub.apk_package,edge.intent_filter.apk_package],
                edges=[edge],
                total_hops=1,
                aggregate_score=edge.compatibility_score,
                predicted_capability=edge.collusion_type,
                mitre_technique=self._map_to_mitre(edge.collusion_type),
            )
            paths.append(path)
        for hop in range(2,CABAL_MAX_HOPS+1):
            extended_any=False
            new_paths:list[CollusionPath]=[]
            for path in paths:
                if path.total_hops!=hop-1:
                    continue
                last_pkg=path.apk_sequence[-1]
                for edge in edges:
                    if edge.stub.apk_package!=last_pkg:
                        continue
                    if edge.intent_filter.apk_package in path.apk_sequence:
                        continue
                    new_score=path.aggregate_score*edge.compatibility_score
                    extended=CollusionPath(
                        path_id=f"{path.path_id}-H{hop}",
                        apk_sequence=path.apk_sequence+[edge.intent_filter.apk_package],
                        edges=path.edges+[edge],
                        total_hops=hop,
                        aggregate_score=round(new_score,4),
                        predicted_capability=f"{path.predicted_capability}→{edge.collusion_type}",
                        mitre_technique=self._map_to_mitre(edge.collusion_type),
                    )
                    new_paths.append(extended)
                    extended_any=True
            paths.extend(new_paths)
            if not extended_any:
                break
        return paths
    @staticmethod
    def _map_to_mitre(collusion_type:str)->str:
        mapping={
            "SMS_BRIDGE":"T1636.004 - Protected User Data: SMS Messages",
            "DATA_HARVEST_BRIDGE":"T1636.003 - Protected User Data: Contact List",
            "ATS_BRIDGE":"T1417 - Input Capture: GUI Input Capture",
            "CLIPBOARD_EXFIL_BRIDGE":"T1414 - Clipboard Data",
            "SCREEN_CAPTURE_BRIDGE":"T1513 - Screen Capture",
            "PRIVILEGE_BRIDGE":"T1626 - Abuse Elevation Control Mechanism",
            "FINANCIAL_FRAUD_BRIDGE":"T1640 - Account Access Removal",
            "LOCATION_EXFIL_BRIDGE":"T1430 - Location Tracking",
        }
        return mapping.get(collusion_type,"T1421 - System Network Configuration Discovery")
