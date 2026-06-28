from __future__ import annotations
import logging
import re
import time
from collections import deque
from typing import Any
from config.settings import(
    ANDROID_LIFECYCLE_PREFIXES,
    DEAD_CODE_MIN_OPCODE_COUNT,
    REFLECTION_INVOKE_SIGNATURES,
)
from models.mutation_artifact_graph import DeadCodeArtifact
logger=logging.getLogger(__name__)
class DeadCodeDetector:
    STAGE_NAME="STAGE_D"
    def __init__(self)->None:
        self._lifecycle_re=re.compile(
            r"^(?:"+"|".join(re.escape(p)for p in ANDROID_LIFECYCLE_PREFIXES)+r")"
        )
    def run(
        self,
        analysis:Any,
        cfg:Any,
        manifest:dict,
    )->list[DeadCodeArtifact]:
        t0=time.perf_counter()
        logger.info("[Stage D] Starting dead code detection")
        entry_descriptors=self._collect_entry_points(analysis,manifest)
        logger.debug("[Stage D] Entry points found: %d",len(entry_descriptors))
        if cfg is not None:
            self._inject_reflection_edges(analysis,cfg)
        reachable=self._bfs_reachable(cfg,entry_descriptors)
        logger.debug("[Stage D] Reachable methods: %d",len(reachable))
        dead_artifacts=self._collect_dead_methods(analysis,reachable)
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage D] Complete in %.1f ms | dead_methods=%d",
            elapsed_ms,len(dead_artifacts),
        )
        return dead_artifacts
    def _collect_entry_points(self,analysis:Any,manifest:dict)->set[str]:
        entry_descriptors:set[str]=set()
        component_classes:set[str]=set()
        for comp_type in("activities","services","receivers","providers"):
            for comp in manifest.get(comp_type,[]):
                name=comp.get("name","")
                if name:
                    smali_class="L"+name.replace(".","/")+";"
                    component_classes.add(smali_class)
        try:
            for class_analysis in analysis.get_classes():
                class_name=class_analysis.name
                is_component=(
                    class_name in component_classes
                    or any(class_name.startswith(c.rstrip(";"))for c in component_classes)
                )
                for method_analysis in class_analysis.get_methods():
                    method_obj=method_analysis.method
                    method_name=method_obj.get_name()
                    if self._lifecycle_re.match(method_name):
                        desc=self._method_desc(method_obj)
                        entry_descriptors.add(desc)
                    if is_component:
                        desc=self._method_desc(method_obj)
                        entry_descriptors.add(desc)
        except Exception as exc:
            logger.warning("[Stage D] Entry point collection error: %s",exc)
        return entry_descriptors
    def _inject_reflection_edges(self,analysis:Any,cfg:Any)->None:
        reflection_callers=0
        try:
            for method_analysis in analysis.get_methods():
                smali_code=self._get_smali(method_analysis)
                if not smali_code:
                    continue
                has_reflection=any(
                    sig in smali_code for sig in REFLECTION_INVOKE_SIGNATURES
                )
                if not has_reflection:
                    continue
                caller_desc=self._method_desc(method_analysis.method)
                reflection_callers+=1
                string_literals=re.findall(r'const-string[^,]+,\s*"([^"]+)"',smali_code)
                for literal in string_literals:
                    smali_candidate="L"+literal.replace(".","/")+";"
                    try:
                        for class_analysis in analysis.get_classes():
                            if class_analysis.name==smali_candidate:
                                for m in class_analysis.get_methods():
                                    callee_desc=self._method_desc(m.method)
                                    if callee_desc not in cfg:
                                        cfg.add_node(callee_desc)
                                    cfg.add_edge(caller_desc,callee_desc)
                    except Exception:
                        continue
        except Exception as exc:
            logger.warning("[Stage D] Reflection edge injection error: %s",exc)
        logger.debug("[Stage D] Reflection callers found: %d",reflection_callers)
    def _bfs_reachable(self,cfg:Any,entry_points:set[str])->set[str]:
        if cfg is None:
            logger.warning("[Stage D] No CFG available — BFS skipped, all methods marked reachable")
            return set()
        visited:set[str]=set()
        queue:deque[str]=deque(entry_points)
        while queue:
            node=queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for _,callee,_ in cfg.out_edges(node,data=True)if False else[]:
                pass
            try:
                for callee in cfg.successors(node):
                    if callee not in visited:
                        queue.append(callee)
            except Exception:
                continue
        return visited
    def _collect_dead_methods(
        self,analysis:Any,reachable:set[str]
    )->list[DeadCodeArtifact]:
        dead:list[DeadCodeArtifact]=[]
        try:
            for method_analysis in analysis.get_methods():
                method_obj=method_analysis.method
                if method_analysis.is_android_api():
                    continue
                if method_analysis.is_external():
                    continue
                method_name=method_obj.get_name()
                if self._lifecycle_re.match(method_name):
                    continue
                if method_name in("<init>","<clinit>"):
                    continue
                desc=self._method_desc(method_obj)
                if desc in reachable:
                    continue
                xrefs_from=list(method_analysis.get_xref_from())
                if xrefs_from:
                    continue
                smali_code=self._get_smali(method_analysis)
                opcode_count=self._count_opcodes(smali_code)
                if opcode_count<DEAD_CODE_MIN_OPCODE_COUNT:
                    continue
                trigger_depth=self._compute_trigger_depth(smali_code)
                guard_entropy=self._compute_guard_entropy(smali_code)
                api_sensitivity=self._compute_api_sensitivity(smali_code)
                guard_indegree=len(xrefs_from)
                artifact=DeadCodeArtifact(
                    class_name=method_obj.get_class_name(),
                    method_name=f"{method_name}{method_obj.get_descriptor()}",
                    smali_code=smali_code[:4000],
                    opcode_count=opcode_count,
                    trigger_depth=trigger_depth,
                    guard_entropy=guard_entropy,
                    api_sensitivity=api_sensitivity,
                    guard_indegree=guard_indegree,
                )
                dead.append(artifact)
        except Exception as exc:
            logger.warning("[Stage D] Dead method collection error: %s",exc)
        return dead
    @staticmethod
    def _get_smali(method_analysis:Any)->str:
        try:
            src=method_analysis.method.get_source()
            return src if src else ""
        except Exception:
            try:
                code=method_analysis.method.get_code()
                if code is None:
                    return ""
                return str(code.get_bc())
            except Exception:
                return ""
    @staticmethod
    def _count_opcodes(smali_code:str)->int:
        if not smali_code:
            return 0
        opcode_re=re.compile(
            r"^\s{4}(?:invoke|move|iget|iput|sget|sput|new|const|add|sub|mul|div|"
            r"rem|and|or|xor|shl|shr|ushr|neg|not|int|long|float|double|return|"
            r"goto|if|switch|array|check|instance|monitor|throw|fill)",
            re.MULTILINE,
        )
        return len(opcode_re.findall(smali_code))
    @staticmethod
    def _compute_trigger_depth(smali_code:str)->int:
        if not smali_code:
            return 0
        depth=0
        max_depth=0
        for line in smali_code.splitlines():
            stripped=line.strip()
            if stripped.startswith(("if-eq","if-ne","if-lt","if-ge","if-gt","if-le")):
                depth+=1
                max_depth=max(max_depth,depth)
            elif stripped.startswith(":cond_"):
                depth=max(0,depth-1)
        return max_depth
    @staticmethod
    def _compute_guard_entropy(smali_code:str)->float:
        if not smali_code:
            return 0.0
        import math
        condition_re=re.compile(r"if-\w+\s+\{?([vp]\d+)\}?,\s*\{?([vp]\d+)\}?",re.IGNORECASE)
        operands:list[str]=[]
        for match in condition_re.finditer(smali_code):
            operands.extend([match.group(1),match.group(2)])
        if not operands:
            return 0.0
        total=len(operands)
        freq:dict[str,int]={}
        for op in operands:
            freq[op]=freq.get(op,0)+1
        entropy=-sum((c/total)*math.log2(c/total)for c in freq.values())
        return round(entropy,4)
    @staticmethod
    def _compute_api_sensitivity(smali_code:str)->float:
        SENSITIVE_APIS:dict[str,float]={
            "SmsManager":1.0,
            "TelephonyManager":0.9,
            "LocationManager":0.8,
            "AudioRecord":0.8,
            "MediaRecorder":0.8,
            "Camera":0.7,
            "DevicePolicyManager":1.0,
            "AccessibilityService":0.9,
            "ContactsContract":0.7,
            "CallLog":0.8,
            "AccountManager":0.7,
            "Cipher":0.6,
            "DexClassLoader":0.9,
            "WindowManager":0.6,
        }
        if not smali_code:
            return 0.0
        score=0.0
        for api,weight in SENSITIVE_APIS.items():
            if api in smali_code:
                score=max(score,weight)
        return round(score,4)
    @staticmethod
    def _method_desc(method_obj:Any)->str:
        try:
            return(
                f"{method_obj.get_class_name()}"
                f"->{method_obj.get_name()}"
                f"{method_obj.get_descriptor()}"
            )
        except Exception:
            return str(method_obj)
