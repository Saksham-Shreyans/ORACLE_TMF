"""
ORACLE-TMF  ·  pipeline/stage_h_partial_apis.py
================================================
STAGE H — Partial API Implementation Detection
Responsibility:
  • Identify classes that extend sensitive Android framework interfaces
    (AccessibilityService, DeviceAdminReceiver, PhoneStateListener, etc.)
  • For each such class, inspect the overriding methods
  • Flag a method as a "partial scaffold" if:
      – Opcode count < PARTIAL_API_OPCODE_THRESHOLD (10)
      – AND no malicious terminal API calls are present
        (performGlobalAction, lockNow, wipeData, etc.)
  • Return a list of PartialAPIArtifact objects
Inputs:
  analysis : Androguard Analysis object (from Stage B)
Outputs: list[PartialAPIArtifact]
Algorithm:
  Interface contract analysis:
    1. Iterate all classes in the analysis
    2. For each class, inspect its superclass and implemented interfaces
    3. If any match SENSITIVE_FRAMEWORK_CLASSES → mark as high-risk subclass
    4. For each method in a high-risk class:
       a. Count Dalvik opcodes
       b. Scan for malicious API calls
       c. If opcode_count < threshold AND no malicious calls → partial scaffold
Rationale:
  Malware authors declare an AccessibilityService to secure the 
  BIND_ACCESSIBILITY_SERVICE permission but leave the onAccessibilityEvent()
  method body nearly empty until the complex overlay/keylogging logic is 
  ready.  A skeleton AccessibilityService with just Log.d() statements is
  almost certainly a placeholder.
"""
from __future__ import annotations
import logging
import re
import time
from typing import Any
from config.settings import(
    MALICIOUS_API_SIGNATURES,
    PARTIAL_API_OPCODE_THRESHOLD,
    SENSITIVE_FRAMEWORK_CLASSES,
)
from models.mutation_artifact_graph import PartialAPIArtifact
logger=logging.getLogger(__name__)

_SENSITIVE_CLASS_PATTERNS:list[re.Pattern]=[
    re.compile(re.escape(cls),re.IGNORECASE)
    for cls in SENSITIVE_FRAMEWORK_CLASSES
]

_MALICIOUS_API_PATTERNS:list[re.Pattern]=[
    re.compile(re.escape(sig),re.IGNORECASE)
    for sig in MALICIOUS_API_SIGNATURES
]

_INTERFACE_OVERRIDE_METHODS:dict[str,list[str]]={
    "android/accessibilityservice/AccessibilityService":[
        "onAccessibilityEvent","onInterrupt","onServiceConnected",
    ],
    "android/app/admin/DeviceAdminReceiver":[
        "onEnabled","onDisabled","onPasswordChanged","onPasswordFailed",
    ],
    "android/telephony/PhoneStateListener":[
        "onCallStateChanged","onDataActivity","onSignalStrengthChanged",
    ],
    "android/content/BroadcastReceiver":[
        "onReceive",
    ],
    "android/inputmethodservice/InputMethodService":[
        "onCreateInputView","onStartInputView","onCurrentInputMethodSubtypeChanged",
    ],
    "android/app/NotificationListenerService":[
        "onNotificationPosted","onNotificationRemoved","onListenerConnected",
    ],
}
class PartialAPIDetector:
    """
    Stage H: Partial API Implementation Detection.
    Usage
    -----
    >>> stage = PartialAPIDetector()
    >>> partial_apis = stage.run(analysis)
    """
    STAGE_NAME="STAGE_H"
    
    
    
    def run(self,analysis:Any)->list[PartialAPIArtifact]:
        """
        Execute Stage H.
        Parameters
        ----------
        analysis : Androguard Analysis object from Stage B
        Returns
        -------
        list[PartialAPIArtifact]
        """
        t0=time.perf_counter()
        logger.info("[Stage H] Starting partial API implementation detection")
        artifacts:list[PartialAPIArtifact]=[]
        try:
            for class_analysis in analysis.get_classes():
                artifact=self._check_class(class_analysis)
                if artifact is not None:
                    artifacts.append(artifact)
        except Exception as exc:
            logger.warning("[Stage H] Analysis iteration error: %s",exc)
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage H] Complete in %.1f ms | partial_api_classes=%d",
            elapsed_ms,len(artifacts),
        )
        return artifacts
    
    
    
    def _check_class(self,class_analysis:Any)->PartialAPIArtifact|None:
        """
        Inspect a single class for partial API implementation.
        Returns an artifact if the class extends a sensitive interface
        with skeleton method bodies.
        """
        class_name=class_analysis.name
        
        interface_extended=self._get_sensitive_interface(class_analysis)
        if not interface_extended:
            return None
        
        stub_methods:list[str]=[]
        opcode_counts:dict[str,int]={}
        expected_overrides=_INTERFACE_OVERRIDE_METHODS.get(interface_extended,[])
        for method_analysis in class_analysis.get_methods():
            method_obj=method_analysis.method
            method_name=method_obj.get_name()
            
            if expected_overrides and method_name not in expected_overrides:
                
                if not method_name.startswith("on"):
                    continue
            smali=self._get_smali(method_analysis)
            if not smali:
                continue
            
            opcode_count=self._count_opcodes(smali)
            opcode_counts[method_name]=opcode_count
            
            has_malicious=self._has_malicious_api(smali)
            if has_malicious:
                
                continue
            
            if opcode_count<PARTIAL_API_OPCODE_THRESHOLD:
                stub_methods.append(method_name)
        if not stub_methods:
            return None
        logger.debug(
            "[Stage H] Partial API detected: %s extends %s | stubs=%s",
            class_name,interface_extended,stub_methods,
        )
        return PartialAPIArtifact(
            class_name=class_name,
            interface_extended=interface_extended,
            method_stubs=stub_methods,
            opcode_counts=opcode_counts,
        )
    
    
    
    def _get_sensitive_interface(self,class_analysis:Any)->str:
        """
        Check if a class extends or implements any SENSITIVE_FRAMEWORK_CLASSES.
        Returns the matched interface name or empty string.
        """
        try:
            class_obj=class_analysis.get_vm_class()
            if class_obj is None:
                return ""
            
            superclass=class_obj.get_superclassname()or ""
            for pattern,cls_name in zip(_SENSITIVE_CLASS_PATTERNS,SENSITIVE_FRAMEWORK_CLASSES):
                if pattern.search(superclass):
                    return cls_name
            
            interfaces=class_obj.get_interfaces()or[]
            for iface in interfaces:
                iface_name=str(iface)
                for pattern,cls_name in zip(_SENSITIVE_CLASS_PATTERNS,SENSITIVE_FRAMEWORK_CLASSES):
                    if pattern.search(iface_name):
                        return cls_name
        except Exception as exc:
            logger.debug("[Stage H] Interface check failed for class: %s",exc)
        return ""
    
    
    
    @staticmethod
    def _has_malicious_api(smali:str)->bool:
        """Return True if any malicious API signature appears in the Smali code."""
        return any(p.search(smali)for p in _MALICIOUS_API_PATTERNS)
    @staticmethod
    def _count_opcodes(smali:str)->int:
        """Count Dalvik opcode instructions in a Smali method body."""
        if not smali:
            return 0
        opcode_re=re.compile(
            r"^\s{4}(?:invoke|move|iget|iput|sget|sput|new|const|add|sub|mul|div|"
            r"rem|and|or|xor|shl|shr|ushr|neg|not|int|long|float|double|return|"
            r"goto|if|switch|array|check|instance|monitor|throw|fill)",
            re.MULTILINE,
        )
        return len(opcode_re.findall(smali))
    @staticmethod
    def _get_smali(method_analysis:Any)->str:
        """Extract Smali source from a MethodAnalysis object."""
        try:
            src=method_analysis.method.get_source()
            return src if src else ""
        except Exception:
            return ""
