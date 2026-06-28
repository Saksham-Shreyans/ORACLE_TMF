from __future__ import annotations
import logging
import time
from typing import Any
from config.settings import PERMISSION_TO_API_MAP
from models.mutation_artifact_graph import UnusedPermissionArtifact
logger=logging.getLogger(__name__)
_PERMISSION_GROUP_MAP:dict[str,str]={
    "android.permission.SEND_SMS":"SMS",
    "android.permission.RECEIVE_SMS":"SMS",
    "android.permission.READ_CONTACTS":"CONTACTS",
    "android.permission.WRITE_CONTACTS":"CONTACTS",
    "android.permission.CAMERA":"CAMERA",
    "android.permission.RECORD_AUDIO":"MICROPHONE",
    "android.permission.ACCESS_FINE_LOCATION":"LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION":"LOCATION",
    "android.permission.READ_CALL_LOG":"PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS":"PHONE",
    "android.permission.READ_PHONE_STATE":"PHONE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE":"ACCESSIBILITY",
    "android.permission.BIND_DEVICE_ADMIN":"DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW":"OVERLAY",
}
class UnusedPermissionAnalyzer:
    STAGE_NAME="STAGE_E"
    def run(self,manifest:dict,analysis:Any)->list[UnusedPermissionArtifact]:
        t0=time.perf_counter()
        logger.info("[Stage E] Starting unused permission analysis")
        invoked_signatures=self._build_invoked_signature_corpus(analysis)
        logger.debug("[Stage E] Invoked API corpus size: %d",len(invoked_signatures))
        declared_permissions=manifest.get("permissions",[])
        logger.debug("[Stage E] Declared permissions: %d",len(declared_permissions))
        unused:list[UnusedPermissionArtifact]=[]
        for perm in declared_permissions:
            artifact=self._check_permission(perm,invoked_signatures)
            if artifact is not None:
                unused.append(artifact)
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage E] Complete in %.1f ms | checked=%d | unused=%d",
            elapsed_ms,len(declared_permissions),len(unused),
        )
        return unused
    def _build_invoked_signature_corpus(self,analysis:Any)->set[str]:
        corpus:set[str]=set()
        try:
            for method_analysis in analysis.get_methods():
                for _,callee_method,_ in method_analysis.get_xref_to():
                    if callee_method is None:
                        continue
                    try:
                        class_name=callee_method.get_class_name()
                        method_name=callee_method.get_name()
                        descriptor=callee_method.get_descriptor()
                        sig=f"{class_name}->{method_name}{descriptor}"
                        corpus.add(sig)
                    except Exception:
                        continue
        except Exception as exc:
            logger.warning("[Stage E] API corpus build failed: %s",exc)
        return corpus
    def _check_permission(
        self,permission:str,invoked_signatures:set[str]
    )->UnusedPermissionArtifact|None:
        expected_apis=PERMISSION_TO_API_MAP.get(permission)
        if not expected_apis:
            return None
        for api_pattern in expected_apis:
            for sig in invoked_signatures:
                if api_pattern in sig:
                    return None
        group=_PERMISSION_GROUP_MAP.get(permission,"UNKNOWN")
        context_note=self._build_context_note(permission,expected_apis)
        logger.debug("[Stage E] Unused permission detected: %s",permission)
        return UnusedPermissionArtifact(
            permission_name=permission,
            android_permission_group=group,
            expected_apis=expected_apis,
            context_note=context_note,
        )
    @staticmethod
    def _build_context_note(permission:str,expected_apis:list[str])->str:
        api_list=", ".join(expected_apis[:2])
        return(
            f"Permission '{permission}' is declared in AndroidManifest.xml "
            f"but none of its protected APIs({api_list}...)appear "
            f"anywhere in the DEX bytecode.This is a strong indicator of "
            f"pre-declared permission scaffolding for a future feature."
        )
