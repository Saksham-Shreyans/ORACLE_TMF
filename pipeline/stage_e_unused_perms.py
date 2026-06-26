"""
ORACLE-TMF  ·  pipeline/stage_e_unused_perms.py
================================================
STAGE E — Unused Permission Intent Analysis
Responsibility:
  • Cross-reference every permission declared in AndroidManifest.xml
    against the set of framework APIs actually invoked in the reachable CFG
  • A permission is "unused" if ALL its mapped API signatures are absent
    from the reachable method corpus
  • Return a list of UnusedPermissionArtifact objects
Inputs:
  manifest   : dict (from Stage C) — declared permissions
  analysis   : Androguard Analysis object (from Stage B) — reachable API corpus
Outputs: list[UnusedPermissionArtifact]
Algorithm (Axplorer-inspired):
  The Axplorer framework maps each Android permission to the set of
  protected framework API methods that require it.  We implement a
  curated subset of this mapping (settings.PERMISSION_TO_API_MAP).
  For each declared permission P:
    1. Look up expected_apis = PERMISSION_TO_API_MAP.get(P, [])
    2. Scan all reachable method invocations for any expected_api signature
    3. If NONE are found → permission is unused → emit UnusedPermissionArtifact
  Note: Permissions with no entry in the map are skipped (insufficient data).
"""
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
    """
    Stage E: Unused Permission Intent Analysis.
    Usage
    -----
    >>> stage = UnusedPermissionAnalyzer()
    >>> unused = stage.run(manifest, analysis)
    """
    STAGE_NAME="STAGE_E"
    
    
    
    def run(self,manifest:dict,analysis:Any)->list[UnusedPermissionArtifact]:
        """
        Execute Stage E.
        Parameters
        ----------
        manifest : dict
            Output of Stage C.
        analysis : Androguard Analysis object
            Output of Stage B.
        Returns
        -------
        list[UnusedPermissionArtifact]
            All declared permissions with zero matching API invocations
            in the reachable CFG.
        """
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
        """
        Build a set of all framework API method signatures invoked anywhere
        in the APK's DEX bytecode (both reachable and dead code paths).
        We include dead code paths here intentionally: an unused permission
        is only suspicious if the API is absent from the ENTIRE binary,
        not just the reachable paths.
        """
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
        """
        Check whether a single permission has any matching API in the corpus.
        Returns UnusedPermissionArtifact if the permission is unused,
        None if the permission is actively used or has no mapping.
        """
        
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
        """Generate a human-readable context note for the analyst report."""
        api_list=", ".join(expected_apis[:2])
        return(
            f"Permission '{permission}' is declared in AndroidManifest.xml "
            f"but none of its protected APIs ({api_list}...) appear "
            f"anywhere in the DEX bytecode. This is a strong indicator of "
            f"pre-declared permission scaffolding for a future feature."
        )
