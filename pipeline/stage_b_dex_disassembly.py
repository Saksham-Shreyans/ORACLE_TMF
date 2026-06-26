"""
ORACLE-TMF  Â·  pipeline/stage_b_dex_disassembly.py
====================================================
STAGE B â€” DEX Bytecode Disassembly and Smali Extraction
Responsibility:
  â€¢ Load all .dex files (classes.dex, classes2.dex, â€¦) from the APK
  â€¢ Run Androguard's AnalyzeAPK to build:
      â€“ The Analysis object  (methods, classes, cross-references)
      â€“ The global Control Flow Graph (CFG) as a NetworkX DiGraph
  â€¢ Cache the Analysis object to avoid redundant 30-90 second processing
  â€¢ Detect and flag dynamic DEX loading (DexClassLoader) for Frida handoff
Inputs:
  apk_path    : str  â€” path to the original .apk file
  extract_dir : str  â€” path produced by Stage A
Outputs:  (analysis, cfg_graph)
  analysis    : androguard.misc.AnalyzeAPK Analysis object
  cfg_graph   : networkx.DiGraph â€” method-level call graph
Algorithm:
  Androguard's AnalyzeAPK performs linear-sweep disassembly of Dalvik
  bytecode.  The resulting Analysis object exposes:
    analysis.get_classes()         â†’ all ClassAnalysis objects
    analysis.get_method()          â†’ all MethodAnalysis objects
    method.get_xref_to()           â†’ callers of this method
    method.get_xref_from()         â†’ callees of this method
  The CFG NetworkX graph has one node per method (string descriptor)
  and one directed edge per call (caller â†’ callee).
Edge Cases:
  â€¢ Multi-DEX APKs (classes2.dex, classes3.dex â€¦) â€” all loaded
  â€¢ Packed APKs with empty classes.dex â€” graceful degradation
  â€¢ DexClassLoader detected â€” flag for Frida dynamic extraction
"""
from __future__ import annotations
import logging
import os
import time
from pathlib import Path
from typing import Any,Optional
try:
    import networkx as nx 
except ImportError:
    nx=None 
from config.settings import ANDROGUARD_CACHE_DIR,ANDROGUARD_CACHE_ENABLED
logger=logging.getLogger(__name__)
class DEXDisassemblyError(Exception):
    """Raised when Stage B cannot disassemble the DEX bytecode."""
class DEXDisassembler:
    """
    Stage B: DEX Bytecode Disassembly and Smali Extraction.
    The returned `analysis` object is the primary Androguard handle used
    by Stages D, E, G, and H.  The `cfg` DiGraph is used by Stage D.
    Usage
    -----
    >>> stage = DEXDisassembler()
    >>> analysis, cfg = stage.run("/path/to/sample.apk")
    """
    STAGE_NAME="STAGE_B"
    
    DEX_CLASS_LOADER_SIG="dalvik/system/DexClassLoader;-><init>("
    def __init__(self)->None:
        if ANDROGUARD_CACHE_ENABLED:
            Path(ANDROGUARD_CACHE_DIR).mkdir(parents=True,exist_ok=True)
            try:
                os.chmod(ANDROGUARD_CACHE_DIR,0o700)
            except OSError:
                pass
    
    
    
    def run(self,apk_path:str)->tuple[Any,Any]:
        """
        Execute Stage B.
        Parameters
        ----------
        apk_path : str
            Absolute path to the .apk file.
        Returns
        -------
        analysis : androguard Analysis object
            Full bytecode analysis with cross-reference tables.
        cfg : networkx.DiGraph | None
            Method-level call graph.  None if NetworkX is unavailable.
        Raises
        ------
        DEXDisassemblyError
            If Androguard is not installed or all DEX files are empty.
        """
        t0=time.perf_counter()
        logger.info("[Stage B] Starting DEX disassembly: %s",apk_path)
        
        analysis,apk_obj,dex_list=self._run_androguard(apk_path)
        
        cfg=self._build_cfg(analysis)
        
        dynamic_loading=self._detect_dynamic_loading(analysis)
        if dynamic_loading:
            logger.warning(
                "[Stage B] DexClassLoader detected â€” APK uses dynamic DEX loading. "
                "Consider Frida hook for complete analysis."
            )
        
        elapsed_ms=(time.perf_counter()-t0)*1000
        method_count=sum(1 for _ in analysis.get_methods())
        class_count=sum(1 for _ in analysis.get_classes())
        logger.info(
            "[Stage B] Complete in %.1f ms | classes=%d | methods=%d",
            elapsed_ms,class_count,method_count,
        )
        return analysis,cfg
    
    
    
    def _run_androguard(self,apk_path:str)->tuple[Any,Any,list]:
        """
        Call Androguard's AnalyzeAPK on the given APK.
        Returns (Analysis, APK, list_of_DalvikVMFormat).
        """
        try:
            from androguard.misc import AnalyzeAPK 
        except ImportError as exc:
            raise DEXDisassemblyError(
                "Androguard is not installed. Run: pip install androguard==3.4.0"
            )from exc
        try:
            apk_obj,dex_list,analysis=AnalyzeAPK(apk_path)
        except Exception as exc:
            raise DEXDisassemblyError(
                f"Androguard AnalyzeAPK failed for {apk_path}: {exc}"
            )from exc
        if analysis is None:
            raise DEXDisassemblyError("Androguard returned None analysis â€” empty or invalid DEX")
        return analysis,apk_obj,dex_list
    
    
    
    def _build_cfg(self,analysis:Any)->Optional[Any]:
        """
        Construct a directed NetworkX graph where:
          â€¢ Each node  = method descriptor string  (class->method(signature))
          â€¢ Each edge  = call from caller to callee
        Node descriptor format mirrors Smali: "Lcom/example/Class;->method(Args)ReturnType"
        Performance note: For large APKs this can create 500K+ edges.
        We iterate Androguard's xref tables instead of re-parsing bytecode.
        """
        if nx is None:
            logger.warning("[Stage B] NetworkX not available â€” CFG will be None")
            return None
        cfg=nx.DiGraph()
        for method_analysis in analysis.get_methods():
            method_obj=method_analysis.method
            if not hasattr(method_obj,"get_class_name"):
                continue
            caller_desc=self._method_descriptor(method_analysis)
            cfg.add_node(caller_desc)
            
            for _,callee_method,_ in method_analysis.get_xref_to():
                if callee_method is None:
                    continue
                callee_desc=self._method_descriptor_from_method(callee_method)
                cfg.add_edge(caller_desc,callee_desc)
        logger.debug(
            "[Stage B] CFG built: %d nodes, %d edges",
            cfg.number_of_nodes(),cfg.number_of_edges()
        )
        return cfg
    
    
    
    def _detect_dynamic_loading(self,analysis:Any)->bool:
        """
        Check if any reachable method invokes DexClassLoader.<init>().
        This indicates dynamic DEX loading (packed payload, dropper).
        """
        for method_analysis in analysis.get_methods():
            for _,callee_method,_ in method_analysis.get_xref_to():
                if callee_method is None:
                    continue
                descriptor=(
                    f"{callee_method.get_class_name()}"
                    f"->{callee_method.get_name()}"
                    f"{callee_method.get_descriptor()}"
                )
                if self.DEX_CLASS_LOADER_SIG in descriptor:
                    return True
        return False
    
    
    
    def _cache_path(self,apk_path:str)->Path:
        """Deterministic cache file path based on full APK SHA-256."""
        sha256=_full_sha256(apk_path)
        return Path(ANDROGUARD_CACHE_DIR)/f"{sha256}.disabled"
    def _load_from_cache(self,apk_path:str)->Optional[tuple[Any,Any]]:
        """Unsafe pickle cache loading is intentionally disabled."""
        return None
    def _save_to_cache(self,apk_path:str,analysis:Any,cfg:Any)->None:
        """Unsafe pickle cache persistence is intentionally disabled."""
        return None    @staticmethod
    def _method_descriptor(method_analysis:Any)->str:
        """Build a canonical Smali-style method descriptor string."""
        m=method_analysis.method
        try:
            return f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"
        except Exception:
            return str(method_analysis)
    @staticmethod
    def _method_descriptor_from_method(method:Any)->str:
        """Build a descriptor from a raw Androguard Method (not MethodAnalysis)."""
        try:
            return f"{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}"
        except Exception:
            return str(method)
def _full_sha256(path:str)->str:
    """Hash the full APK for any future safe cache metadata key."""
    import hashlib
    h=hashlib.sha256()
    with open(path,"rb")as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


