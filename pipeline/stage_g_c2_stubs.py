"""
ORACLE-TMF  ·  pipeline/stage_g_c2_stubs.py
============================================
STAGE G — C2 Endpoint Stub and Network Scaffold Detection
Responsibility:
  • Identify classes/methods that initialise HTTP network clients
    (OkHttpClient, Retrofit, HttpURLConnection) without ever calling
    the terminal execution methods (.execute(), .enqueue(), .getOutputStream())
  • Extract the URL/path/schema from dormant Retrofit @GET/@POST annotations
    or from const-string opcodes adjacent to the network client
  • Return a list of C2EndpointStubArtifact objects
Inputs:
  dead_methods : list[DeadCodeArtifact] — output of Stage D
  analysis     : Androguard Analysis object — for full class-level scanning
Outputs: list[C2EndpointStubArtifact]
Algorithm:
  For every dead-code method body (Smali):
    1. Check if the Smali contains any NETWORK_CLIENT_CLASSES signature
    2. If yes, check whether any NETWORK_TERMINAL_METHODS appear in the
       SAME method body or in the call chain
    3. If terminal methods are ABSENT → this is an unexecuted network scaffold (C2 stub)
    4. Extract URL/path from const-string opcodes or annotation metadata
  Additionally, scan ALL Smali methods (not just dead code) for C2 URL
  patterns extracted in Stage F (placeholder_strings) that appear in
  network client contexts.
"""
from __future__ import annotations
import logging
import re
import time
from typing import Any
from config.settings import(
    NETWORK_CLIENT_CLASSES,
    NETWORK_TERMINAL_METHODS,
)
from models.mutation_artifact_graph import C2EndpointStubArtifact,DeadCodeArtifact
logger=logging.getLogger(__name__)

_HTTP_METHOD_RE=re.compile(
    r'const-string[^,]+,\s*"((?:GET|POST|PUT|DELETE|PATCH|HEAD)\b[^"]*)"',
    re.IGNORECASE,
)

_URL_RE=re.compile(
    r'const-string[^,]+,\s*"((?:https?://|/api/|/v\d+/|/drop|/upload|/exfil|'
    r'/collect|/cmd|/bot|/panel)[^"]{3,})"',
    re.IGNORECASE,
)

_IP_PORT_RE=re.compile(
    r'const-string[^,]+,\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?)"'
)
class C2StubDetector:
    """
    Stage G: C2 Endpoint Stub and Network Scaffold Detection.
    Usage
    -----
    >>> stage = C2StubDetector()
    >>> stubs = stage.run(dead_methods, analysis)
    """
    STAGE_NAME="STAGE_G"
    def __init__(self)->None:
        
        self._client_patterns=[
            re.compile(re.escape(cls),re.IGNORECASE)
            for cls in NETWORK_CLIENT_CLASSES
        ]
        self._terminal_patterns=[
            re.compile(re.escape(term),re.IGNORECASE)
            for term in NETWORK_TERMINAL_METHODS
        ]
    
    
    
    def run(
        self,
        dead_methods:list[DeadCodeArtifact],
        analysis:Any,
    )->list[C2EndpointStubArtifact]:
        """
        Execute Stage G.
        Parameters
        ----------
        dead_methods : list[DeadCodeArtifact] from Stage D
        analysis     : Androguard Analysis object from Stage B
        Returns
        -------
        list[C2EndpointStubArtifact]
        """
        t0=time.perf_counter()
        logger.info("[Stage G] Starting C2 stub and network scaffold detection")
        stubs:list[C2EndpointStubArtifact]=[]
        
        for dead in dead_methods:
            artifact=self._check_dead_method(dead)
            if artifact is not None:
                stubs.append(artifact)
        
        
        stubs.extend(self._scan_all_methods(analysis,already_found={
            s.class_name+s.method_name for s in stubs
        }))
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage G] Complete in %.1f ms | c2_stubs=%d",
            elapsed_ms,len(stubs),
        )
        return stubs
    
    
    
    def _check_dead_method(
        self,dead:DeadCodeArtifact
    )->C2EndpointStubArtifact|None:
        """
        Check if a single dead-code method body contains a network client
        without any terminal execution call.
        """
        smali=dead.smali_code
        if not smali:
            return None
        
        framework=self._detect_network_client(smali)
        if not framework:
            return None
        
        if self._has_terminal_method(smali):
            
            return None
        
        url=self._extract_url(smali)
        http_method=self._extract_http_method(smali)
        schema=self._extract_payload_schema(smali)
        return C2EndpointStubArtifact(
            class_name=dead.class_name,
            method_name=dead.method_name,
            framework=framework,
            extracted_url=url,
            http_method=http_method,
            payload_schema=schema,
        )
    
    
    
    def _scan_all_methods(
        self,analysis:Any,already_found:set[str]
    )->list[C2EndpointStubArtifact]:
        """
        Scan ALL methods in the DEX for network scaffolds that were not
        caught in Pass 1 (e.g., reachable but gated methods).
        """
        stubs:list[C2EndpointStubArtifact]=[]
        try:
            for method_analysis in analysis.get_methods():
                if method_analysis.is_android_api()or method_analysis.is_external():
                    continue
                method_obj=method_analysis.method
                class_name=method_obj.get_class_name()
                method_name=f"{method_obj.get_name()}{method_obj.get_descriptor()}"
                key=class_name+method_name
                if key in already_found:
                    continue
                smali=self._get_smali(method_analysis)
                if not smali:
                    continue
                framework=self._detect_network_client(smali)
                if not framework:
                    continue
                if self._has_terminal_method(smali):
                    continue
                url=self._extract_url(smali)
                http_method=self._extract_http_method(smali)
                schema=self._extract_payload_schema(smali)
                
                if url or http_method:
                    stubs.append(C2EndpointStubArtifact(
                        class_name=class_name,
                        method_name=method_name,
                        framework=framework,
                        extracted_url=url,
                        http_method=http_method,
                        payload_schema=schema,
                    ))
        except Exception as exc:
            logger.warning("[Stage G] Full method scan error: %s",exc)
        return stubs
    
    
    
    def _detect_network_client(self,smali:str)->str:
        """
        Return the first network client framework name found in the Smali code,
        or empty string if none is found.
        """
        for pattern,class_name in zip(self._client_patterns,NETWORK_CLIENT_CLASSES):
            if pattern.search(smali):
                
                parts=class_name.split("/")
                return parts[-1].rstrip(";")if parts else class_name
        return ""
    def _has_terminal_method(self,smali:str)->bool:
        """
        Return True if any NETWORK_TERMINAL_METHODS signature appears in
        the Smali code — meaning the network request actually fires.
        """
        return any(p.search(smali)for p in self._terminal_patterns)
    @staticmethod
    def _extract_url(smali:str)->str:
        """Extract the first URL or API path from const-string opcodes."""
        match=_URL_RE.search(smali)
        if match:
            return match.group(1)
        
        match=_IP_PORT_RE.search(smali)
        return match.group(1)if match else ""
    @staticmethod
    def _extract_http_method(smali:str)->str:
        """Extract HTTP method string (GET/POST/PUT etc.) from Smali annotations."""
        match=_HTTP_METHOD_RE.search(smali)
        return match.group(1)if match else ""
    @staticmethod
    def _extract_payload_schema(smali:str)->str:
        """
        Attempt to extract a JSON schema hint from empty JSON literals or
        placeholder schema strings in the method's string constants.
        """
        schema_re=re.compile(
            r'const-string[^,]+,\s*"(\{[^"]{0,200}\})"'
        )
        match=schema_re.search(smali)
        if match:
            candidate=match.group(1)
            
            if '""'in candidate or "null"in candidate.lower():
                return candidate[:200]
        return ""
    @staticmethod
    def _get_smali(method_analysis:Any)->str:
        """Extract Smali source from a MethodAnalysis object."""
        try:
            src=method_analysis.method.get_source()
            return src if src else ""
        except Exception:
            return ""
