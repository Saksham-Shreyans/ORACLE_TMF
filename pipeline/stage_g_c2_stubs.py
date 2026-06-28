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
        for pattern,class_name in zip(self._client_patterns,NETWORK_CLIENT_CLASSES):
            if pattern.search(smali):
                parts=class_name.split("/")
                return parts[-1].rstrip(";")if parts else class_name
        return ""
    def _has_terminal_method(self,smali:str)->bool:
        return any(p.search(smali)for p in self._terminal_patterns)
    @staticmethod
    def _extract_url(smali:str)->str:
        match=_URL_RE.search(smali)
        if match:
            return match.group(1)
        match=_IP_PORT_RE.search(smali)
        return match.group(1)if match else ""
    @staticmethod
    def _extract_http_method(smali:str)->str:
        match=_HTTP_METHOD_RE.search(smali)
        return match.group(1)if match else ""
    @staticmethod
    def _extract_payload_schema(smali:str)->str:
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
        try:
            src=method_analysis.method.get_source()
            return src if src else ""
        except Exception:
            return ""
