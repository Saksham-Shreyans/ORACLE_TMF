"""
ORACLE-TMF  ·  pipeline/stage_c_manifest_parser.py
====================================================
STAGE C — AndroidManifest.xml Deep Parsing
Responsibility:
  • Decompress the binary AXML-encoded AndroidManifest.xml using Androguard
  • Extract: declared permissions, activities, services, receivers, providers
  • Extract: intent filters, exported components, min/target SDK
  • Detect GenAI API keys or identifiers in meta-data elements (TMF-Psi)
  • Return a structured dict that is stored in MAG.manifest
Inputs:  apk_path (str)
Outputs: manifest dict (stored in MAG.manifest)
Algorithm:
  Androguard's APK object uses its internal AXMLPrinter to decompress
  the binary AndroidManifest.xml (AXML format) and exposes high-level
  getter methods.  We call these methods rather than parsing raw XML.
"""
from __future__ import annotations
import logging
import re
import time
from typing import Any
logger=logging.getLogger(__name__)
class ManifestParseError(Exception):
    """Raised when Stage C cannot parse the AndroidManifest.xml."""
class ManifestParser:
    """
    Stage C: AndroidManifest.xml Deep Parsing.
    Usage
    -----
    >>> stage = ManifestParser()
    >>> manifest = stage.run("/path/to/sample.apk")
    """
    STAGE_NAME="STAGE_C"
    
    GENAI_META_KEY_PATTERNS:tuple[str,...]=(
        r"(?i)gemini",
        r"(?i)openai",
        r"(?i)anthropic",
        r"(?i)gpt[_\-]?(?:4|3|turbo)",
        r"(?i)ollama",
        r"(?i)mistral",
        r"(?i)llm[_\-]?api",
        r"(?i)palm[_\-]?api",
    )
    def __init__(self)->None:
        self._genai_patterns=[
            re.compile(p)for p in self.GENAI_META_KEY_PATTERNS
        ]
    
    
    
    def run(self,apk_path:str)->dict:
        """
        Execute Stage C.
        Parameters
        ----------
        apk_path : str
            Absolute path to the .apk file.
        Returns
        -------
        manifest : dict
            Structured manifest data.  Schema:
            {
              "package_name":  str,
              "permissions":   [str, ...],
              "activities":    [{"name": str, "exported": bool, "intent_filters": [...]}],
              "services":      [{"name": str, "exported": bool}],
              "receivers":     [{"name": str, "exported": bool}],
              "providers":     [{"name": str, "exported": bool}],
              "meta_data":     {key: value},
              "min_sdk":       int,
              "target_sdk":    int,
              "genai_hints":   [str],   # TMF-Psi: any GenAI meta-data detected
            }
        Raises
        ------
        ManifestParseError
            If Androguard fails to parse the manifest.
        """
        t0=time.perf_counter()
        logger.info("[Stage C] Parsing AndroidManifest.xml from: %s",apk_path)
        apk_obj=self._load_apk(apk_path)
        manifest=self._extract_manifest(apk_obj)
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage C] Complete in %.1f ms | permissions=%d | activities=%d | "
            "services=%d | receivers=%d",
            elapsed_ms,
            len(manifest["permissions"]),
            len(manifest["activities"]),
            len(manifest["services"]),
            len(manifest["receivers"]),
        )
        return manifest
    
    
    
    def _load_apk(self,apk_path:str)->Any:
        """Load the APK with Androguard's APK class."""
        try:
            from androguard.core.bytecodes.apk import APK 
            return APK(apk_path)
        except ImportError as exc:
            raise ManifestParseError(
                "Androguard not installed. Run: pip install androguard==3.4.0"
            )from exc
        except Exception as exc:
            raise ManifestParseError(
                f"Failed to load APK for manifest parsing: {exc}"
            )from exc
    
    
    
    def _extract_manifest(self,apk:Any)->dict:
        """Extract all manifest fields from the Androguard APK object."""
        manifest:dict={
            "package_name":self._safe(apk.get_package),
            "permissions":self._extract_permissions(apk),
            "activities":self._extract_activities(apk),
            "services":self._extract_services(apk),
            "receivers":self._extract_receivers(apk),
            "providers":self._extract_providers(apk),
            "meta_data":self._extract_meta_data(apk),
            "min_sdk":self._safe_int(apk.get_min_sdk_version),
            "target_sdk":self._safe_int(apk.get_target_sdk_version),
            "version_name":self._safe(apk.get_androidversion_name),
            "version_code":self._safe(apk.get_androidversion_code),
            "genai_hints":[],
        }
        manifest["genai_hints"]=self._detect_genai_hints(manifest)
        return manifest
    def _extract_permissions(self,apk:Any)->list[str]:
        """Extract all <uses-permission> entries."""
        try:
            perms=apk.get_permissions()
            return sorted(set(str(p)for p in perms))if perms else[]
        except Exception as exc:
            logger.debug("[Stage C] Permission extraction failed: %s",exc)
            return[]
    def _extract_activities(self,apk:Any)->list[dict]:
        """Extract <activity> components with intent filters."""
        activities=[]
        try:
            for name in apk.get_activities():
                exported=self._is_exported(apk,name,"activity")
                filters=self._get_intent_filters(apk,name,"activity")
                activities.append({
                    "name":str(name),
                    "exported":exported,
                    "intent_filters":filters,
                })
        except Exception as exc:
            logger.debug("[Stage C] Activity extraction failed: %s",exc)
        return activities
    def _extract_services(self,apk:Any)->list[dict]:
        """Extract <service> components."""
        services=[]
        try:
            for name in apk.get_services():
                services.append({
                    "name":str(name),
                    "exported":self._is_exported(apk,name,"service"),
                })
        except Exception as exc:
            logger.debug("[Stage C] Service extraction failed: %s",exc)
        return services
    def _extract_receivers(self,apk:Any)->list[dict]:
        """Extract <receiver> components."""
        receivers=[]
        try:
            for name in apk.get_receivers():
                receivers.append({
                    "name":str(name),
                    "exported":self._is_exported(apk,name,"receiver"),
                })
        except Exception as exc:
            logger.debug("[Stage C] Receiver extraction failed: %s",exc)
        return receivers
    def _extract_providers(self,apk:Any)->list[dict]:
        """Extract <provider> components."""
        providers=[]
        try:
            for name in apk.get_providers():
                providers.append({
                    "name":str(name),
                    "exported":self._is_exported(apk,name,"provider"),
                })
        except Exception as exc:
            logger.debug("[Stage C] Provider extraction failed: %s",exc)
        return providers
    def _extract_meta_data(self,apk:Any)->dict:
        """
        Extract <meta-data> key-value pairs from the application element.
        These often contain API keys, configuration flags, or library tokens.
        """
        meta:dict={}
        try:
            
            
            xml_str=apk.get_android_manifest_axml().get_xml()
            if xml_str:
                xml_text=xml_str.decode("utf-8",errors="replace")if isinstance(xml_str,bytes)else xml_str
                pattern=re.compile(
                    r'<meta-data[^>]+android:name="([^"]*)"[^>]+android:value="([^"]*)"',
                    re.DOTALL,
                )
                for match in pattern.finditer(xml_text):
                    meta[match.group(1)]=match.group(2)
        except Exception as exc:
            logger.debug("[Stage C] Meta-data extraction failed: %s",exc)
        return meta
    def _detect_genai_hints(self,manifest:dict)->list[str]:
        """
        TMF-Psi: Scan meta-data keys/values and permission strings for
        references to GenAI APIs.  Returns a list of hint strings.
        """
        hints:list[str]=[]
        meta=manifest.get("meta_data",{})
        for key,value in meta.items():
            combined=f"{key}={value}"
            for pattern in self._genai_patterns:
                if pattern.search(combined):
                    hints.append(combined)
                    break
        return hints
    
    
    
    @staticmethod
    def _is_exported(apk:Any,component_name:str,comp_type:str)->bool:
        """
        Determine if a component is exported.
        An exported component is accessible from other apps and is an
        attack surface for inter-component communication (ICC) exploits.
        """
        try:
            
            manifest_xml=apk.get_android_manifest_axml().get_xml()
            if not manifest_xml:
                return False
            xml_text=manifest_xml.decode("utf-8",errors="replace")if isinstance(manifest_xml,bytes)else manifest_xml
            short_name=component_name.split(".")[-1]
            exported_pattern=re.compile(
                rf'<{comp_type}[^>]*(?:{re.escape(component_name)}|{re.escape(short_name)})'
                rf'[^>]*android:exported="true"',
                re.DOTALL|re.IGNORECASE,
            )
            return bool(exported_pattern.search(xml_text))
        except Exception:
            return False
    @staticmethod
    def _get_intent_filters(apk:Any,component_name:str,comp_type:str)->list[dict]:
        """Extract intent filter action/category lists for a given component."""
        filters:list[dict]=[]
        try:
            xml_bytes=apk.get_android_manifest_axml().get_xml()
            if not xml_bytes:
                return filters
            xml_text=xml_bytes.decode("utf-8",errors="replace")if isinstance(xml_bytes,bytes)else xml_bytes
            
            short_name=component_name.split(".")[-1]
            block_re=re.compile(
                rf'<{comp_type}[^>]*(?:{re.escape(component_name)}|{re.escape(short_name)})'
                rf'.*?</{comp_type}>',
                re.DOTALL|re.IGNORECASE,
            )
            block_match=block_re.search(xml_text)
            if not block_match:
                return filters
            block=block_match.group(0)
            action_re=re.compile(r'android:name="(android\.intent\.[^"]*)"')
            category_re=re.compile(r'android:name="(android\.intent\.category\.[^"]*)"')
            actions=action_re.findall(block)
            categories=category_re.findall(block)
            if actions or categories:
                filters.append({"actions":actions,"categories":categories})
        except Exception:
            pass
        return filters
    @staticmethod
    def _safe(getter)->str:
        """Call a getter, return empty string on any exception."""
        try:
            result=getter()
            return str(result)if result is not None else ""
        except Exception:
            return ""
    @staticmethod
    def _safe_int(getter)->int:
        """Call a getter that should return an int."""
        try:
            result=getter()
            return int(result)if result is not None else 0
        except Exception:
            return 0
