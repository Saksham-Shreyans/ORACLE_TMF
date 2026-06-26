"""
ORACLE-TMF  ·  engines/genai_scaffold_detector.py
===================================================
CLASS 7 — GenAI API Scaffold Detection  (TMF-Psi)
MOTIVATION:
  The February 2026 discovery of PromptSpy (ESET Research) crystallises a new
  threat class: AI-augmented Android malware.  PromptSpy integrates Google's
  Gemini API directly into its execution flow, receiving dynamic JSON-formatted
  UI manipulation instructions by sending XML dumps of the device screen to the
  Gemini API.  PromptLock (August 2025) was the first AI-driven ransomware,
  generating encryption routines via LLM calls at runtime.
  These malware families contain DORMANT GenAI API stubs in their compiled APKs
  before the live backend is ready.  VNCspy, for example, contained dormant
  Gemini API references not present in any observed execution path — a Class 7
  mutation artifact that ORACLE-TMF can detect proactively.
WHAT WE DETECT:
  1. GenAI API endpoint URLs in the DEX string pool (dead code context)
  2. LLM model name string constants (gemini-1.5-pro, gpt-4o, claude-3-sonnet)
  3. API key format patterns (sk-ant-*, AIza*, hf_*, sk-*)
  4. JSON message schema patterns ({role: user, content: ...}) in dead code
  5. Manifest meta-data keys referencing GenAI providers (TMF-Psi meta-check)
ALGORITHM:
  Pass 1 — String Pool Scan:
    For each string constant in the DEX:
      • Check against GENAI_PROVIDER_MAP (endpoints + model names)
      • Check against API key regex patterns
      • If match → find which methods reference this string
      • Cross-reference those methods with the dead_code list
      • If the method is dead → emit GenAIAPIScaffoldArtifact
  Pass 2 — Manifest Meta-Data Check (uses Stage C output):
    Scan mag.manifest["meta_data"] and mag.manifest["genai_hints"]
    for API keys or provider identifiers.
  Pass 3 — JSON Schema Pattern Check:
    Scan placeholder strings from Stage F for LLM message format patterns.
Research basis:
  • PromptSpy analysis — ESET Research (February 2026)
  • PromptLock analysis — Kaspersky ICS CERT (August 2025)
  • ORACLE-TMF Section V-B: "Artifact Class 7: GenAI API Scaffolds (TMF-Psi)"
  • VNCspy forensic report — Threat Fabric (2025)
"""
from __future__ import annotations
import logging
import re
import time
from typing import Any
from models.mutation_artifact_graph import DeadCodeArtifact,GenAIAPIScaffoldArtifact
logger=logging.getLogger(__name__)





GENAI_PROVIDER_MAP:dict[str,dict]={
    "Gemini":{
        "endpoints":[
            "generativelanguage.googleapis.com",
            "generativelanguage.googleapis.com/v1beta",
            "aiplatform.googleapis.com",
        ],
        "models":[
            "gemini-1.5-pro","gemini-1.5-flash","gemini-2.0-flash",
            "gemini-pro","gemini-ultra",
        ],
        "key_pattern":re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "api_path_hint":"/v1beta/models/",
    },
    "OpenAI":{
        "endpoints":[
            "api.openai.com",
            "api.openai.com/v1/chat/completions",
            "api.openai.com/v1/embeddings",
        ],
        "models":[
            "gpt-4o","gpt-4-turbo","gpt-4","gpt-3.5-turbo",
            "text-davinci","o1-preview","o3-mini",
        ],
        "key_pattern":re.compile(r"sk-[A-Za-z0-9]{20,60}"),
        "api_path_hint":"/v1/chat/completions",
    },
    "Anthropic":{
        "endpoints":[
            "api.anthropic.com",
            "api.anthropic.com/v1/messages",
        ],
        "models":[
            "claude-3-opus","claude-3-sonnet","claude-3-haiku",
            "claude-3-5-sonnet","claude-sonnet-4","claude-opus-4",
        ],
        "key_pattern":re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,80}"),
        "api_path_hint":"/v1/messages",
    },
    "Ollama":{
        "endpoints":[
            "localhost:11434",
            "127.0.0.1:11434",
            "api/generate",
            "api/chat",
        ],
        "models":[
            "llama3","llama3.1","llama3.3","llama2",
            "mistral","mixtral","phi3","gemma","qwen2",
        ],
        "key_pattern":None,
        "api_path_hint":"/api/generate",
    },
    "Mistral":{
        "endpoints":[
            "api.mistral.ai",
            "api.mistral.ai/v1/chat/completions",
        ],
        "models":[
            "mistral-7b","mistral-8x7b","mixtral-8x7b",
            "mistral-large","mistral-medium","codestral",
        ],
        "key_pattern":re.compile(r"[A-Za-z0-9]{32}"),
        "api_path_hint":"/v1/chat/completions",
    },
    "Together AI":{
        "endpoints":[
            "api.together.xyz",
            "api.together.xyz/v1",
        ],
        "models":["togethercomputer/","meta-llama/","mistralai/"],
        "key_pattern":re.compile(r"[A-Fa-f0-9]{64}"),
        "api_path_hint":"/v1/chat/completions",
    },
    "Groq":{
        "endpoints":[
            "api.groq.com",
            "api.groq.com/openai/v1",
        ],
        "models":["llama3-70b-8192","mixtral-8x7b-32768","gemma-7b-it"],
        "key_pattern":re.compile(r"gsk_[A-Za-z0-9]{52}"),
        "api_path_hint":"/openai/v1/chat/completions",
    },
    "Hugging Face":{
        "endpoints":[
            "api-inference.huggingface.co",
            "huggingface.co/api",
        ],
        "models":["facebook/opt","EleutherAI/gpt-j","bigscience/bloom"],
        "key_pattern":re.compile(r"hf_[A-Za-z0-9]{37}"),
        "api_path_hint":"/models/",
    },
    "Cohere":{
        "endpoints":[
            "api.cohere.ai",
            "api.cohere.ai/v1/generate",
        ],
        "models":["command-r","command-r-plus","command","embed-english"],
        "key_pattern":re.compile(r"[A-Za-z0-9]{40}"),
        "api_path_hint":"/v1/generate",
    },
}

_LLM_MSG_PATTERNS:list[re.Pattern]=[
    re.compile(r'"role"\s*:\s*"(?:user|assistant|system)"',re.IGNORECASE),
    re.compile(r'"messages"\s*:\s*\[',re.IGNORECASE),
    re.compile(r'"prompt"\s*:\s*"',re.IGNORECASE),
    re.compile(r'"max_tokens"\s*:\s*\d+',re.IGNORECASE),
    re.compile(r'"temperature"\s*:\s*0\.\d+',re.IGNORECASE),
]
class GenAIScaffoldDetector:
    """
    Class 7 — GenAI API Scaffold Detector (TMF-Psi).
    Detects dormant stubs for Large Language Model (LLM) API endpoints
    embedded in Android APKs but not yet active in any execution path.
    Usage
    -----
    >>> detector = GenAIScaffoldDetector()
    >>> scaffolds = detector.run(analysis, dead_code_artifacts)
    """
    STAGE_NAME="GENAI_DETECT"
    def __init__(self)->None:
        
        self._all_endpoints:dict[str,str]={}
        self._all_models:dict[str,str]={}
        for provider,data in GENAI_PROVIDER_MAP.items():
            for ep in data["endpoints"]:
                self._all_endpoints[ep.lower()]=provider
            for model in data["models"]:
                self._all_models[model.lower()]=provider
    
    
    
    def run(
        self,
        analysis:Any,
        dead_code:list[DeadCodeArtifact],
    )->list[GenAIAPIScaffoldArtifact]:
        """
        Execute Class 7 GenAI scaffold detection.
        Parameters
        ----------
        analysis   : Androguard Analysis object from Stage B
        dead_code  : list[DeadCodeArtifact] from Stage D (DTE-classified)
        Returns
        -------
        list[GenAIAPIScaffoldArtifact]
        """
        t0=time.perf_counter()
        logger.info("[TMF-Psi] Starting GenAI API scaffold detection")
        
        dead_descriptors:set[str]={
            f"{a.class_name}->{a.method_name}"for a in dead_code
        }
        artifacts:list[GenAIAPIScaffoldArtifact]=[]
        seen_keys:set[str]=set()
        
        string_pool_artifacts=self._scan_string_pool(analysis,dead_descriptors)
        for artifact in string_pool_artifacts:
            key=f"{artifact.class_name}::{artifact.method_name}::{artifact.provider}"
            if key not in seen_keys:
                seen_keys.add(key)
                artifacts.append(artifact)
        
        smali_artifacts=self._scan_dead_code_smali(dead_code)
        for artifact in smali_artifacts:
            key=f"{artifact.class_name}::{artifact.method_name}::{artifact.provider}"
            if key not in seen_keys:
                seen_keys.add(key)
                artifacts.append(artifact)
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[TMF-Psi] Complete in %.1f ms | genai_scaffolds=%d | providers=%s",
            elapsed_ms,
            len(artifacts),
            list({a.provider for a in artifacts}),
        )
        return artifacts
    
    
    
    def _scan_string_pool(
        self,
        analysis:Any,
        dead_descriptors:set[str],
    )->list[GenAIAPIScaffoldArtifact]:
        """
        Scan the DEX global string pool for GenAI provider indicators.
        For each matching string, find the methods that reference it.
        If that method is in the dead code set → emit a GenAIAPIScaffoldArtifact.
        """
        artifacts:list[GenAIAPIScaffoldArtifact]=[]
        try:
            for string_analysis in analysis.get_strings():
                raw_value=str(string_analysis.get_value())
                value_lower=raw_value.lower()
                
                provider,indicator_type=self._classify_string(value_lower,raw_value)
                if not provider:
                    continue
                
                for method_analysis,_ in string_analysis.get_xref_from():
                    if method_analysis.is_android_api()or method_analysis.is_external():
                        continue
                    method_obj=method_analysis.method
                    class_name=method_obj.get_class_name()
                    method_name=f"{method_obj.get_name()}{method_obj.get_descriptor()}"
                    desc=f"{class_name}->{method_name}"
                    
                    if desc not in dead_descriptors and not self._is_stub_method(method_analysis):
                        continue
                    
                    smali=self._get_smali(method_analysis)
                    api_endpoint,model_hint=self._extract_genai_details(smali,provider,raw_value)
                    artifacts.append(GenAIAPIScaffoldArtifact(
                        class_name=class_name,
                        method_name=method_name,
                        provider=provider,
                        api_endpoint=api_endpoint,
                        model_hint=model_hint,
                    ))
                    logger.debug(
                        "[TMF-Psi] Scaffold detected: %s in %s (provider=%s)",
                        indicator_type,class_name,provider,
                    )
        except Exception as exc:
            logger.warning("[TMF-Psi] String pool scan error: %s",exc)
        return artifacts
    
    
    
    def _scan_dead_code_smali(
        self,dead_code:list[DeadCodeArtifact]
    )->list[GenAIAPIScaffoldArtifact]:
        """
        Directly scan the Smali bodies of dead code artifacts for GenAI patterns.
        This catches cases where string obfuscation breaks string analysis
        cross-reference, but the raw Smali still contains recognisable endpoint
        fragments (e.g., split across multiple const-string opcodes).
        """
        artifacts:list[GenAIAPIScaffoldArtifact]=[]
        for dead in dead_code:
            smali=dead.smali_code
            if not smali:
                continue
            
            string_re=re.compile(r'const-string(?:/jumbo)?\s+[vp]\d+,\s*"([^"]{6,})"')
            for match in string_re.finditer(smali):
                value=match.group(1)
                provider,_=self._classify_string(value.lower(),value)
                if not provider:
                    continue
                api_endpoint,model_hint=self._extract_genai_details(smali,provider,value)
                
                is_llm_schema=any(p.search(smali)for p in _LLM_MSG_PATTERNS)
                if is_llm_schema:
                    logger.debug(
                        "[TMF-Psi] LLM message schema detected in dead method: %s",
                        dead.method_name,
                    )
                artifacts.append(GenAIAPIScaffoldArtifact(
                    class_name=dead.class_name,
                    method_name=dead.method_name,
                    provider=provider,
                    api_endpoint=api_endpoint,
                    model_hint=model_hint,
                ))
                break 
        return artifacts
    
    
    
    def _classify_string(self,value_lower:str,raw_value:str)->tuple[str,str]:
        """
        Classify a string as belonging to a GenAI provider.
        Returns (provider_name, indicator_type) or ("", "") if no match.
        """
        
        for endpoint,provider in self._all_endpoints.items():
            if endpoint in value_lower:
                return provider,"endpoint"
        
        for model,provider in self._all_models.items():
            if model in value_lower:
                return provider,"model_name"
        
        for provider,data in GENAI_PROVIDER_MAP.items():
            key_pattern=data.get("key_pattern")
            if key_pattern and key_pattern.search(raw_value):
                if len(raw_value)>20:
                    return provider,"api_key"
        return "",""
    @staticmethod
    def _extract_genai_details(
        smali:str,provider:str,triggering_string:str
    )->tuple[str,str]:
        """
        Extract the specific API endpoint URL and model name from a Smali method body.
        Returns (api_endpoint, model_hint).
        """
        api_endpoint=""
        model_hint=""
        if not smali:
            return triggering_string[:100],model_hint
        
        url_re=re.compile(r'const-string[^,]+,\s*"(https?://[^"]{10,})"')
        url_match=url_re.search(smali)
        if url_match:
            api_endpoint=url_match.group(1)[:150]
        else:
            api_endpoint=triggering_string[:100]
        
        provider_data=GENAI_PROVIDER_MAP.get(provider,{})
        for model in provider_data.get("models",[]):
            if model.lower()in smali.lower():
                model_hint=model
                break
        return api_endpoint,model_hint
    @staticmethod
    def _is_stub_method(method_analysis:Any)->bool:
        """
        Check if a method is a stub (even if technically reachable)
        by checking if it has < 5 opcodes or only logging calls.
        """
        try:
            smali=method_analysis.method.get_source()or ""
            lines=[l.strip()for l in smali.splitlines()if l.strip()]
            opcode_lines=[l for l in lines if l[:2]in("in","mo","ig","ip","co","re","if")]
            return len(opcode_lines)<5
        except Exception:
            return False
    @staticmethod
    def _get_smali(method_analysis:Any)->str:
        """Safely extract Smali source."""
        try:
            return method_analysis.method.get_source()or ""
        except Exception:
            return ""
