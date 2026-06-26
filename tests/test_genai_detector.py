"""
ORACLE-TMF  ·  tests/test_genai_detector.py
=============================================
Unit tests for the GenAI API Scaffold Detector (Class 7 / TMF-Psi).
Tests cover:
  • Provider detection accuracy for all 9 tracked providers
  • Endpoint string classification
  • Model name string classification
  • API key pattern matching (Gemini, OpenAI, Anthropic, Groq, HuggingFace)
  • Dead code Smali scanning for obfuscated references
  • LLM message schema pattern matching
  • Empty / edge-case handling
  • Deduplication across passes
Does NOT require Androguard — tests use mock objects and direct method calls.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest

PROJECT_ROOT=str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0,PROJECT_ROOT)
from engines.genai_scaffold_detector import(
    GENAI_PROVIDER_MAP,
    GenAIScaffoldDetector,
    _LLM_MSG_PATTERNS,
)
from models.mutation_artifact_graph import DeadCodeArtifact,DTEClass



@pytest.fixture(scope="module")
def detector():
    """Shared detector instance."""
    return GenAIScaffoldDetector()
def _make_dead_code(
    smali:str="",
    class_name:str="Lcom/malware/GenAIHelper;",
    method_name:str="callLLM()V",
)->DeadCodeArtifact:
    """Factory for dead code artifacts with given Smali body."""
    return DeadCodeArtifact(
        class_name=class_name,
        method_name=method_name,
        smali_code=smali,
        opcode_count=30,
        dte_label=DTEClass.SCAFFOLDING,
        dte_confidence=0.85,
    )



class TestProviderMap:
    """Validate the GENAI_PROVIDER_MAP is well-structured."""
    def test_all_providers_have_endpoints(self):
        for provider,data in GENAI_PROVIDER_MAP.items():
            assert "endpoints"in data,f"{provider} missing 'endpoints'"
            assert len(data["endpoints"])>0,f"{provider} has empty endpoints"
    def test_all_providers_have_models(self):
        for provider,data in GENAI_PROVIDER_MAP.items():
            assert "models"in data,f"{provider} missing 'models'"
            assert len(data["models"])>0,f"{provider} has empty models"
    def test_key_pattern_is_regex_or_none(self):
        for provider,data in GENAI_PROVIDER_MAP.items():
            pattern=data.get("key_pattern")
            assert pattern is None or isinstance(pattern,re.Pattern),(
                f"{provider} key_pattern is not a regex or None"
            )
    def test_expected_providers_present(self):
        expected={"Gemini","OpenAI","Anthropic","Ollama","Mistral"}
        actual=set(GENAI_PROVIDER_MAP.keys())
        assert expected.issubset(actual),f"Missing providers: {expected-actual}"



class TestStringClassification:
    """Test _classify_string() for endpoint, model, and API key detection."""
    def test_gemini_endpoint(self,detector):
        provider,kind=detector._classify_string(
            "generativelanguage.googleapis.com/v1beta/models/gemini-pro:generatecontent",
            "generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
        )
        assert provider=="Gemini"
        assert kind=="endpoint"
    def test_openai_endpoint(self,detector):
        provider,kind=detector._classify_string(
            "api.openai.com/v1/chat/completions","api.openai.com/v1/chat/completions"
        )
        assert provider=="OpenAI"
        assert kind=="endpoint"
    def test_anthropic_endpoint(self,detector):
        provider,kind=detector._classify_string(
            "api.anthropic.com/v1/messages","api.anthropic.com/v1/messages"
        )
        assert provider=="Anthropic"
        assert kind=="endpoint"
    def test_ollama_endpoint(self,detector):
        provider,kind=detector._classify_string(
            "localhost:11434","localhost:11434"
        )
        assert provider=="Ollama"
        assert kind=="endpoint"
    def test_model_name_gpt4o(self,detector):
        provider,kind=detector._classify_string("gpt-4o","gpt-4o")
        assert provider=="OpenAI"
        assert kind=="model_name"
    def test_model_name_gemini_flash(self,detector):
        provider,kind=detector._classify_string(
            "gemini-2.0-flash","gemini-2.0-flash"
        )
        assert provider=="Gemini"
        assert kind=="model_name"
    def test_model_name_claude(self,detector):
        provider,kind=detector._classify_string(
            "claude-3-sonnet","claude-3-sonnet"
        )
        assert provider=="Anthropic"
        assert kind=="model_name"
    def test_no_match_returns_empty(self,detector):
        provider,kind=detector._classify_string(
            "just a normal string with nothing special","just a normal string"
        )
        assert provider==""
        assert kind==""
    def test_api_key_gemini(self,detector):
        fake_key="AIza"+"a"*35
        provider,kind=detector._classify_string(fake_key.lower(),fake_key)
        assert provider=="Gemini"
        assert kind=="api_key"
    def test_api_key_anthropic(self,detector):
        fake_key="sk-ant-"+"x"*40
        provider,kind=detector._classify_string(fake_key.lower(),fake_key)
        assert provider=="Anthropic"
        assert kind=="api_key"



class TestDeadCodeSmaliScan:
    """Test _scan_dead_code_smali() — Pass 2."""
    def test_detect_gemini_in_smali(self,detector):
        fake_key = "AIza" + "SyFakeKeyNotReal1234567890123456789"
        smali='''
.method public callGemini()V
    .locals 2
    const-string v0, "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
    const-string v1, "''' + fake_key + '''"
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    return-void
.end method
'''
        dead=[_make_dead_code(smali=smali)]
        artifacts=detector._scan_dead_code_smali(dead)
        assert len(artifacts)==1
        assert artifacts[0].provider=="Gemini"
        assert "gemini-1.5-pro"in artifacts[0].model_hint
    def test_detect_openai_in_smali(self,detector):
        smali='''
.method private initOpenAI()V
    .locals 1
    const-string v0, "api.openai.com/v1/chat/completions"
    return-void
.end method
'''
        dead=[_make_dead_code(smali=smali,method_name="initOpenAI()V")]
        artifacts=detector._scan_dead_code_smali(dead)
        assert len(artifacts)==1
        assert artifacts[0].provider=="OpenAI"
    def test_no_detection_on_clean_smali(self,detector):
        smali='''
.method public onCreate()V
    .locals 1
    const-string v0, "Hello, World!"
    invoke-virtual {v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    return-void
.end method
'''
        dead=[_make_dead_code(smali=smali)]
        artifacts=detector._scan_dead_code_smali(dead)
        assert len(artifacts)==0
    def test_empty_smali_no_crash(self,detector):
        dead=[_make_dead_code(smali="")]
        artifacts=detector._scan_dead_code_smali(dead)
        assert len(artifacts)==0
    def test_dedup_per_method(self,detector):
        """Multiple GenAI strings in the same method should yield only 1 artifact."""
        smali='''
.method public dualLLM()V
    .locals 2
    const-string v0, "api.openai.com/v1/chat/completions"
    const-string v1, "api.anthropic.com/v1/messages"
    return-void
.end method
'''
        dead=[_make_dead_code(smali=smali)]
        artifacts=detector._scan_dead_code_smali(dead)
        
        assert len(artifacts)==1



class TestLLMSchemaPatterns:
    """Test the regex patterns that detect structured LLM prompting code."""
    def test_role_user_pattern(self):
        text='{"role": "user", "content": "What is 2+2?"}'
        assert any(p.search(text)for p in _LLM_MSG_PATTERNS)
    def test_messages_array_pattern(self):
        text='{"messages": [{"role": "system", "content": "You are helpful"}]}'
        assert any(p.search(text)for p in _LLM_MSG_PATTERNS)
    def test_max_tokens_pattern(self):
        text='{"max_tokens": 4096}'
        assert any(p.search(text)for p in _LLM_MSG_PATTERNS)
    def test_temperature_pattern(self):
        text='{"temperature": 0.7}'
        assert any(p.search(text)for p in _LLM_MSG_PATTERNS)
    def test_no_false_positive_on_normal_json(self):
        text='{"name": "John", "age": 30}'
        assert not any(p.search(text)for p in _LLM_MSG_PATTERNS)



class TestDetailExtraction:
    """Test _extract_genai_details() for URL and model hint extraction."""
    def test_extract_url_from_smali(self):
        smali='const-string v0, "https://api.openai.com/v1/chat/completions"'
        endpoint,model=GenAIScaffoldDetector._extract_genai_details(
            smali,"OpenAI","api.openai.com"
        )
        assert "https://api.openai.com"in endpoint
    def test_extract_model_hint(self):
        smali='''
const-string v0, "https://generativelanguage.googleapis.com/v1beta"
const-string v1, "gemini-1.5-pro"
'''
        endpoint,model=GenAIScaffoldDetector._extract_genai_details(
            smali,"Gemini","generativelanguage.googleapis.com"
        )
        assert model=="gemini-1.5-pro"
    def test_empty_smali_returns_trigger(self):
        endpoint,model=GenAIScaffoldDetector._extract_genai_details(
            "","OpenAI","api.openai.com"
        )
        assert endpoint=="api.openai.com"
        assert model==""
