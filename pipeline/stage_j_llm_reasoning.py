"""
ORACLE-TMF  ·  pipeline/stage_j_llm_reasoning.py
=================================================
STAGE J — LLM Mutation Artifact Reasoning Engine

Responsibility:
  • Orchestrate three LLM agents in sequence using the Anthropic SDK
  • Agent 1 (Decompiler):  Smali dead code → readable pseudo-Java
  • Agent 2 (Hypothesizer): Mutation Artifact JSON → MITRE ATT&CK forecast
  • Agent 3 (Validator):   Hypothesis → RAG-grounded validation + P_LLM score
  • Retrieve relevant context from the ChromaDB vector store (RAG)
  • Return a list of MutationForecast objects with P_LLM scores

Inputs:
  mag : MutationArtifactGraph  — fully populated by Stages A–I

Outputs: list[MutationForecast]

Multi-Agent Chain:
  ┌─────────────────┐    ┌───────────────────┐    ┌──────────────────────┐
  │ Agent 1          │    │ Agent 2            │    │ Agent 3              │
  │ DECOMPILER       │───▶│ HYPOTHESIZER       │───▶│ SKEPTICAL VALIDATOR  │
  │ Smali → Java     │    │ Artifacts → MITRE  │    │ RAG validation       │
  │ Identifies APIs  │    │ Forecasts v_{n+1}  │    │ Assigns P_LLM        │
  └─────────────────┘    └───────────────────┘    └──────────────────────┘

Context Window Management:
  Each agent receives:
    - MAG JSON (≤ 16K chars, stripped of raw Smali)
    - RAG context (≤ 8K chars, top-5 MITRE + MalNet docs)
  Total per call: ≤ 24K chars → well within claude-sonnet-4-6 context limit
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from config.settings import (
    ANTHROPIC_API_KEY,
    CHROMA_MITRE_COLLECTION,
    CHROMA_MALNET_COLLECTION,
    CHROMA_PERSIST_DIR,
    LLM_MAG_CONTEXT_CHARS,
    LLM_MAX_TOKENS,
    LLM_MODEL,
    LLM_RAG_CONTEXT_CHARS,
    LLM_TEMPERATURE,
    RAG_TOP_K,
)
from models.mutation_artifact_graph import MutationArtifactGraph, MutationForecast

logger = logging.getLogger(__name__)


class LLMReasoningEngine:
    """
    Stage J: Multi-Agent LLM Mutation Artifact Reasoning Engine.

    The engine runs three sequential agents using the Anthropic SDK.
    Each agent is stateless — it receives all required context in a
    single API call (no multi-turn conversation state is maintained).

    Usage
    -----
    >>> engine = LLMReasoningEngine()
    >>> forecasts = engine.run(mag)
    """

    STAGE_NAME = "STAGE_J"

    # ─────────────────────────────────────────────────────────
    #  SYSTEM PROMPTS  (research paper specification §2.5)
    # ─────────────────────────────────────────────────────────

    _AGENT1_SYSTEM = """You are an expert Android reverse engineer and malware analyst.
Your task is to translate Dalvik/Smali bytecode snippets into highly readable pseudo-Java.

Rules:
1. Identify ALL Android framework APIs invoked (e.g., android.telephony.SmsManager.sendTextMessage).
2. Identify the underlying logic intent — what is this code designed to do?
3. Flag any reflection chains, encryption operations, or network calls.
4. Do NOT hallucinate external context — only analyse what is shown.
5. Output Format (JSON only, no prose):
{
  "pseudo_java": "<readable pseudo-Java code>",
  "identified_apis": ["api.signature.1", "api.signature.2"],
  "logic_summary": "<one sentence describing what this code does>",
  "reflection_chains": ["<class.forName call 1>", ...],
  "risk_indicators": ["<indicator 1>", ...]
}"""

    _AGENT2_SYSTEM = """You are ORACLE-TMF, an elite threat intelligence forecaster 
specialising in Android banking malware evolution.

Your task is to analyse a Mutation Artifact Graph (MAG) extracted from an Android APK
and predict the EXACT capability the malware developer will implement in the NEXT release.

Reasoning framework (follow this chain-of-thought):
1. What does the dead code scaffold tell you about developer intent?
2. What do unused permissions pre-position the malware to do?
3. What do C2 stubs reveal about planned infrastructure?
4. Connect these signals: what is the SINGLE most likely next capability?
5. Map this capability to a SPECIFIC MITRE ATT&CK for Mobile technique.

Constraints:
- Apply the Activation Energy Theorem: predict the capability requiring the LEAST 
  development effort to complete given the existing scaffolding.
- Prefer specific techniques over broad tactics.
- Think step-by-step before outputting your prediction.

Output Format (JSON only, no prose before or after):
{
  "chain_of_thought": "<your step-by-step reasoning>",
  "predicted_tactic": "<MITRE Tactic ID and name, e.g. TA0011 - Command and Control>",
  "predicted_technique": "<MITRE Technique ID and name, e.g. T1568.002 - DGA>",
  "rationale": "<concise explanation connecting artifacts to prediction>",
  "supporting_artifact_classes": ["CLASS_1_DEAD_CODE", "CLASS_4_C2_ENDPOINT_STUB"],
  "predicted_target_institutions": ["<bank name if predictable, else empty>"],
  "predicted_target_countries": ["<country code if predictable, else empty>"]
}"""

    _AGENT3_SYSTEM = """You are the Skeptical Validator of the ORACLE-TMF system.
Your role is to RIGOROUSLY challenge mutation forecasts and reject those that can be 
explained by benign SDK boilerplate or coincidence.

Validation criteria:
1. GROUND CHECK: Is there a historical precedent for this mutation in the identified 
   malware family? Use the provided RAG context from MalNet and MITRE.
2. BOILERPLATE CHECK: Could the dead code be explained by a common third-party SDK 
   (Firebase, Google Play Services, Facebook SDK)?
3. SPECIFICITY CHECK: Is the forecast specific enough to be actionable 
   (naming a technique, not just a tactic)?
4. COHERENCE CHECK: Do the multiple artifact types independently converge on the 
   same capability?

Scoring: Assign a confidence score P_LLM in [0.0, 1.0]:
  - 0.9-1.0: All 4 checks pass, strong historical precedent
  - 0.7-0.9: 3 checks pass, reasonable precedent
  - 0.5-0.7: 2 checks pass, weak evidence
  - 0.0-0.5: Reject — likely boilerplate or insufficient evidence

Output Format (JSON only):
{
  "validation_result": "ACCEPT" | "REJECT" | "WEAK_ACCEPT",
  "ground_check": "<pass/fail and reasoning>",
  "boilerplate_check": "<pass/fail and reasoning>",
  "specificity_check": "<pass/fail and reasoning>",
  "coherence_check": "<pass/fail and reasoning>",
  "p_llm": <float 0.0-1.0>,
  "final_rationale": "<concise validation summary>"
}"""

    # ─────────────────────────────────────────────────────────
    #  INITIALISATION
    # ─────────────────────────────────────────────────────────

    def __init__(self) -> None:
        self._client = self._init_anthropic_client()
        self._rag    = self._init_rag()

    def _init_anthropic_client(self) -> Any:
        """Initialise the Anthropic client with the configured API key."""
        try:
            import anthropic  # type: ignore
            if not ANTHROPIC_API_KEY:
                logger.warning(
                    "[Stage J] ANTHROPIC_API_KEY not set — LLM calls will fail. "
                    "Export the key: export ANTHROPIC_API_KEY=sk-ant-..."
                )
            return anthropic.Anthropic(api_key=ANTHROPIC_API_KEY or "placeholder")
        except ImportError as exc:
            logger.error("[Stage J] anthropic package not installed: %s", exc)
            return None

    def _init_rag(self) -> Optional["RAGRetriever"]:
        """Initialise the RAG retriever against the ChromaDB knowledge base."""
        try:
            return RAGRetriever()
        except Exception as exc:
            logger.warning("[Stage J] RAG unavailable — proceeding without: %s", exc)
            return None

    # ─────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────

    def run(self, mag: MutationArtifactGraph) -> list[MutationForecast]:
        """
        Execute Stage J.

        Parameters
        ----------
        mag : MutationArtifactGraph
            Fully populated MAG from Stages A-I.

        Returns
        -------
        list[MutationForecast]
            Forecasts with p_llm scores from the Skeptical Validator.
        """
        t0 = time.perf_counter()
        logger.info("[Stage J] Starting multi-agent LLM reasoning engine")

        if self._client is None:
            logger.error("[Stage J] No LLM client available — returning empty forecasts")
            return []

        forecasts: list[MutationForecast] = []

        # Prepare MAG context (compact, ≤ 16K chars)
        mag_context = mag.to_llm_context(max_chars=LLM_MAG_CONTEXT_CHARS)

        # Prepare RAG context (≤ 8K chars)
        rag_context = self._retrieve_rag_context(
            mag.malware_family, mag_context
        )

        # ── Agent 1: Decompile top dead code scaffolding methods ──────
        decompiler_outputs = self._run_agent1_decompiler(mag, mag_context)

        # ── Agent 2: Generate mutation hypotheses ─────────────────────
        enriched_mag_context = self._enrich_context_with_decompiler(
            mag_context, decompiler_outputs
        )
        hypothesis = self._run_agent2_hypothesizer(
            enriched_mag_context, rag_context
        )

        if hypothesis is None:
            logger.warning("[Stage J] Hypothesizer returned no hypothesis")
            return []

        # ── Agent 3: Validate hypothesis ──────────────────────────────
        validation = self._run_agent3_validator(
            hypothesis, enriched_mag_context, rag_context
        )

        # ── Assemble MutationForecast ─────────────────────────────────
        forecast = self._assemble_forecast(hypothesis, validation)
        if forecast is not None:
            forecasts.append(forecast)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[Stage J] Complete in %.1f ms | forecasts=%d",
            elapsed_ms, len(forecasts),
        )
        return forecasts

    # ─────────────────────────────────────────────────────────
    #  AGENT 1 — DECOMPILER
    # ─────────────────────────────────────────────────────────

    def _run_agent1_decompiler(
        self, mag: MutationArtifactGraph, mag_context: str
    ) -> list[dict]:
        """
        Agent 1: Translate the top-3 dead code scaffolding methods
        from Smali into readable pseudo-Java.

        Only sends the SCAFFOLDING-classified dead code snippets (DTE output).
        """
        scaffolding = mag.scaffolding_artifacts()
        if not scaffolding:
            logger.debug("[Stage J] No scaffolding artifacts — skipping Agent 1")
            return []

        # Send top 3 by opcode count (most substantial stubs)
        top_stubs = sorted(scaffolding, key=lambda a: a.opcode_count, reverse=True)[:3]

        outputs: list[dict] = []
        for stub in top_stubs:
            smali_snippet = (
                f"Class: {stub.class_name}\n"
                f"Method: {stub.method_name}\n"
                f"Smali:\n{stub.smali_code[:2000]}"
            )
            user_prompt = f"Translate the following Smali dead code:\n\n```smali\n{smali_snippet}\n```"
            response = self._call_llm(self._AGENT1_SYSTEM, user_prompt)
            if response:
                parsed = self._parse_json_response(response)
                if parsed:
                    stub.pseudo_java = parsed.get("pseudo_java", "")
                    outputs.append(parsed)
                    logger.debug("[Stage J] Agent 1 decompiled: %s", stub.method_name)

        return outputs

    # ─────────────────────────────────────────────────────────
    #  AGENT 2 — HYPOTHESIZER
    # ─────────────────────────────────────────────────────────

    def _run_agent2_hypothesizer(
        self, mag_context: str, rag_context: str
    ) -> Optional[dict]:
        """
        Agent 2: Analyse the full MAG and predict the next mutation technique.
        """
        user_prompt = (
            f"Mutation Artifact Graph:\n{mag_context}\n\n"
            f"Historical Context (RAG):\n{rag_context}"
        )
        response = self._call_llm(self._AGENT2_SYSTEM, user_prompt)
        if not response:
            return None
        return self._parse_json_response(response)

    # ─────────────────────────────────────────────────────────
    #  AGENT 3 — SKEPTICAL VALIDATOR
    # ─────────────────────────────────────────────────────────

    def _run_agent3_validator(
        self, hypothesis: dict, mag_context: str, rag_context: str
    ) -> Optional[dict]:
        """
        Agent 3: Validate the Hypothesizer's output against RAG precedent
        and assign a normalised confidence score P_LLM.
        """
        user_prompt = (
            f"Hypothesis to Validate:\n{json.dumps(hypothesis, indent=2)}\n\n"
            f"Mutation Artifact Graph:\n{mag_context}\n\n"
            f"Historical Precedent (RAG):\n{rag_context}"
        )
        response = self._call_llm(self._AGENT3_SYSTEM, user_prompt)
        if not response:
            return None
        return self._parse_json_response(response)

    # ─────────────────────────────────────────────────────────
    #  FORECAST ASSEMBLY
    # ─────────────────────────────────────────────────────────

    def _assemble_forecast(
        self, hypothesis: dict, validation: Optional[dict]
    ) -> Optional[MutationForecast]:
        """Combine Hypothesizer and Validator outputs into a MutationForecast."""
        if validation is None:
            p_llm = 0.0
            validation_result = "NO_VALIDATION"
        else:
            p_llm = float(validation.get("p_llm", 0.0))
            validation_result = validation.get("validation_result", "UNKNOWN")

        # Extract technique details
        predicted_tactic     = hypothesis.get("predicted_tactic", "")
        predicted_technique  = hypothesis.get("predicted_technique", "")
        technique_name       = ""

        # Split "T1568.002 - Domain Generation Algorithms" into id and name
        if " - " in predicted_technique:
            parts = predicted_technique.split(" - ", 1)
            predicted_technique = parts[0].strip()
            technique_name      = parts[1].strip()

        tactic_id = ""
        if " - " in predicted_tactic:
            tactic_id = predicted_tactic.split(" - ", 1)[0].strip()

        rationale = hypothesis.get("rationale", "")
        if validation and validation.get("final_rationale"):
            rationale = f"{rationale}\n\nValidator: {validation['final_rationale']}"

        return MutationForecast(
            predicted_tactic    = tactic_id or predicted_tactic,
            predicted_technique = predicted_technique,
            technique_name      = technique_name,
            rationale           = rationale[:2000],
            p_llm               = min(1.0, max(0.0, p_llm)),
            supporting_artifacts = hypothesis.get("supporting_artifact_classes", []),
            predicted_target_institutions = hypothesis.get("predicted_target_institutions", []),
            predicted_target_countries    = hypothesis.get("predicted_target_countries", []),
        )

    # ─────────────────────────────────────────────────────────
    #  RAG RETRIEVAL
    # ─────────────────────────────────────────────────────────

    def _retrieve_rag_context(self, family: str, mag_context: str) -> str:
        """
        Retrieve relevant documents from ChromaDB for grounding agent reasoning.
        Returns a compact text block of ≤ 8K chars.
        """
        if self._rag is None:
            return "(RAG not available — no historical context)"
        try:
            query = f"malware family {family or 'banking trojan'} MITRE ATT&CK technique mutation"
            docs  = self._rag.retrieve(query, top_k=RAG_TOP_K)
            context_parts = []
            total = 0
            for doc in docs:
                chunk = f"[Source: {doc.get('source', 'unknown')}]\n{doc.get('text', '')}\n"
                if total + len(chunk) > LLM_RAG_CONTEXT_CHARS:
                    break
                context_parts.append(chunk)
                total += len(chunk)
            return "\n---\n".join(context_parts) or "(No relevant documents found)"
        except Exception as exc:
            logger.warning("[Stage J] RAG retrieval failed: %s", exc)
            return "(RAG retrieval error)"

    # ─────────────────────────────────────────────────────────
    #  LLM CALL WRAPPER
    # ─────────────────────────────────────────────────────────

    def _call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """
        Make a single synchronous call to the Anthropic API.
        Returns the text content of the first response block, or None on failure.
        """
        if self._client is None:
            return None
        try:
            message = self._client.messages.create(
                model      = LLM_MODEL,
                max_tokens = LLM_MAX_TOKENS,
                temperature= LLM_TEMPERATURE,
                system     = system_prompt,
                messages   = [{"role": "user", "content": user_prompt}],
            )
            if message.content:
                return message.content[0].text
            return None
        except Exception as exc:
            logger.error("[Stage J] LLM API call failed: %s", exc)
            return None

    # ─────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_json_response(text: str) -> Optional[dict]:
        """
        Extract and parse a JSON object from LLM response text.
        Handles cases where the model wraps JSON in markdown code blocks.
        """
        if not text:
            return None
        # Strip markdown code fences
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]) if len(lines) > 2 else text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Attempt to extract JSON object substring
            import re
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        logger.debug("[Stage J] Failed to parse JSON from LLM response")
        return None

    @staticmethod
    def _enrich_context_with_decompiler(
        mag_context: str, decompiler_outputs: list[dict]
    ) -> str:
        """Append Agent 1 pseudo-Java translations to the MAG context."""
        if not decompiler_outputs:
            return mag_context
        pseudo_java_block = "\n\n## Agent 1 — Decompiled Dead Code Scaffolding:\n"
        for i, output in enumerate(decompiler_outputs, 1):
            pseudo_java_block += (
                f"\n### Stub {i}\n"
                f"**Summary**: {output.get('logic_summary', 'N/A')}\n"
                f"**APIs**: {', '.join(output.get('identified_apis', []))}\n"
                f"```java\n{output.get('pseudo_java', '')[:800]}\n```\n"
            )
        # Ensure combined context stays within limit
        combined = mag_context + pseudo_java_block
        return combined[:LLM_MAG_CONTEXT_CHARS]


# ─────────────────────────────────────────────────────────────────
#  RAG RETRIEVER — ChromaDB wrapper
# ─────────────────────────────────────────────────────────────────

class RAGRetriever:
    """
    ChromaDB-based RAG retriever over two knowledge base collections:
      1. MITRE ATT&CK for Mobile (all T1xxx.yyy techniques)
      2. MalNet phylogenetics (family-level architecture descriptions)
    """

    def __init__(self) -> None:
        import chromadb  # type: ignore
        from sentence_transformers import SentenceTransformer  # type: ignore

        self._model  = SentenceTransformer("all-MiniLM-L6-v2")
        self._client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
        self._mitre  = self._get_or_create(CHROMA_MITRE_COLLECTION)
        self._malnet = self._get_or_create(CHROMA_MALNET_COLLECTION)

    def _get_or_create(self, name: str):
        try:
            return self._client.get_collection(name)
        except Exception:
            return self._client.create_collection(name)

    def retrieve(self, query: str, top_k: int = 5) -> list[dict]:
        """Retrieve top-k documents from both collections."""
        embedding = self._model.encode(query).tolist()
        docs: list[dict] = []

        for collection in [self._mitre, self._malnet]:
            try:
                results = collection.query(
                    query_embeddings=[embedding], n_results=min(top_k, collection.count())
                )
                ids       = results.get("ids", [[]])[0]
                documents = results.get("documents", [[]])[0]
                metadatas = results.get("metadatas", [[]])[0]
                for doc_id, text, meta in zip(ids, documents, metadatas):
                    docs.append({
                        "id":     doc_id,
                        "text":   text[:500],
                        "source": meta.get("source", collection.name),
                    })
            except Exception as exc:
                logger.debug("[RAG] Collection query error: %s", exc)

        return docs[:top_k]

    def ingest_mitre_technique(self, technique_id: str, name: str, description: str) -> None:
        """Ingest a MITRE ATT&CK technique into the vector store."""
        from sentence_transformers import SentenceTransformer
        text      = f"{technique_id} - {name}: {description}"
        embedding = self._model.encode(text).tolist()
        self._mitre.add(
            ids        = [technique_id],
            documents  = [text],
            embeddings = [embedding],
            metadatas  = [{"source": "MITRE ATT&CK Mobile", "technique_id": technique_id}],
        )

    def ingest_malnet_family(self, family: str, description: str) -> None:
        """Ingest a MalNet malware family architecture description."""
        embedding = self._model.encode(description).tolist()
        self._malnet.add(
            ids        = [family],
            documents  = [description],
            embeddings = [embedding],
            metadatas  = [{"source": "MalNet Phylogenetics", "family": family}],
        )
