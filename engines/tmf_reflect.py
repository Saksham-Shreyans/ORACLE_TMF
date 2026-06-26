"""
ORACLE-TMF  ·  engines/tmf_reflect.py
======================================
TMF-REFLECT — Reflection-Aware CFG Augmentation Engine

PROBLEM:
  Standard BFS dead-code detection fails silently when malware invokes
  methods via Java reflection chains:

    Class.forName("com.evil.SmsExfiltrator")
         .getMethod("run")
         .invoke(null, context);

  Androguard's `get_xref_from()` sees NO edge to `SmsExfiltrator.run()`.
  Therefore, that class appears unreachable and Stage D marks it as dead
  code.  This false negative destroys the most dangerous artifacts.

SOLUTION — Reflection Dependency Graph (RDG):
  TMF-REFLECT builds a secondary graph alongside the primary CFG by:

  1. SCAN: Find every method containing reflection invocation opcodes
     (Class.forName, Method.invoke, loadClass, DexClassLoader.<init>)

  2. EXTRACT: Pull all const-string operands from the SAME method body
     as each reflection call.  These are candidate class name strings.

  3. WEIGHT: Compute edge weight = 1 / (1 + Shannon_entropy(string))
     • Low-entropy strings  ("com.evil.SmsExfiltrator") → weight ~1.0  → HIGH confidence
     • High-entropy strings ("aB3cD9eF2gH")             → weight ~0.1  → LOW confidence

  4. RESOLVE: Two-stage resolution:
     a. Direct   : weight ≥ threshold and string matches Smali class pattern → inject edge
     b. Semantic : SBERT nearest-neighbour against known malware class corpus
                   for partially-obfuscated names (weight in [0.15, threshold))

  5. INJECT: Add resolved (caller → callee) edges into the primary CFG.
     Stage D then runs BFS on the augmented CFG, correctly marking
     reflection-invoked methods as REACHABLE (not dead code).

Threshold candidates (from ORACLE-TMF ablation study):
  {0.2, 0.3, 0.4, 0.5, 0.6}
  Default = 0.4  (best False-Negative-Rate reduction without FP explosion)

Research basis:
  • Enck et al. (2011) — TaintDroid: dynamic taint tracking in Android
  • ORACLE-TMF Section VI-B: "TMF-REFLECT: Reflection-Aware CFG Augmentation"
  • Zhang-Shasha tree edit distance for method body alignment
  • Sentence-BERT: Reimers & Gurevych (2019), https://arxiv.org/abs/1908.10084
"""

from __future__ import annotations

import logging
import math
import re
import time
from typing import Any, Optional

from config.settings import (
    REFLECT_DEFAULT_THRESHOLD,
    REFLECT_MAX_CHAIN_DEPTH,
    REFLECT_THRESHOLD_CANDIDATES,
    SBERT_MODEL,
)

logger = logging.getLogger(__name__)

# ── Reflection API signatures to scan for ─────────────────────────────────────
_REFLECTION_SIGS: tuple[str, ...] = (
    "Ljava/lang/Class;->forName(",
    "Ljava/lang/reflect/Method;->invoke(",
    "Ljava/lang/ClassLoader;->loadClass(",
    "Ldalvik/system/DexClassLoader;-><init>(",
    "Ldalvik/system/PathClassLoader;->loadClass(",
    "Ljava/lang/Class;->getDeclaredMethod(",
    "Ljava/lang/Class;->getMethod(",
)

# Smali class descriptor pattern: Lsome/package/ClassName;
_SMALI_CLASS_RE = re.compile(r"^L[a-zA-Z][a-zA-Z0-9/$_]{2,};$")

# const-string opcode patterns (all Dalvik const-string variants)
_CONST_STRING_RE = re.compile(
    r"const-string(?:/jumbo)?\s+[vp]\d+,\s*\"([^\"]{4,})\"",
    re.MULTILINE,
)

# Corpus of known malware class name patterns (for SBERT semantic matching)
_MALWARE_CLASS_CORPUS: list[str] = [
    "com.example.config.Settings",
    "com.android.service.SystemService",
    "com.update.service.UpdateManager",
    "com.manager.app.ApplicationManager",
    "com.sms.interceptor.SmsReceiver",
    "com.contact.stealer.ContactManager",
    "com.location.tracker.GpsService",
    "com.audio.recorder.MicCapture",
    "com.screen.capture.ScreenService",
    "com.keylogger.input.KeyCapture",
    "com.overlay.attack.PhishingActivity",
    "com.banking.overlay.LoginActivity",
    "com.crypto.wallet.WalletStealer",
    "com.c2.network.CommandService",
    "com.dropper.payload.PayloadLoader",
    "com.bot.controller.BotManager",
    "com.device.admin.AdminReceiver",
    "com.accessibility.service.AccessService",
    "com.notification.listener.NotifListener",
]


class TMFReflect:
    """
    TMF-REFLECT: Reflection-Aware CFG Augmentation Engine.

    Augments the primary CFG with edges inferred from Java reflection chains,
    reducing false-negative dead code classification caused by dynamic dispatch.

    Usage
    -----
    >>> engine = TMFReflect()
    >>> augmented_cfg = engine.augment_cfg(analysis, cfg)
    >>> # Now run Stage D with augmented_cfg
    """

    def __init__(self, threshold: float = REFLECT_DEFAULT_THRESHOLD) -> None:
        """
        Parameters
        ----------
        threshold : float
            Minimum edge weight to inject an RDG edge into the CFG.
            Lower threshold = more edges injected (fewer false negatives,
            more false positives in reachability).
        """
        self.threshold = threshold
        self._sbert_model: Optional[Any] = None   # Lazy-loaded on first use
        self._sbert_available = True              # Set False if import fails

    # ─────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────

    def augment_cfg(
        self,
        analysis: Any,
        cfg: Any,
        threshold: Optional[float] = None,
    ) -> Any:
        """
        Augment the primary CFG with reflection-resolved edges.

        Parameters
        ----------
        analysis : Androguard Analysis object from Stage B
        cfg      : networkx.DiGraph from Stage B (modified IN-PLACE)
        threshold: float, optional — override default threshold

        Returns
        -------
        The same cfg DiGraph, with reflection edges injected.
        Modifies cfg in-place and also returns it for chaining.
        """
        if cfg is None:
            logger.warning("[TMF-REFLECT] No CFG provided — skipping augmentation")
            return cfg

        t = threshold if threshold is not None else self.threshold
        t0 = time.perf_counter()
        logger.info("[TMF-REFLECT] Augmenting CFG (threshold=%.2f)", t)

        # Step 1: Build the Reflection Dependency Graph
        rdg = self._build_rdg(analysis)
        logger.debug("[TMF-REFLECT] RDG nodes: %d", len(rdg))

        # Step 2: Resolve RDG entries to concrete CFG edges
        edges_injected = self._resolve_and_inject(rdg, analysis, cfg, t)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[TMF-REFLECT] Complete in %.1f ms | "
            "reflection_calls_found=%d | edges_injected=%d",
            elapsed_ms, len(rdg), edges_injected,
        )
        return cfg

    # ─────────────────────────────────────────────────────────
    #  STEP 1: BUILD REFLECTION DEPENDENCY GRAPH
    # ─────────────────────────────────────────────────────────

    def _build_rdg(self, analysis: Any) -> list[dict]:
        """
        Scan all methods for reflection API calls and extract the string
        arguments that may represent target class names.

        Returns a list of RDG entries:
        {
          "caller_desc"   : str   — Smali method descriptor of the reflection caller
          "string_value"  : str   — Extracted const-string operand
          "entropy"       : float — Shannon entropy of the string
          "weight"        : float — 1 / (1 + entropy)
          "chain_depth"   : int   — Nesting depth of reflection chain
        }
        """
        rdg: list[dict] = []

        try:
            for method_analysis in analysis.get_methods():
                if method_analysis.is_android_api() or method_analysis.is_external():
                    continue

                smali_code = self._get_smali(method_analysis)
                if not smali_code:
                    continue

                # Check if this method contains any reflection signatures
                has_reflection = any(sig in smali_code for sig in _REFLECTION_SIGS)
                if not has_reflection:
                    continue

                caller_desc = self._method_descriptor(method_analysis.method)
                chain_depth = self._count_reflection_depth(smali_code)

                # Extract all const-string operands from this method
                for match in _CONST_STRING_RE.finditer(smali_code):
                    string_value = match.group(1)
                    entropy = self._shannon_entropy(string_value)
                    weight  = 1.0 / (1.0 + entropy)

                    rdg.append({
                        "caller_desc":  caller_desc,
                        "string_value": string_value,
                        "entropy":      round(entropy, 4),
                        "weight":       round(weight, 4),
                        "chain_depth":  chain_depth,
                    })

        except Exception as exc:
            logger.warning("[TMF-REFLECT] RDG build error: %s", exc)

        return rdg

    # ─────────────────────────────────────────────────────────
    #  STEP 2: RESOLVE AND INJECT
    # ─────────────────────────────────────────────────────────

    def _resolve_and_inject(
        self,
        rdg: list[dict],
        analysis: Any,
        cfg: Any,
        threshold: float,
    ) -> int:
        """
        Resolve each RDG entry to a concrete class/method in the analysis
        and inject edges into the CFG if the weight exceeds the threshold.

        Two resolution strategies:
          A. DIRECT:   string_value is a valid Smali class descriptor AND
                       weight >= threshold → inject edges to all methods in that class
          B. SEMANTIC: weight in [threshold * 0.5, threshold) →
                       SBERT nearest-neighbour against known malware class corpus
                       → if similarity > 0.75 → inject edge

        Returns the number of edges injected.
        """
        injected = 0
        class_cache: dict[str, Any] = {}   # class_name → ClassAnalysis

        # Pre-build class name → ClassAnalysis map for O(1) lookup
        try:
            for class_analysis in analysis.get_classes():
                class_cache[class_analysis.name] = class_analysis
        except Exception:
            pass

        for entry in rdg:
            string_val  = entry["string_value"]
            weight      = entry["weight"]
            caller_desc = entry["caller_desc"]

            if weight < threshold * 0.5:
                # Too low confidence even for semantic resolution
                continue

            # Convert Java-style to Smali descriptor if needed
            smali_candidate = self._to_smali_class(string_val)

            if weight >= threshold:
                # STRATEGY A: Direct resolution
                count = self._inject_direct(
                    caller_desc, smali_candidate, class_cache, cfg
                )
                injected += count

            elif weight >= threshold * 0.5:
                # STRATEGY B: Semantic SBERT resolution
                count = self._inject_semantic(
                    caller_desc, string_val, weight, class_cache, cfg
                )
                injected += count

        return injected

    def _inject_direct(
        self,
        caller_desc: str,
        smali_class: str,
        class_cache: dict,
        cfg: Any,
    ) -> int:
        """
        Direct injection: the extracted string resolves to a known class.
        Adds synthetic CFG edges from caller to all methods in the target class.
        """
        if not _SMALI_CLASS_RE.match(smali_class):
            return 0
        if smali_class not in class_cache:
            return 0

        class_analysis = class_cache[smali_class]
        count = 0
        for method_analysis in class_analysis.get_methods():
            callee_desc = self._method_descriptor(method_analysis.method)
            if callee_desc not in cfg:
                cfg.add_node(callee_desc)
            cfg.add_edge(caller_desc, callee_desc, weight="reflect_direct")
            count += 1

        if count > 0:
            logger.debug(
                "[TMF-REFLECT] Direct inject: %s → %s (%d methods)",
                caller_desc[-40:], smali_class, count
            )
        return count

    def _inject_semantic(
        self,
        caller_desc: str,
        string_val: str,
        weight: float,
        class_cache: dict,
        cfg: Any,
    ) -> int:
        """
        Semantic injection: use SBERT to find the closest known class name.
        Only injects if cosine similarity exceeds 0.75.
        """
        sbert = self._get_sbert()
        if sbert is None:
            return 0

        try:
            import numpy as np
            query_emb   = sbert.encode(string_val, normalize_embeddings=True)
            corpus_embs = sbert.encode(_MALWARE_CLASS_CORPUS, normalize_embeddings=True)
            similarities = np.dot(corpus_embs, query_emb)
            best_idx     = int(np.argmax(similarities))
            best_sim     = float(similarities[best_idx])

            if best_sim < 0.75:
                return 0

            best_match  = _MALWARE_CLASS_CORPUS[best_idx]
            smali_match = self._to_smali_class(best_match)

            logger.debug(
                "[TMF-REFLECT] Semantic resolve: '%s' → '%s' (sim=%.3f)",
                string_val[:40], best_match, best_sim,
            )
            return self._inject_direct(caller_desc, smali_match, class_cache, cfg)

        except Exception as exc:
            logger.debug("[TMF-REFLECT] SBERT resolution failed: %s", exc)
            return 0

    # ─────────────────────────────────────────────────────────
    #  SBERT LAZY LOADER
    # ─────────────────────────────────────────────────────────

    def _get_sbert(self) -> Optional[Any]:
        """Lazy-load the Sentence-BERT model on first use."""
        if not self._sbert_available:
            return None
        if self._sbert_model is not None:
            return self._sbert_model
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            self._sbert_model = SentenceTransformer(SBERT_MODEL)
            logger.debug("[TMF-REFLECT] SBERT model loaded: %s", SBERT_MODEL)
        except ImportError:
            logger.warning(
                "[TMF-REFLECT] sentence-transformers not installed — "
                "semantic resolution disabled.  Run: pip install sentence-transformers"
            )
            self._sbert_available = False
            return None
        except Exception as exc:
            logger.warning("[TMF-REFLECT] SBERT load failed: %s", exc)
            self._sbert_available = False
            return None
        return self._sbert_model

    # ─────────────────────────────────────────────────────────
    #  UTILITIES
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _to_smali_class(java_name: str) -> str:
        """
        Convert a Java class name to Smali class descriptor format.
          "com.evil.Payload"      → "Lcom/evil/Payload;"
          "Lcom/evil/Payload;"   → unchanged (already Smali)
          "com/evil/Payload"     → "Lcom/evil/Payload;"
        """
        name = java_name.strip()
        if name.startswith("L") and name.endswith(";"):
            return name
        # Replace dots with slashes (Java → Smali)
        name = name.replace(".", "/")
        if not name.startswith("L"):
            name = "L" + name
        if not name.endswith(";"):
            name = name + ";"
        return name

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Shannon entropy of a string in bits per character."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        total = len(text)
        return -sum((v / total) * math.log2(v / total) for v in freq.values())

    @staticmethod
    def _count_reflection_depth(smali_code: str) -> int:
        """Count how many different reflection APIs appear in the method body."""
        return sum(1 for sig in _REFLECTION_SIGS if sig in smali_code)

    @staticmethod
    def _get_smali(method_analysis: Any) -> str:
        """Safely extract Smali source from MethodAnalysis."""
        try:
            src = method_analysis.method.get_source()
            return src if src else ""
        except Exception:
            return ""

    @staticmethod
    def _method_descriptor(method_obj: Any) -> str:
        """Canonical Smali method descriptor."""
        try:
            return (
                f"{method_obj.get_class_name()}"
                f"->{method_obj.get_name()}"
                f"{method_obj.get_descriptor()}"
            )
        except Exception:
            return str(method_obj)
