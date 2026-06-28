"""
ORACLE-TMF  ·  research/kinship/builder_dna.py
================================================
KINSHIP: Builder DNA Fingerprinting — Stage 2 Tier 3.

Extracts a Builder DNA Vector (BDV) from APK dead code, enabling
attribution by developmental style — even when active code is fully
obfuscated.  Malware authors have consistent coding habits that survive
obfuscation because they are embedded in the STRUCTURE of the code:
  • Identifier naming patterns (character n-gram frequency in dead blocks)
  • Structural graph patterns of C2 stub scaffolding
  • Entropy profile of placeholder strings
  • Smali opcode frequency fingerprints in partial API implementations

Two APKs with similar BDVs likely share the same developer/team.
This enables:
  • Attribution: linking a new family to a known MaaS operator
  • Evolution tracking: confirming that two version chains are from the same author
  • Infrastructure sharing detection: shared C2 scaffolding patterns

Implementation
--------------
Stage 1: BDV extraction
  • Character n-gram frequencies in identifier text from dead code
  • Smali opcode n-gram frequencies (instruction sequence fingerprint)
  • Entropy statistics of placeholder strings
  • C2 stub structural graph patterns (degree distribution)

Stage 2: Clustering
  • Sentence-BERT embeds the textual component of each BDV
  • Cosine similarity clusters APKs by builder origin
  • Threshold: KINSHIP_SIMILARITY_THRESHOLD = 0.72
"""
from __future__ import annotations

import logging
import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from config.stage2_settings import (
    KINSHIP_MAX_DEAD_BLOCKS,
    KINSHIP_NGRAM_SIZES,
    KINSHIP_SBERT_MODEL,
    KINSHIP_SIMILARITY_THRESHOLD,
)
from models.mutation_artifact_graph import (
    MutationArtifactGraph,
    DeadCodeArtifact,
)

logger = logging.getLogger(__name__)

# Sentence-BERT is optional — fallback to TF-IDF cosine similarity
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    _SBERT_AVAILABLE = True
except ImportError:
    _SBERT_AVAILABLE = False
    logger.warning("[KINSHIP] sentence-transformers not installed — using TF-IDF fallback")


@dataclass
class BuilderDNAVector:
    """
    Builder DNA Vector (BDV) for a single APK.

    All components are serialisable (no NumPy arrays at storage layer).
    """

    apk_hash: str = ""
    apk_package: str = ""

    # Character n-gram frequencies in dead code identifier text
    # Keys are n-gram tuples serialised as strings: "ab" → count
    char_ngram_freq: dict[str, float] = field(default_factory=dict)

    # Smali opcode n-gram frequencies (instruction patterns)
    opcode_ngram_freq: dict[str, float] = field(default_factory=dict)

    # Placeholder string entropy statistics
    entropy_mean: float = 0.0
    entropy_std: float = 0.0
    entropy_max: float = 0.0
    placeholder_count: int = 0

    # C2 stub structural graph features
    c2_stub_count: int = 0
    c2_avg_method_depth: float = 0.0
    c2_framework_fingerprint: str = ""   # "okhttp3", "retrofit2", etc.

    # Partial API structure fingerprint
    partial_api_count: int = 0
    partial_api_interfaces: list[str] = field(default_factory=list)

    # Embedding (computed by KINSHIP clustering, not stored in BDV base)
    _embedding: list[float] = field(default_factory=list, repr=False)

    # Attribution metadata
    suspected_builder: str = ""
    attribution_confidence: float = 0.0
    similar_apks: list[str] = field(default_factory=list)  # APK hashes

    def to_text_representation(self) -> str:
        """
        Compact text representation for SBERT embedding.

        Encodes the structural patterns as a descriptor string that
        captures the developer's coding style in a language-model-friendly format.
        """
        top_ngrams = sorted(
            self.char_ngram_freq.items(), key=lambda kv: kv[1], reverse=True
        )[:50]
        ngram_text = " ".join(k for k, _ in top_ngrams)

        top_opcodes = sorted(
            self.opcode_ngram_freq.items(), key=lambda kv: kv[1], reverse=True
        )[:30]
        opcode_text = " ".join(k for k, _ in top_opcodes)

        ifaces = " ".join(self.partial_api_interfaces[:10])
        return (
            f"ngrams:{ngram_text} "
            f"opcodes:{opcode_text} "
            f"c2_framework:{self.c2_framework_fingerprint} "
            f"entropy_mean:{self.entropy_mean:.2f} "
            f"entropy_std:{self.entropy_std:.2f} "
            f"api_ifaces:{ifaces}"
        )

    def to_dict(self) -> dict:
        return {
            "apk_hash": self.apk_hash,
            "apk_package": self.apk_package,
            "entropy_mean": round(self.entropy_mean, 4),
            "entropy_std": round(self.entropy_std, 4),
            "entropy_max": round(self.entropy_max, 4),
            "placeholder_count": self.placeholder_count,
            "c2_stub_count": self.c2_stub_count,
            "c2_avg_method_depth": round(self.c2_avg_method_depth, 3),
            "c2_framework_fingerprint": self.c2_framework_fingerprint,
            "partial_api_count": self.partial_api_count,
            "partial_api_interfaces": self.partial_api_interfaces,
            "suspected_builder": self.suspected_builder,
            "attribution_confidence": round(self.attribution_confidence, 4),
            "similar_apks": self.similar_apks,
        }


@dataclass
class KINSHIPResult:
    """Output of the KINSHIP engine for a set of APKs."""

    bdv_list: list[BuilderDNAVector] = field(default_factory=list)
    cluster_assignments: dict[str, int] = field(default_factory=dict)  # apk_hash → cluster_id
    cluster_count: int = 0
    runtime_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "apks_fingerprinted": len(self.bdv_list),
            "cluster_count": self.cluster_count,
            "runtime_ms": round(self.runtime_ms, 2),
            "fingerprints": [bdv.to_dict() for bdv in self.bdv_list],
            "cluster_assignments": self.cluster_assignments,
        }


class KINSHIPEngine:
    """
    KINSHIP Builder DNA Fingerprinting Engine.

    Usage
    -----
    >>> engine = KINSHIPEngine()
    >>> bdv = engine.extract_bdv(mag)
    >>> result = engine.cluster([bdv1, bdv2, bdv3])
    >>> result = engine.run(mag_list)
    """

    ENGINE_NAME = "KINSHIP"

    def __init__(self) -> None:
        self._sbert: Optional[object] = None
        if _SBERT_AVAILABLE:
            try:
                self._sbert = SentenceTransformer(KINSHIP_SBERT_MODEL)
                logger.info("[KINSHIP] SBERT model loaded: %s", KINSHIP_SBERT_MODEL)
            except Exception as exc:
                logger.warning("[KINSHIP] SBERT load failed (%s) — TF-IDF fallback", exc)
        logger.info("[KINSHIP] Engine initialised (sbert=%s)", _SBERT_AVAILABLE)

    def run(self, mag_list: list[MutationArtifactGraph]) -> KINSHIPResult:
        """
        Full KINSHIP pipeline: extract BDVs → embed → cluster.

        Parameters
        ----------
        mag_list : list[MutationArtifactGraph]
            One MAG per APK to fingerprint.

        Returns
        -------
        KINSHIPResult
        """
        t0 = time.perf_counter()
        logger.info("[KINSHIP] Fingerprinting %d APKs", len(mag_list))

        bdv_list = [self.extract_bdv(mag) for mag in mag_list]
        bdv_list = self._compute_embeddings(bdv_list)
        clusters = self._cluster_bdvs(bdv_list) if len(bdv_list) > 1 else {}

        # Propagate attribution within clusters
        for bdv in bdv_list:
            apk_hash = bdv.apk_hash
            cluster_id = clusters.get(apk_hash, -1)
            if cluster_id >= 0:
                # Find all APKs in same cluster
                same_cluster = [
                    h for h, c in clusters.items() if c == cluster_id and h != apk_hash
                ]
                bdv.similar_apks = same_cluster

        elapsed_ms = (time.perf_counter() - t0) * 1000
        result = KINSHIPResult(
            bdv_list=bdv_list,
            cluster_assignments=clusters,
            cluster_count=len(set(clusters.values())) if clusters else 0,
            runtime_ms=round(elapsed_ms, 2),
        )
        logger.info(
            "[KINSHIP] Complete in %.1f ms | fingerprints=%d | clusters=%d",
            elapsed_ms, len(bdv_list), result.cluster_count,
        )
        return result

    def extract_bdv(self, mag: MutationArtifactGraph) -> BuilderDNAVector:
        """
        Extract a Builder DNA Vector from a single APK's MAG.

        Parameters
        ----------
        mag : MutationArtifactGraph
            The MAG to fingerprint.

        Returns
        -------
        BuilderDNAVector
        """
        bdv = BuilderDNAVector(
            apk_hash=mag.apk_metadata.sha256[:16] or "unknown",
            apk_package=mag.apk_metadata.package_name,
        )

        # Cap dead code blocks for tractability
        dead_blocks = mag.dead_code[:KINSHIP_MAX_DEAD_BLOCKS]

        # Feature 1: Character n-gram frequencies
        bdv.char_ngram_freq = self._compute_char_ngrams(dead_blocks)

        # Feature 2: Smali opcode n-gram frequencies
        bdv.opcode_ngram_freq = self._compute_opcode_ngrams(dead_blocks)

        # Feature 3: Placeholder entropy profile
        entropies = [s.entropy for s in mag.placeholder_strings if s.entropy > 0]
        if entropies:
            mean_e = sum(entropies) / len(entropies)
            bdv.entropy_mean = round(mean_e, 4)
            bdv.entropy_std = round(
                math.sqrt(sum((e - mean_e) ** 2 for e in entropies) / len(entropies)), 4
            )
            bdv.entropy_max = round(max(entropies), 4)
        bdv.placeholder_count = len(mag.placeholder_strings)

        # Feature 4: C2 stub structural fingerprint
        bdv.c2_stub_count = len(mag.c2_stubs)
        if mag.c2_stubs:
            frameworks = [s.framework for s in mag.c2_stubs if s.framework]
            if frameworks:
                # Most common framework = signature of coding style
                bdv.c2_framework_fingerprint = Counter(frameworks).most_common(1)[0][0]
            avg_depth = sum(
                len(s.method_name.split(";")) for s in mag.c2_stubs
            ) / len(mag.c2_stubs)
            bdv.c2_avg_method_depth = round(avg_depth, 3)

        # Feature 5: Partial API interface fingerprint
        bdv.partial_api_count = len(mag.partial_apis)
        bdv.partial_api_interfaces = list({
            p.interface_extended for p in mag.partial_apis
        })[:20]

        return bdv

    def cosine_similarity(self, bdv_a: BuilderDNAVector, bdv_b: BuilderDNAVector) -> float:
        """
        Compute cosine similarity between two BDVs.

        Uses SBERT embedding if available; falls back to TF-IDF.
        """
        if bdv_a._embedding and bdv_b._embedding:
            return self._cosine(bdv_a._embedding, bdv_b._embedding)
        # TF-IDF fallback: use char n-gram overlap
        return self._ngram_overlap_similarity(
            bdv_a.char_ngram_freq, bdv_b.char_ngram_freq
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_char_ngrams(
        self, dead_blocks: list[DeadCodeArtifact]
    ) -> dict[str, float]:
        """Character n-gram frequencies from identifier text in dead code."""
        all_text = ""
        for block in dead_blocks:
            # Extract identifier names (class + method)
            all_text += f" {block.class_name} {block.method_name} "
            # Also extract string literals from smali
            strings = re.findall(r'"([^"]{3,})"', block.smali_code)
            all_text += " ".join(strings[:20]) + " "

        counts: Counter = Counter()
        for n in KINSHIP_NGRAM_SIZES:
            for i in range(len(all_text) - n + 1):
                ng = all_text[i:i + n]
                if ng.strip():  # Skip whitespace-only n-grams
                    counts[ng] += 1

        # Normalise by total count
        total = max(sum(counts.values()), 1)
        return {ng: round(count / total, 6) for ng, count in counts.most_common(500)}

    @staticmethod
    def _compute_opcode_ngrams(
        dead_blocks: list[DeadCodeArtifact],
    ) -> dict[str, float]:
        """Smali opcode n-gram frequencies (instruction sequence pattern)."""
        # Extract opcodes (first word of each smali line = opcode)
        all_opcodes: list[str] = []
        for block in dead_blocks:
            for line in block.smali_code.split("\n"):
                line = line.strip()
                if line and not line.startswith(".") and not line.startswith(":"):
                    opcode = line.split()[0] if line.split() else ""
                    if opcode:
                        all_opcodes.append(opcode)

        counts: Counter = Counter()
        # Bigrams and trigrams of opcodes
        for n in [2, 3]:
            for i in range(len(all_opcodes) - n + 1):
                ng = "_".join(all_opcodes[i:i + n])
                counts[ng] += 1

        total = max(sum(counts.values()), 1)
        return {ng: round(count / total, 6) for ng, count in counts.most_common(200)}

    def _compute_embeddings(
        self, bdv_list: list[BuilderDNAVector]
    ) -> list[BuilderDNAVector]:
        """Compute SBERT embeddings for each BDV's text representation."""
        if not self._sbert or not bdv_list:
            return bdv_list

        try:
            texts = [bdv.to_text_representation() for bdv in bdv_list]
            embeddings = self._sbert.encode(texts, show_progress_bar=False)
            for bdv, emb in zip(bdv_list, embeddings):
                bdv._embedding = emb.tolist()
            logger.info("[KINSHIP] SBERT embeddings computed for %d BDVs", len(bdv_list))
        except Exception as exc:
            logger.warning("[KINSHIP] Embedding failed: %s", exc)
        return bdv_list

    def _cluster_bdvs(
        self, bdv_list: list[BuilderDNAVector]
    ) -> dict[str, int]:
        """
        Cluster BDVs by cosine similarity.

        Uses greedy clustering: each BDV with similarity ≥
        KINSHIP_SIMILARITY_THRESHOLD to an existing cluster centroid
        joins that cluster; otherwise forms a new one.
        """
        if not bdv_list:
            return {}

        clusters: list[list[BuilderDNAVector]] = [[bdv_list[0]]]
        assignments: dict[str, int] = {bdv_list[0].apk_hash: 0}

        for bdv in bdv_list[1:]:
            best_cluster = -1
            best_score = KINSHIP_SIMILARITY_THRESHOLD - 0.001

            for cluster_id, cluster in enumerate(clusters):
                # Compare to first member of cluster (greedy centroid)
                score = self.cosine_similarity(bdv, cluster[0])
                if score > best_score:
                    best_score = score
                    best_cluster = cluster_id

            if best_cluster >= 0:
                clusters[best_cluster].append(bdv)
                assignments[bdv.apk_hash] = best_cluster
            else:
                new_id = len(clusters)
                clusters.append([bdv])
                assignments[bdv.apk_hash] = new_id

        logger.info(
            "[KINSHIP] Clustered %d APKs into %d builder groups",
            len(bdv_list), len(clusters),
        )
        return assignments

    @staticmethod
    def _cosine(vec_a: list[float], vec_b: list[float]) -> float:
        """Cosine similarity between two float vectors."""
        if not vec_a or not vec_b or len(vec_a) != len(vec_b):
            return 0.0
        dot = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = math.sqrt(sum(a * a for a in vec_a))
        norm_b = math.sqrt(sum(b * b for b in vec_b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return round(dot / (norm_a * norm_b), 6)

    @staticmethod
    def _ngram_overlap_similarity(
        freq_a: dict[str, float], freq_b: dict[str, float]
    ) -> float:
        """TF-IDF cosine similarity fallback using n-gram frequency dicts."""
        if not freq_a or not freq_b:
            return 0.0
        keys = set(freq_a) | set(freq_b)
        dot = sum(freq_a.get(k, 0) * freq_b.get(k, 0) for k in keys)
        norm_a = math.sqrt(sum(v * v for v in freq_a.values()))
        norm_b = math.sqrt(sum(v * v for v in freq_b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return round(dot / (norm_a * norm_b), 6)
