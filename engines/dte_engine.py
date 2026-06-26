"""
ORACLE-TMF  ·  engines/dte_engine.py
======================================
DORMANCY TAXONOMY ENGINE (DTE)

The DTE is a 4-class XGBoost classifier that resolves a critical ambiguity:
Not all statically unreachable code is a mutation artifact. A huge fraction
of dead code in real-world APKs is benign SDK boilerplate left behind by
third-party library inclusion (Firebase, Google Play Services, etc.).

Without the DTE, the Stage D dead code list would be polluted with thousands
of Firebase/Google SDK methods, flooding the LLM context and destroying signal.

The DTE classifies each DeadCodeArtifact into exactly ONE of four classes:

  ┌──────────────────────────┬──────────────────────────────────────────────────┐
  │ Class                    │ Description                                       │
  ├──────────────────────────┼──────────────────────────────────────────────────┤
  │ REMNANT                  │ Benign SDK boilerplate → DISCARD immediately      │
  │ SCAFFOLDING              │ Future capability stub → forward to Stage J       │
  │ LOGIC_BOMB               │ Conditional dormant payload → HIGH PRIORITY       │
  │ ENCRYPTED_DROPPER        │ Dynamic loader stub → Frida extraction path       │
  └──────────────────────────┴──────────────────────────────────────────────────┘

Feature Vector (4 features, matching DTE_FEATURE_* constants in settings.py):
  [0] trigger_depth   — max if-* nesting depth (logic bombs have depth ≥ 3)
  [1] guard_entropy   — Shannon entropy of conditional operands (obfuscated = high)
  [2] api_sensitivity — max sensitivity score of Android APIs in the method
  [3] guard_indegree  — number of incoming xref edges (REMNANT has many callers)

Model: XGBoost, n_estimators=300, max_depth=6, learning_rate=0.1
Training: Synthetic training set generated from domain expert heuristics.
          On first run, model is trained and saved to WORK_DIR.
          Subsequent runs load from the saved model file.

Research basis:
  • XGBoost: Chen & Guestrin (2016), https://arxiv.org/abs/1603.02754
  • Feature engineering: ORACLE-TMF Section VI-C (DTE specification)
  • Class distributions: derived from empirical malware analysis literature
"""

from __future__ import annotations

import logging
import os
import pickle
import time
from pathlib import Path
from typing import Optional

import numpy as np

from config.settings import (
    DTE_CLASS_ENC_DROPPER,
    DTE_CLASS_LOGIC_BOMB,
    DTE_CLASS_REMNANT,
    DTE_CLASS_SCAFFOLDING,
    DTE_FEATURE_API_SENSITIVITY,
    DTE_FEATURE_GUARD_ENTROPY,
    DTE_FEATURE_GUARD_INDEGREE,
    DTE_FEATURE_TRIGGER_DEPTH,
    DTE_LEARNING_RATE,
    DTE_MAX_DEPTH,
    DTE_N_ESTIMATORS,
    WORK_DIR,
)
from models.mutation_artifact_graph import DeadCodeArtifact, DTEClass

logger = logging.getLogger(__name__)

# Path where the trained XGBoost model is persisted across runs
_MODEL_CACHE_PATH = os.path.join(WORK_DIR, ".dte_xgboost_model.pkl")

# Class label → integer index (XGBoost requires integer labels)
_LABEL_TO_INT: dict[str, int] = {
    DTE_CLASS_REMNANT:       0,
    DTE_CLASS_SCAFFOLDING:   1,
    DTE_CLASS_LOGIC_BOMB:    2,
    DTE_CLASS_ENC_DROPPER:   3,
}
_INT_TO_LABEL: dict[int, str] = {v: k for k, v in _LABEL_TO_INT.items()}

# DTEClass enum mapping
_INT_TO_DTECLASS: dict[int, DTEClass] = {
    0: DTEClass.REMNANT,
    1: DTEClass.SCAFFOLDING,
    2: DTEClass.LOGIC_BOMB,
    3: DTEClass.ENCRYPTED_DROPPER,
}


class DTEEngine:
    """
    Dormancy Taxonomy Engine — XGBoost 4-class dormancy classifier.

    Classifies each DeadCodeArtifact and updates its dte_label and
    dte_confidence fields IN-PLACE.  Returns the modified list.

    Usage
    -----
    >>> engine = DTEEngine()
    >>> classified = engine.classify(dead_code_artifacts)
    """

    def __init__(self) -> None:
        Path(WORK_DIR).mkdir(parents=True, exist_ok=True)
        self._model = self._load_or_train_model()

    # ─────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────

    def classify(
        self, artifacts: list[DeadCodeArtifact]
    ) -> list[DeadCodeArtifact]:
        """
        Classify each dead code artifact using the DTE XGBoost model.

        Updates `dte_label` and `dte_confidence` on each artifact in-place.
        Returns the same list (modified), filtering out REMNANT class artifacts.

        Parameters
        ----------
        artifacts : list[DeadCodeArtifact]
            Raw dead code artifacts from Stage D.

        Returns
        -------
        list[DeadCodeArtifact]
            Artifacts with DTE labels set.  REMNANT artifacts are EXCLUDED
            from the return value (they are discarded as benign boilerplate).
        """
        if not artifacts:
            return []

        t0 = time.perf_counter()
        logger.info("[DTE] Classifying %d dead code artifact(s)", len(artifacts))

        # Build feature matrix
        X = self._build_feature_matrix(artifacts)

        # Predict class and probability
        try:
            y_pred    = self._model.predict(X)
            y_proba   = self._model.predict_proba(X)
        except Exception as exc:
            logger.warning("[DTE] Prediction failed: %s — defaulting to SCAFFOLDING", exc)
            for a in artifacts:
                a.dte_label      = DTEClass.SCAFFOLDING
                a.dte_confidence = 0.5
            return artifacts

        # Update artifact labels
        non_remnant: list[DeadCodeArtifact] = []
        class_counts: dict[str, int] = {k: 0 for k in _LABEL_TO_INT}

        for artifact, pred_int, proba_row in zip(artifacts, y_pred, y_proba):
            dte_class = _INT_TO_DTECLASS.get(int(pred_int), DTEClass.SCAFFOLDING)
            confidence = float(proba_row[int(pred_int)])

            artifact.dte_label      = dte_class
            artifact.dte_confidence = round(confidence, 4)

            cls_str = dte_class.value
            class_counts[_LABEL_TO_INT.get(cls_str, 1)] = class_counts.get(
                _LABEL_TO_INT.get(cls_str, 1), 0
            ) + 1  # type: ignore

            if dte_class != DTEClass.REMNANT:
                non_remnant.append(artifact)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Count by class
        remnant_count    = sum(1 for a in artifacts if a.dte_label == DTEClass.REMNANT)
        scaffold_count   = sum(1 for a in artifacts if a.dte_label == DTEClass.SCAFFOLDING)
        logic_bomb_count = sum(1 for a in artifacts if a.dte_label == DTEClass.LOGIC_BOMB)
        dropper_count    = sum(1 for a in artifacts if a.dte_label == DTEClass.ENCRYPTED_DROPPER)

        logger.info(
            "[DTE] Complete in %.1f ms | REMNANT=%d (discarded) | "
            "SCAFFOLDING=%d | LOGIC_BOMB=%d | ENCRYPTED_DROPPER=%d",
            elapsed_ms, remnant_count, scaffold_count, logic_bomb_count, dropper_count,
        )
        return non_remnant

    # ─────────────────────────────────────────────────────────
    #  FEATURE MATRIX
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _build_feature_matrix(artifacts: list[DeadCodeArtifact]) -> np.ndarray:
        """
        Build an (N, 4) feature matrix from the artifact list.

        Feature vector layout (matches settings.DTE_FEATURE_* indices):
          [0] trigger_depth    → int   [0, ∞)
          [1] guard_entropy    → float [0.0, 8.0]
          [2] api_sensitivity  → float [0.0, 1.0]
          [3] guard_indegree   → int   [0, ∞)
        """
        rows = []
        for a in artifacts:
            row = [0.0, 0.0, 0.0, 0.0]
            row[DTE_FEATURE_TRIGGER_DEPTH]   = float(a.trigger_depth)
            row[DTE_FEATURE_GUARD_ENTROPY]   = float(a.guard_entropy)
            row[DTE_FEATURE_API_SENSITIVITY] = float(a.api_sensitivity)
            row[DTE_FEATURE_GUARD_INDEGREE]  = float(a.guard_indegree)
            rows.append(row)
        if not rows:
            return np.empty((0, 4), dtype=np.float32)
        return np.array(rows, dtype=np.float32)

    # ─────────────────────────────────────────────────────────
    #  MODEL MANAGEMENT
    # ─────────────────────────────────────────────────────────

    def _load_or_train_model(self) -> object:
        """Load saved model from disk or train a new one from synthetic data."""
        if os.path.isfile(_MODEL_CACHE_PATH):
            try:
                with open(_MODEL_CACHE_PATH, "rb") as fh:
                    model = pickle.load(fh)
                logger.info("[DTE] Loaded saved XGBoost model from %s", _MODEL_CACHE_PATH)
                return model
            except Exception as exc:
                logger.warning("[DTE] Failed to load saved model (%s) — retraining", exc)

        return self._train_model()

    def _train_model(self) -> object:
        """
        Train the DTE XGBoost classifier on a synthetic dataset.

        Synthetic data is generated from domain expert knowledge about the
        feature distributions of each class.  The class imbalance mirrors
        real-world APK populations (most dead code is benign SDK remnants).

        Class proportions:
          REMNANT (0)          : 5000 samples  (50%) — most dead code is benign
          SCAFFOLDING (1)      : 3000 samples  (30%) — common in MaaS binaries
          LOGIC_BOMB (2)       :  500 samples  (5%)  — rare but critical
          ENCRYPTED_DROPPER (3):  200 samples  (2%)  — very rare, high-value

        Total: ~8700 samples, stratified.
        """
        try:
            from xgboost import XGBClassifier  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "xgboost not installed. Run: pip install xgboost --break-system-packages"
            ) from exc

        logger.info("[DTE] Training synthetic XGBoost model (%d estimators)...", DTE_N_ESTIMATORS)
        t0 = time.perf_counter()
        rng = np.random.default_rng(seed=42)   # Reproducible

        X, y = self._generate_synthetic_data(rng)

        model = XGBClassifier(
            n_estimators    = DTE_N_ESTIMATORS,
            max_depth       = DTE_MAX_DEPTH,
            learning_rate   = DTE_LEARNING_RATE,
            n_jobs          = -1,
            use_label_encoder = False,
            eval_metric     = "mlogloss",
            random_state    = 42,
            subsample       = 0.8,
            colsample_bytree= 0.8,
        )
        model.fit(X, y)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info("[DTE] Model trained in %.1f ms", elapsed_ms)

        # Persist model to disk
        try:
            with open(_MODEL_CACHE_PATH, "wb") as fh:
                pickle.dump(model, fh, protocol=4)
            logger.info("[DTE] Model saved to %s", _MODEL_CACHE_PATH)
        except Exception as exc:
            logger.warning("[DTE] Could not save model: %s", exc)

        return model

    @staticmethod
    def _generate_synthetic_data(rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray]:
        """
        Generate synthetic training data for the DTE classifier.

        Feature distributions are derived from domain knowledge:

        REMNANT (0) — SDK boilerplate:
          • trigger_depth:   0-1  (no complex guards)
          • guard_entropy:   0.0-1.5 (low complexity)
          • api_sensitivity: 0.0-0.2 (benign APIs only)
          • guard_indegree:  2-15 (has callers in the larger framework)

        SCAFFOLDING (1) — Future capability stub:
          • trigger_depth:   0-2  (simple guards or none)
          • guard_entropy:   1.0-3.5 (moderate complexity)
          • api_sensitivity: 0.4-0.9 (sensitive APIs present)
          • guard_indegree:  0-2  (few/no callers → isolated)

        LOGIC_BOMB (2) — Conditional dormant payload:
          • trigger_depth:   3-8  (deeply nested guards)
          • guard_entropy:   3.0-6.0 (highly complex conditions)
          • api_sensitivity: 0.6-1.0 (destructive/spying APIs)
          • guard_indegree:  0-1  (isolated — triggered by time/event)

        ENCRYPTED_DROPPER (3) — Dynamic loader:
          • trigger_depth:   1-4  (moderate guards)
          • guard_entropy:   2.0-5.0 (obfuscated logic)
          • api_sensitivity: 0.9-1.0 (DexClassLoader = 0.9+)
          • guard_indegree:  0-1  (isolated)
        """
        samples_per_class = {0: 5000, 1: 3000, 2: 500, 3: 200}

        X_parts, y_parts = [], []

        # Class 0 — REMNANT
        n = samples_per_class[0]
        X_parts.append(np.column_stack([
            rng.integers(0, 2, size=n).astype(float),           # trigger_depth: 0-1
            rng.uniform(0.0, 1.5, size=n),                       # guard_entropy
            rng.uniform(0.0, 0.25, size=n),                      # api_sensitivity: low
            rng.integers(2, 16, size=n).astype(float),           # guard_indegree: has callers
        ]))
        y_parts.append(np.zeros(n, dtype=int))

        # Class 1 — SCAFFOLDING
        n = samples_per_class[1]
        X_parts.append(np.column_stack([
            rng.integers(0, 3, size=n).astype(float),            # trigger_depth: 0-2
            rng.uniform(1.0, 3.5, size=n),                       # guard_entropy: moderate
            rng.uniform(0.4, 0.9, size=n),                       # api_sensitivity: moderate-high
            rng.integers(0, 3, size=n).astype(float),            # guard_indegree: isolated
        ]))
        y_parts.append(np.ones(n, dtype=int))

        # Class 2 — LOGIC_BOMB
        n = samples_per_class[2]
        X_parts.append(np.column_stack([
            rng.integers(3, 9, size=n).astype(float),            # trigger_depth: 3-8 DEEP
            rng.uniform(3.0, 6.5, size=n),                       # guard_entropy: HIGH
            rng.uniform(0.6, 1.0, size=n),                       # api_sensitivity: high
            rng.integers(0, 2, size=n).astype(float),            # guard_indegree: isolated
        ]))
        y_parts.append(np.full(n, 2, dtype=int))

        # Class 3 — ENCRYPTED_DROPPER
        n = samples_per_class[3]
        X_parts.append(np.column_stack([
            rng.integers(1, 5, size=n).astype(float),            # trigger_depth: 1-4
            rng.uniform(2.0, 5.5, size=n),                       # guard_entropy: moderate-high
            rng.uniform(0.9, 1.01, size=n).clip(0, 1),           # api_sensitivity: 0.9-1.0 (DexClassLoader)
            rng.integers(0, 2, size=n).astype(float),            # guard_indegree: isolated
        ]))
        y_parts.append(np.full(n, 3, dtype=int))

        X = np.vstack(X_parts).astype(np.float32)
        y = np.concatenate(y_parts).astype(np.int32)

        # Shuffle
        idx = rng.permutation(len(X))
        return X[idx], y[idx]
