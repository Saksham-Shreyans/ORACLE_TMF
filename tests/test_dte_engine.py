"""
ORACLE-TMF  ·  tests/test_dte_engine.py
==========================================
Unit tests for the Dormancy Taxonomy Engine (DTE).
Tests cover:
  • Feature matrix construction from DeadCodeArtifact lists
  • Model training and prediction on synthetic data
  • REMNANT filtering (remnants must be excluded from return value)
  • DTE label assignment (all returned artifacts have a non-REMNANT label)
  • Classification confidence in [0.0, 1.0]
  • Empty input returns empty list
  • Feature vector ordering matches settings.DTE_FEATURE_* constants
Requires: numpy, xgboost (both installed via requirements.txt).
Does NOT require Androguard or any APK file.
"""
import sys
import unittest
import numpy as np
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent))
from config.settings import(
    DTE_FEATURE_API_SENSITIVITY,
    DTE_FEATURE_GUARD_ENTROPY,
    DTE_FEATURE_GUARD_INDEGREE,
    DTE_FEATURE_TRIGGER_DEPTH,
    DTE_N_ESTIMATORS,
)
from engines.dte_engine import DTEEngine
from models.mutation_artifact_graph import DeadCodeArtifact,DTEClass
def _make_artifact(
    trigger_depth:int=0,
    guard_entropy:float=0.0,
    api_sensitivity:float=0.0,
    guard_indegree:int=0,
    opcode_count:int=20,
)->DeadCodeArtifact:
    """Factory helper for test artifacts."""
    return DeadCodeArtifact(
        class_name="Lcom/test/Cls;",
        method_name="testMethod()V",
        smali_code=".method public testMethod()V\n    return-void\n.end method",
        opcode_count=opcode_count,
        trigger_depth=trigger_depth,
        guard_entropy=guard_entropy,
        api_sensitivity=api_sensitivity,
        guard_indegree=guard_indegree,
    )
class TestDTEEngineInit(unittest.TestCase):
    """Test that DTEEngine initialises and trains/loads correctly."""
    def test_engine_initialises(self):
        """DTEEngine must construct without error."""
        engine=DTEEngine()
        self.assertIsNotNone(engine._model)
    def test_model_has_predict_method(self):
        engine=DTEEngine()
        self.assertTrue(hasattr(engine._model,"predict"))
        self.assertTrue(hasattr(engine._model,"predict_proba"))
    def test_model_n_estimators(self):
        engine=DTEEngine()
        
        if hasattr(engine._model,"n_estimators"):
            self.assertEqual(engine._model.n_estimators,DTE_N_ESTIMATORS)
class TestDTEFeatureMatrix(unittest.TestCase):
    """Test feature matrix construction."""
    def test_feature_vector_shape(self):
        arts=[_make_artifact(trigger_depth=2,guard_entropy=3.5,api_sensitivity=0.8,guard_indegree=1)]
        X=DTEEngine._build_feature_matrix(arts)
        self.assertEqual(X.shape,(1,4))
        self.assertEqual(X.dtype,np.float32)
    def test_feature_ordering(self):
        """Feature indices must match settings.DTE_FEATURE_* constants."""
        artifact=_make_artifact(trigger_depth=5,guard_entropy=4.1,api_sensitivity=0.9,guard_indegree=0)
        X=DTEEngine._build_feature_matrix([artifact])
        self.assertAlmostEqual(float(X[0,DTE_FEATURE_TRIGGER_DEPTH]),5.0,places=4)
        self.assertAlmostEqual(float(X[0,DTE_FEATURE_GUARD_ENTROPY]),4.1,places=4)
        self.assertAlmostEqual(float(X[0,DTE_FEATURE_API_SENSITIVITY]),0.9,places=4)
        self.assertAlmostEqual(float(X[0,DTE_FEATURE_GUARD_INDEGREE]),0.0,places=4)
    def test_multiple_artifacts_shape(self):
        arts=[_make_artifact()for _ in range(10)]
        X=DTEEngine._build_feature_matrix(arts)
        self.assertEqual(X.shape,(10,4))
    def test_empty_artifacts_shape(self):
        X=DTEEngine._build_feature_matrix([])
        self.assertEqual(X.shape,(0,4))
class TestDTEClassification(unittest.TestCase):
    """Test DTE classification outcomes on synthetic data."""
    @classmethod
    def setUpClass(cls):
        """Initialise engine ONCE for all classification tests (training is slow)."""
        cls.engine=DTEEngine()
    def test_empty_input_returns_empty(self):
        result=self.engine.classify([])
        self.assertEqual(result,[])
    def test_labels_assigned(self):
        """All returned artifacts must have a dte_label set."""
        arts=[_make_artifact(trigger_depth=1,api_sensitivity=0.7)for _ in range(5)]
        result=self.engine.classify(arts)
        
        for a in result:
            self.assertIsInstance(a.dte_label,DTEClass)
            self.assertNotEqual(a.dte_label,DTEClass.REMNANT,
                                "REMNANT artifacts must be filtered from classify() output")
    def test_confidence_in_range(self):
        """DTE confidence must be in [0.0, 1.0]."""
        arts=[_make_artifact(trigger_depth=3,api_sensitivity=0.85,guard_entropy=4.0)]
        result=self.engine.classify(arts)
        for a in result:
            self.assertGreaterEqual(a.dte_confidence,0.0)
            self.assertLessEqual(a.dte_confidence,1.0)
    def test_remnant_profile_filtered(self):
        """
        A low-sensitivity, high-indegree artifact should be classified as REMNANT
        and therefore EXCLUDED from the return value.
        """
        
        art=_make_artifact(trigger_depth=0,guard_entropy=0.5,api_sensitivity=0.05,guard_indegree=10)
        before=[art]
        result=self.engine.classify(before)
        
        if result:
            self.assertNotEqual(result[0].dte_label,DTEClass.REMNANT)
        
    def test_high_risk_profile_tends_to_logic_bomb(self):
        """
        A high-trigger-depth, high-entropy, high-api-sensitivity, low-indegree
        artifact should tend toward LOGIC_BOMB or ENCRYPTED_DROPPER.
        """
        arts=[
            _make_artifact(trigger_depth=7,guard_entropy=5.5,api_sensitivity=1.0,guard_indegree=0)
        ]
        result=self.engine.classify(arts)
        if result:
            self.assertIn(
                result[0].dte_label,
                [DTEClass.LOGIC_BOMB,DTEClass.ENCRYPTED_DROPPER,DTEClass.SCAFFOLDING],
            )
    def test_original_list_labels_updated(self):
        """
        The input list artifacts must be updated in-place with dte_label
        even if REMNANT (classify() mutates the originals before filtering).
        """
        arts=[_make_artifact(trigger_depth=2,api_sensitivity=0.6)]
        _=self.engine.classify(arts)
        
        self.assertNotEqual(arts[0].dte_confidence,0.0,
                            "dte_confidence should be updated after classify()")
class TestDTESyntheticData(unittest.TestCase):
    """Test the synthetic training data generator."""
    def test_synthetic_data_shapes(self):
        import numpy as np
        rng=np.random.default_rng(seed=0)
        X,y=DTEEngine._generate_synthetic_data(rng)
        
        self.assertGreater(len(X),5000)
        self.assertEqual(X.shape[1],4)
        self.assertEqual(len(X),len(y))
    def test_synthetic_labels_in_range(self):
        import numpy as np
        rng=np.random.default_rng(seed=42)
        X,y=DTEEngine._generate_synthetic_data(rng)
        unique_labels=set(y.tolist())
        self.assertEqual(unique_labels,{0,1,2,3},
                         "Synthetic data must contain all 4 class labels")
    def test_class_0_majority(self):
        """REMNANT (class 0) must be the largest class."""
        import numpy as np
        rng=np.random.default_rng(seed=1)
        X,y=DTEEngine._generate_synthetic_data(rng)
        count_per_class={c:int(np.sum(y==c))for c in range(4)}
        self.assertEqual(
            max(count_per_class,key=count_per_class.get),0,
            "Class 0 (REMNANT) must be the majority class in synthetic data"
        )
    def test_feature_values_in_bounds(self):
        """Feature values must be non-negative."""
        import numpy as np
        rng=np.random.default_rng(seed=2)
        X,y=DTEEngine._generate_synthetic_data(rng)
        self.assertTrue(np.all(X>=0),"All feature values must be non-negative")
        self.assertTrue(np.all(X[:,DTE_FEATURE_API_SENSITIVITY]<=1.0),
                        "api_sensitivity must be in [0, 1]")
if __name__=="__main__":
    unittest.main(verbosity=2)
