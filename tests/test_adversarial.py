from __future__ import annotations
import sys
from pathlib import Path
import pytest
PROJECT_ROOT=str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0,PROJECT_ROOT)
from engines.adversarial_robustness import AdversarialRobustnessTester
from engines.dte_engine import DTEEngine
from models.mutation_artifact_graph import DeadCodeArtifact,DTEClass
@pytest.fixture(scope="module")
def dte():
    return DTEEngine()
@pytest.fixture(scope="module")
def tester(dte):
    return AdversarialRobustnessTester(dte)
@pytest.fixture
def synthetic_artifacts():
    artifacts=[]
    for i in range(10):
        art=DeadCodeArtifact(
            class_name=f"com.example.Test{i}",
            method_name="testMethod",
            smali_code="invoke-virtual",
            opcode_count=5,
            pseudo_java="void testMethod() {}"
        )
        art.trigger_depth=float(i)
        art.guard_entropy=0.5
        art.api_sensitivity=0.2
        art.guard_indegree=1.0
        art.dte_label=DTEClass.REMNANT if i%2==0 else DTEClass.LOGIC_BOMB
        artifacts.append(art)
    return artifacts
class TestAdversarialRobustnessTester:
    def test_evaluate_empty(self,tester):
        report=tester.evaluate([])
        assert "overall_stability" in report
        assert report["overall_stability"]==1.0
    def test_evaluate_structure(self,tester,synthetic_artifacts):
        report=tester.evaluate(synthetic_artifacts)
        assert "overall_stability" in report
        assert "per_class_stability" in report
        assert "avg_boundary_distance" in report
        assert "vulnerable_artifacts" in report
        assert "epsilon_stability_curve" in report
        assert "perturbation_matrix" in report
        assert 0.0<=report["overall_stability"]<=1.0
        assert isinstance(report["vulnerable_artifacts"],list)
        assert isinstance(report["perturbation_matrix"],list)
        assert len(report["perturbation_matrix"])==len(synthetic_artifacts)
    def test_per_class_stability(self,tester,synthetic_artifacts):
        report=tester.evaluate(synthetic_artifacts)
        per_class=report["per_class_stability"]
        assert DTEClass.REMNANT.value in per_class
        assert DTEClass.LOGIC_BOMB.value in per_class
