import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent))
from config.settings import(
    ARTIFACT_DENSITY_SCORES,
    BAYESIAN_WEIGHT_D_ARTIFACT,
    BAYESIAN_WEIGHT_H_PRIOR,
    BAYESIAN_WEIGHT_P_LLM,
    CONFIDENCE_GATE_THRESHOLD,
    MVV_CLIP_HIGH,
    MVV_CLIP_LOW,
)
from models.mutation_artifact_graph import(
    C2EndpointStubArtifact,
    DeadCodeArtifact,
    DTEClass,
    MutationArtifactGraph,
    MutationForecast,
    UnusedPermissionArtifact,
    VersionDelta,
)
from pipeline.stage_k_bayesian_scorer import BayesianScorer
class TestBayesianWeights(unittest.TestCase):
    def test_weights_sum_to_one(self):
        total=BAYESIAN_WEIGHT_P_LLM+BAYESIAN_WEIGHT_D_ARTIFACT+BAYESIAN_WEIGHT_H_PRIOR
        self.assertAlmostEqual(total,1.0,places=9,
                               msg=f"Bayesian weights sum to{total},expected 1.0")
    def test_individual_weights(self):
        self.assertAlmostEqual(BAYESIAN_WEIGHT_P_LLM,0.45,places=9)
        self.assertAlmostEqual(BAYESIAN_WEIGHT_D_ARTIFACT,0.35,places=9)
        self.assertAlmostEqual(BAYESIAN_WEIGHT_H_PRIOR,0.20,places=9)
    def test_gate_threshold(self):
        self.assertEqual(CONFIDENCE_GATE_THRESHOLD,0.72)
    def test_mvv_clip_range(self):
        self.assertEqual(MVV_CLIP_LOW,0.5)
        self.assertEqual(MVV_CLIP_HIGH,1.5)
    def test_density_score_mapping(self):
        self.assertAlmostEqual(ARTIFACT_DENSITY_SCORES[1],0.33,places=9)
        self.assertAlmostEqual(ARTIFACT_DENSITY_SCORES[2],0.66,places=9)
        self.assertAlmostEqual(ARTIFACT_DENSITY_SCORES[3],1.00,places=9)
class TestBayesianFormula(unittest.TestCase):
    def setUp(self):
        self.scorer=BayesianScorer()
    def _make_mag_with_three_classes(self)->MutationArtifactGraph:
        mag=MutationArtifactGraph()
        mag.dead_code=[DeadCodeArtifact("Lcom/A;","m()V","",10,DTEClass.SCAFFOLDING)]
        mag.unused_permissions=[UnusedPermissionArtifact("android.permission.SEND_SMS")]
        mag.c2_stubs=[C2EndpointStubArtifact("Lcom/B;","c()V","OkHttp")]
        mag.malware_family="FluBot"
        mag.version_delta=VersionDelta(mvv_normalized=1.0)
        return mag
    def test_formula_high_confidence(self):
        mag=self._make_mag_with_three_classes()
        forecast=MutationForecast(p_llm=0.90,supporting_artifacts=["CLASS_1_DEAD_CODE"])
        forecasts_in=[forecast]
        original_get_prior=self.scorer._get_historical_prior
        self.scorer._get_historical_prior=lambda technique,family:0.50
        scored=self.scorer.run(forecasts_in,mag,rag=None)
        self.scorer._get_historical_prior=original_get_prior
        self.assertEqual(len(scored),1)
        result=scored[0]
        self.assertAlmostEqual(result.artifact_density,1.00,places=2)
        self.assertAlmostEqual(result.mvv_normalized,1.00,places=2)
        expected_c=0.45*0.90+0.35*1.00*1.00+0.20*0.50
        self.assertAlmostEqual(result.confidence_score,expected_c,places=2)
    def test_gate_passes_above_threshold(self):
        mag=self._make_mag_with_three_classes()
        forecast=MutationForecast(p_llm=0.95)
        self.scorer._get_historical_prior=lambda technique,family:0.80
        scored=self.scorer.run([forecast],mag,rag=None)
        self.assertTrue(scored[0].passes_gate,
                        f"Expected gate=True,C={scored[0].confidence_score:.3f}")
    def test_gate_fails_below_threshold(self):
        mag=MutationArtifactGraph()
        forecast=MutationForecast(p_llm=0.20)
        self.scorer._get_historical_prior=lambda technique,family:0.05
        scored=self.scorer.run([forecast],mag,rag=None)
        self.assertFalse(scored[0].passes_gate,
                         f"Expected gate=False,C={scored[0].confidence_score:.3f}")
    def test_empty_forecast_list_returns_empty(self):
        mag=MutationArtifactGraph()
        scored=self.scorer.run([],mag,rag=None)
        self.assertEqual(scored,[])
    def test_sorted_by_confidence_descending(self):
        mag=self._make_mag_with_three_classes()
        forecasts_in=[
            MutationForecast(p_llm=0.30,predicted_technique="T1001"),
            MutationForecast(p_llm=0.90,predicted_technique="T1568"),
            MutationForecast(p_llm=0.60,predicted_technique="T1406"),
        ]
        scored=self.scorer.run(forecasts_in,mag,rag=None)
        scores=[f.confidence_score for f in scored]
        self.assertEqual(scores,sorted(scores,reverse=True),
                         "Forecasts must be sorted by confidence descending")
    def test_probability_sanitisation(self):
        mag=self._make_mag_with_three_classes()
        forecast=MutationForecast(p_llm=1.0)
        self.scorer._get_historical_prior=lambda technique,family:1.0
        scored=self.scorer.run([forecast],mag,rag=None)
        c=scored[0].confidence_score
        self.assertGreaterEqual(c,0.0)
        self.assertLessEqual(c,1.0)
class TestArtifactDensity(unittest.TestCase):
    def setUp(self):
        self.scorer=BayesianScorer()
    def test_zero_artifacts(self):
        mag=MutationArtifactGraph()
        d=self.scorer._compute_artifact_density(mag)
        self.assertEqual(d,0.0)
    def test_one_class(self):
        mag=MutationArtifactGraph()
        mag.dead_code=[DeadCodeArtifact("Lcom/A;","m()V","",5)]
        d=self.scorer._compute_artifact_density(mag)
        self.assertAlmostEqual(d,0.33,places=2)
    def test_two_classes(self):
        mag=MutationArtifactGraph()
        mag.dead_code=[DeadCodeArtifact("Lcom/A;","m()V","",5)]
        mag.unused_permissions=[UnusedPermissionArtifact("android.permission.SEND_SMS")]
        d=self.scorer._compute_artifact_density(mag)
        self.assertAlmostEqual(d,0.66,places=2)
    def test_three_or_more_classes(self):
        mag=MutationArtifactGraph()
        mag.dead_code=[DeadCodeArtifact("Lcom/A;","m()V","",5)]
        mag.unused_permissions=[UnusedPermissionArtifact("android.permission.SEND_SMS")]
        mag.c2_stubs=[C2EndpointStubArtifact("Lcom/B;","c()V","OkHttp")]
        d=self.scorer._compute_artifact_density(mag)
        self.assertAlmostEqual(d,1.00,places=2)
    def test_seven_classes_capped_at_one(self):
        mag=MutationArtifactGraph()
        mag.dead_code=[DeadCodeArtifact("Lcom/A;","m()V","",5)]
        mag.unused_permissions=[UnusedPermissionArtifact("android.permission.SEND_SMS")]
        mag.c2_stubs=[C2EndpointStubArtifact("Lcom/B;","c()V","OkHttp")]
        mag.partial_apis=[PartialAPIArtifact("Lcom/C;","android/accessibilityservice/AccessibilityService")]
        mag.genai_scaffolds=[]
        d=self.scorer._compute_artifact_density(mag)
        self.assertLessEqual(d,1.0)
class TestMVVNorm(unittest.TestCase):
    def test_none_delta_returns_one(self):
        mvv=BayesianScorer._get_mvv_norm(None)
        self.assertEqual(mvv,1.0)
    def test_clips_below_low_bound(self):
        delta=VersionDelta(mvv_normalized=0.1)
        mvv=BayesianScorer._get_mvv_norm(delta)
        self.assertGreaterEqual(mvv,MVV_CLIP_LOW)
    def test_clips_above_high_bound(self):
        delta=VersionDelta(mvv_normalized=2.5)
        mvv=BayesianScorer._get_mvv_norm(delta)
        self.assertLessEqual(mvv,MVV_CLIP_HIGH)
    def test_normal_value_unchanged(self):
        delta=VersionDelta(mvv_normalized=1.2)
        mvv=BayesianScorer._get_mvv_norm(delta)
        self.assertAlmostEqual(mvv,1.2,places=5)
from models.mutation_artifact_graph import PartialAPIArtifact
if __name__=="__main__":
    unittest.main(verbosity=2)
