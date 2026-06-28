"""Focused tests for the research readiness engine."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent))
from engines.research_readiness import ResearchReadinessEngine
from models.mutation_artifact_graph import(
    APKMetadata,
    C2EndpointStubArtifact,
    DeadCodeArtifact,
    DTEClass,
    GenAIAPIScaffoldArtifact,
    MutationArtifactGraph,
    MutationForecast,
    UnusedPermissionArtifact,
    VersionDelta,
)
class _NetworkResult:
    stix_indicators=[{"type":"indicator"}]
    def to_dict(self):
        return{
            "threat_count":1,
            "highest_threat_level":"HIGH",
            "max_amplification_factor":50.0,
            "has_dga":True,
            "suricata_rules_count":2,
        }
class _Stage2Report:
    stage_m=None
    stage_n=object()
    stage_o=None
    stage_p=object()
    stage_q=object()
    stage_r=None
    network_attack=_NetworkResult()
    confirmed_behaviors=[]
    collusion_paths_found=0
    builder_cluster_id=7
    robustness_score=0.81
    highest_ddos_threat="HIGH"
    nav_redirection="SMS_TO_DGA"
    adjusted_forecasts=[object()]
    total_elapsed_ms=12.5
def _make_mag()->MutationArtifactGraph:
    mag=MutationArtifactGraph()
    mag.apk_metadata=APKMetadata(
        sha256="a"*64,
        package_name="com.test.banker",
        version_name="2.0",
        version_code=20,
        file_size_bytes=12345,
    )
    mag.malware_family="TestBanker"
    mag.dead_code=[DeadCodeArtifact("Lcom/A;","run()V",".method",20,DTEClass.SCAFFOLDING,0.9)]
    mag.unused_permissions=[UnusedPermissionArtifact("android.permission.SEND_SMS")]
    mag.c2_stubs=[C2EndpointStubArtifact("Lcom/N;","post()V","OkHttp","https://c2.example/api")]
    mag.genai_scaffolds=[GenAIAPIScaffoldArtifact("Lcom/Ai;","ask()V","Gemini")]
    mag.version_delta=VersionDelta(mvv_normalized=1.2)
    mag.forecasts=[
        MutationForecast(
            predicted_tactic="TA0011",
            predicted_technique="T1568.002",
            technique_name="Domain Generation Algorithms",
            confidence_score=0.83,
            passes_gate=True,
        )
    ]
    mag.stage_timings_ms={
        "STAGE_A":1.0,
        "STAGE_C":1.0,
        "STAGE_F":1.0,
        "TARGETING":1.0,
        "STAGE_I":1.0,
    }
    return mag
class TestResearchReadinessEngine(unittest.TestCase):
    def test_assess_populates_readiness_and_stage2_summary(self):
        mag=_make_mag()
        report=ResearchReadinessEngine().assess(mag,_Stage2Report())
        self.assertIs(mag.research_readiness,report)
        self.assertIsNotNone(mag.stage2_intelligence)
        self.assertTrue(mag.stage2_intelligence.available)
        self.assertEqual(mag.stage2_intelligence.builder_cluster_id,7)
        self.assertEqual(mag.stage2_intelligence.highest_network_threat,"HIGH")
        self.assertEqual(mag.stage2_intelligence.suricata_rules_count,2)
        self.assertGreater(report.publication_readiness_score,0.5)
        self.assertGreater(report.stage2_intelligence_score,0.0)
        self.assertIn("Stage 2 intelligence fusion",[c["method"]for c in report.methodology_cards])
    def test_assess_without_stage2_records_safe_default_summary(self):
        mag=_make_mag()
        report=ResearchReadinessEngine().assess(mag,None)
        self.assertIsNotNone(mag.stage2_intelligence)
        self.assertFalse(mag.stage2_intelligence.available)
        self.assertEqual(mag.stage2_intelligence.safety_mode,"SAFE_STATIC_DEFAULT")
        self.assertIn("Stage 2 intelligence was not run"," ".join(report.limitations))
if __name__=="__main__":
    unittest.main(verbosity=2)
