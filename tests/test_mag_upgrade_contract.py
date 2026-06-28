"""Upgrade contract tests for MAG research and Stage 2 serialization."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent))
from models.mutation_artifact_graph import(
    MutationArtifactGraph,
    ResearchReadinessReport,
    Stage2IntelligenceSummary,
)
class TestMAGUpgradeContract(unittest.TestCase):
    def test_research_and_stage2_summary_round_trip(self):
        mag=MutationArtifactGraph()
        mag.stage2_intelligence=Stage2IntelligenceSummary(
            available=True,
            enabled_stages=["N_NAV","P_KINSHIP","NETWORK_ATTACK"],
            builder_cluster_id=42,
            highest_network_threat="HIGH",
            suricata_rules_count=3,
            safety_mode="SAFE_STATIC_DEFAULT",
        )
        mag.research_readiness=ResearchReadinessReport(
            publication_readiness_score=0.71,
            paper_readiness="WORKSHOP_READY",
            risk_tier="HIGH",
            key_findings=["Stage 2 summary survived serialization."],
        )
        payload=mag.to_dict()
        self.assertIn("stage2_intelligence",payload)
        self.assertIn("research_readiness",payload)
        self.assertEqual(payload["stage2_intelligence"]["builder_cluster_id"],42)
        restored=MutationArtifactGraph.from_dict(payload)
        self.assertTrue(restored.stage2_intelligence.available)
        self.assertEqual(restored.stage2_intelligence.highest_network_threat,"HIGH")
        self.assertEqual(restored.research_readiness.paper_readiness,"WORKSHOP_READY")
if __name__=="__main__":
    unittest.main(verbosity=2)
