"""Lightweight tests for the upgraded FastAPI response contract."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent))
from api import AnalysisResponse,_build_stage2_config_dict
class TestAPIUpgradeContract(unittest.TestCase):
    def test_stage2_config_safe_default_disabled(self):
        self.assertIsNone(_build_stage2_config_dict(enable_stage2=False))
    def test_stage2_config_enables_safe_modules_without_lab_features(self):
        cfg=_build_stage2_config_dict(enable_stage2=True)
        self.assertTrue(cfg["nav_enabled"])
        self.assertTrue(cfg["kinship_enabled"])
        self.assertTrue(cfg["mirage_enabled"])
        self.assertTrue(cfg["network_attack_enabled"])
        self.assertFalse(cfg["phantom_enabled"])
        self.assertFalse(cfg["ouroboros_enabled"])
        self.assertFalse(cfg["synthetic_variant_enabled"])
    def test_analysis_response_accepts_research_and_stage2_summaries(self):
        response=AnalysisResponse(
            analysis_id="abc123",
            status="completed",
            research_readiness={
                "publication_readiness_score":0.7,
                "paper_readiness":"WORKSHOP_READY",
                "risk_tier":"HIGH",
            },
            stage2_summary={
                "available":True,
                "enabled_stages":["N_NAV","P_KINSHIP"],
                "highest_network_threat":"HIGH",
                "suricata_rules_count":2,
            },
        )
        self.assertEqual(response.research_readiness.paper_readiness,"WORKSHOP_READY")
        self.assertTrue(response.stage2_summary.available)
        self.assertEqual(response.stage2_summary.suricata_rules_count,2)
if __name__=="__main__":
    unittest.main(verbosity=2)
