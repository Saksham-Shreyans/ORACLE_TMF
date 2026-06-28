"""Focused tests for Stage L research paper draft output."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent))
from engines.research_readiness import ResearchReadinessEngine
from models.mutation_artifact_graph import APKMetadata,DeadCodeArtifact,MutationArtifactGraph,MutationForecast
import pipeline.stage_l_report_synthesizer as stage_l
class TestStageLResearchPaper(unittest.TestCase):
    def test_direct_markdown_generator_emits_paper_draft(self):
        mag=MutationArtifactGraph()
        mag.apk_metadata=APKMetadata(sha256="b"*64,package_name="com.paper.demo")
        mag.malware_family="PaperDemo"
        mag.dead_code=[DeadCodeArtifact("Lcom/P;","future()V",".method",18)]
        mag.forecasts=[MutationForecast(predicted_technique="T1406",confidence_score=0.81,passes_gate=True)]
        mag.stage_timings_ms={"STAGE_A":1.0,"STAGE_C":1.0,"STAGE_F":1.0,"TARGETING":1.0,"STAGE_I":1.0}
        ResearchReadinessEngine().assess(mag)
        tmp_root=Path("C:/tmp")
        tmp_root.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=tmp_root)as tmp:
            original_dir=stage_l.REPORT_OUTPUT_DIR
            stage_l.REPORT_OUTPUT_DIR=tmp
            try:
                path=stage_l.ReportSynthesizer()._generate_research_paper_markdown(mag,"paper_demo")
            finally:
                stage_l.REPORT_OUTPUT_DIR=original_dir
            self.assertTrue(path)
            self.assertTrue(os.path.isfile(path))
            paper=Path(path).read_text(encoding="utf-8")
            self.assertIn("# ORACLE-TMF Case Study",paper)
            self.assertIn("## Research Readiness Metrics",paper)
            self.assertIn("## Stage 2 Intelligence Summary",paper)
            self.assertIn("## Ethics and Safety Statement",paper)
if __name__=="__main__":
    unittest.main(verbosity=2)
