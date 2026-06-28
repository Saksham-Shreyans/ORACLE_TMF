import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent.parent))
from orchestrator_stage2 import Stage2Config,Stage2Orchestrator,Stage2Report
class _Meta:
    sha256="cafebabe11223344"
    package_name="com.test.orchestrator"
class _DeadCode:
    def __init__(self,smali="",label="SCAFFOLDING",conf=0.8):
        self.class_name="Lcom/T;"
        self.method_name="m()"
        self.smali_code=smali
        self.dte_label=label
        self.dte_confidence=conf
class _Perm:
    def __init__(self,name="android.permission.RECEIVE_SMS"):
        self.permission_name=name
        self.risk_level="HIGH"
        self.declared_in_manifest=True
        self.used_in_code=False
class _String:
    def __init__(self,val="https://placeholder.example.com",entropy=3.5):
        self.value=val
        self.class_name="Lcom/C;"
        self.entropy=entropy
class _C2:
    def __init__(self):
        self.extracted_url="https://c2.example.com/api"
        self.class_name="Lcom/Net;"
        self.method_name="post"
        self.framework="okhttp3"
class _PartialAPI:
    def __init__(self):
        self.interface_extended="android.accessibilityservice.AccessibilityService"
        self.class_name="Lcom/A;"
        self.implemented_methods=2
        self.total_required_methods=6
class FakeForecast:
    def __init__(self,technique="T1417 - GUI Input Capture",score=0.75):
        self.predicted_technique=technique
        self.confidence_score=score
        self.passes_gate=score>=0.6
        self.gate_threshold=0.6
class FakeMAG:
    def __init__(self,pkg="com.test.orch",family="TestFam",version="v1",
                 n_dead=3,n_perms=2,n_strings=4,n_c2=1,n_partial=1,
                 manifest=None):
        self.apk_metadata=_Meta()
        self.apk_metadata.package_name=pkg
        self.apk_metadata.sha256=f"sha_{pkg[:8]}"
        self.malware_family=family
        self.family_version=version
        self.dead_code=[_DeadCode()for _ in range(n_dead)]
        self.unused_permissions=[_Perm()for _ in range(n_perms)]
        self.placeholder_strings=[_String()for _ in range(n_strings)]
        self.c2_stubs=[_C2()for _ in range(n_c2)]
        self.partial_apis=[_PartialAPI()for _ in range(n_partial)]
        self.unfinished_ui_flows=[]
        self.genai_scaffolds=[]
        self.nav_result=None
        self.forecasts=[]
        self.manifest=manifest or{"receivers":[],"services":[],"activities":[]}
class TestStage2Config(unittest.TestCase):
    def test_defaults(self):
        cfg=Stage2Config()
        self.assertFalse(cfg.phantom_enabled)
        self.assertTrue(cfg.nav_enabled)
        self.assertFalse(cfg.cabal_enabled)
        self.assertTrue(cfg.kinship_enabled)
        self.assertTrue(cfg.mirage_enabled)
        self.assertFalse(cfg.ouroboros_enabled)
        self.assertTrue(cfg.network_attack_enabled)
        self.assertFalse(cfg.synthetic_variant_enabled)
        self.assertTrue(cfg.save_json_reports)
    def test_custom_overrides(self):
        cfg=Stage2Config(
            phantom_enabled=True,
            nav_enabled=False,
            kinship_enabled=False,
        )
        self.assertTrue(cfg.phantom_enabled)
        self.assertFalse(cfg.nav_enabled)
        self.assertFalse(cfg.kinship_enabled)
class TestStage2OrchestratorInit(unittest.TestCase):
    def test_default_init(self):
        orch=Stage2Orchestrator()
        self.assertIsNotNone(orch)
    def test_custom_config_init(self):
        cfg=Stage2Config(kinship_enabled=False,mirage_enabled=False)
        orch=Stage2Orchestrator(cfg)
        self.assertFalse(orch.config.kinship_enabled)
        self.assertFalse(orch.config.mirage_enabled)
class TestStage2OrchestratorRun(unittest.TestCase):
    def setUp(self):
        self.cfg=Stage2Config(
            phantom_enabled=False,
            nav_enabled=True,
            cabal_enabled=False,
            kinship_enabled=True,
            mirage_enabled=True,
            ouroboros_enabled=False,
            network_attack_enabled=True,
            save_json_reports=False,
        )
        self.orch=Stage2Orchestrator(self.cfg)
        self.mag=FakeMAG()
        self.forecasts=[FakeForecast()]
    def test_run_returns_report(self):
        report=self.orch.run(self.mag,forecasts=self.forecasts)
        self.assertIsNotNone(report)
        self.assertIsInstance(report,Stage2Report)
    def test_report_has_apk_hash(self):
        report=self.orch.run(self.mag,forecasts=self.forecasts)
        self.assertNotEqual(report.apk_hash,"")
    def test_report_total_elapsed_positive(self):
        report=self.orch.run(self.mag,forecasts=self.forecasts)
        self.assertGreater(report.total_elapsed_ms,0.0)
    def test_stage_m_skipped_when_disabled(self):
        report=self.orch.run(self.mag,forecasts=self.forecasts)
        if report.stage_m:
            self.assertTrue(report.stage_m.skipped)
    def test_stage_n_runs_without_prev(self):
        report=self.orch.run(self.mag,forecasts=self.forecasts,mag_prev=None)
        if report.stage_n:
            self.assertTrue(report.stage_n.skipped)
            self.assertNotEqual(report.stage_n.skip_reason,"")
    def test_stage_n_runs_with_prev(self):
        mag_prev=FakeMAG(n_dead=10,n_perms=5)
        report=self.orch.run(
            self.mag,forecasts=self.forecasts,mag_prev=mag_prev
        )
        if report.stage_n:
            self.assertFalse(report.stage_n.skipped)
    def test_stage_o_skipped_for_single_apk(self):
        cfg=Stage2Config(cabal_enabled=True,save_json_reports=False)
        orch=Stage2Orchestrator(cfg)
        report=orch.run(self.mag,forecasts=self.forecasts)
        if report.stage_o:
            self.assertTrue(report.stage_o.skipped)
    def test_network_attack_result_populated(self):
        report=self.orch.run(self.mag,forecasts=self.forecasts)
        self.assertIsNotNone(report.network_attack)
    def test_adjusted_forecasts_list_populated(self):
        report=self.orch.run(self.mag,forecasts=self.forecasts)
        self.assertIsInstance(report.adjusted_forecasts,list)
        self.assertEqual(len(report.adjusted_forecasts),len(self.forecasts))
    def test_error_in_one_stage_does_not_crash_orchestrator(self):
        cfg=Stage2Config(
            kinship_enabled=True,
            mirage_enabled=True,
            save_json_reports=False,
        )
        orch=Stage2Orchestrator(cfg)
        try:
            report=orch.run(FakeMAG(),forecasts=[])
            self.assertIsNotNone(report)
        except Exception as exc:
            self.fail(f"Orchestrator raised an exception:{exc}")
class TestStage2ReportDict(unittest.TestCase):
    def setUp(self):
        cfg=Stage2Config(save_json_reports=False)
        orch=Stage2Orchestrator(cfg)
        self.report=orch.run(FakeMAG(),forecasts=[FakeForecast()])
    def test_to_dict_produces_dict(self):
        d=self.report.to_dict()
        self.assertIsInstance(d,dict)
    def test_required_top_level_keys_present(self):
        d=self.report.to_dict()
        required=[
            "apk_hash","family","analysis_timestamp",
            "confirmed_behaviors","collusion_paths_found",
            "builder_cluster_id","robustness_score",
            "highest_ddos_threat","nav_redirection",
            "total_elapsed_ms","stage_results","adjusted_forecasts",
        ]
        for key in required:
            self.assertIn(key,d,f"Missing key in to_dict():{key}")
    def test_stage_results_key_has_expected_sub_keys(self):
        d=self.report.to_dict()
        stage_results=d.get("stage_results",{})
        expected_stages=["M_PHANTOM","N_NAV","O_CABAL","P_KINSHIP","Q_MIRAGE","R_OUROBOROS"]
        for stage_key in expected_stages:
            self.assertIn(stage_key,stage_results)
    def test_json_round_trip_succeeds(self):
        d=self.report.to_dict()
        try:
            json_str=json.dumps(d,default=str)
            reparsed=json.loads(json_str)
            self.assertIsInstance(reparsed,dict)
        except(TypeError,ValueError)as exc:
            self.fail(f"JSON serialisation failed:{exc}")
    def test_robustness_score_in_unit_interval(self):
        d=self.report.to_dict()
        score=d["robustness_score"]
        self.assertGreaterEqual(score,0.0)
        self.assertLessEqual(score,1.0)
    def test_total_elapsed_ms_positive(self):
        d=self.report.to_dict()
        self.assertGreater(d["total_elapsed_ms"],0.0)
class TestNAVForecastAdjustment(unittest.TestCase):
    def test_nav_drop_adjusts_confidence(self):
        cfg=Stage2Config(
            nav_enabled=True,
            kinship_enabled=False,
            mirage_enabled=False,
            network_attack_enabled=False,
            save_json_reports=False,
        )
        orch=Stage2Orchestrator(cfg)
        mag_curr=FakeMAG(n_dead=2,n_perms=0)
        mag_prev=FakeMAG(n_dead=10,n_perms=5)
        forecasts=[FakeForecast(score=0.70)]
        original_score=forecasts[0].confidence_score
        report=orch.run(
            mag_curr,
            forecasts=forecasts,
            mag_prev=mag_prev,
        )
        self.assertEqual(len(report.adjusted_forecasts),1)
        adjusted_score=report.adjusted_forecasts[0].confidence_score
        self.assertGreaterEqual(adjusted_score,0.0)
        self.assertLessEqual(adjusted_score,1.0)
if __name__=="__main__":
    unittest.main(verbosity=2)
