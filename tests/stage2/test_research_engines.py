import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent.parent))
class _Meta:
    sha256="deadbeef00001111"
    package_name="com.test.sample"
class _DeadCode:
    def __init__(self,class_name="Lcom/T;",method_name="m()",smali_code="",
                 dte_label="SCAFFOLDING",dte_confidence=0.85):
        self.class_name=class_name
        self.method_name=method_name
        self.smali_code=smali_code
        self.dte_label=dte_label
        self.dte_confidence=dte_confidence
class _Perm:
    def __init__(self,name="android.permission.RECEIVE_SMS",risk="HIGH"):
        self.permission_name=name
        self.risk_level=risk
        self.declared_in_manifest=True
        self.used_in_code=False
class _String:
    def __init__(self,value="https://placeholder.example.com",entropy=3.8):
        self.value=value
        self.class_name="Lcom/C;"
        self.entropy=entropy
class _C2:
    def __init__(self,url="https://c2.example.com",framework="okhttp3",
                 class_name="Lcom/N;"):
        self.extracted_url=url
        self.class_name=class_name
        self.method_name="post"
        self.framework=framework
class _PartialAPI:
    def __init__(self,iface="android.accessibilityservice.AccessibilityService"):
        self.interface_extended=iface
        self.class_name="Lcom/A;"
        self.implemented_methods=2
        self.total_required_methods=6
class _Forecast:
    def __init__(self,technique="T1417 - GUI Input Capture",confidence=0.75):
        self.predicted_technique=technique
        self.confidence_score=confidence
        self.passes_gate=confidence>=0.6
        self.gate_threshold=0.6
class FakeMAG:
    def __init__(self,pkg="com.test.sample",family="TestFam",version="v1",
                 dead_code=None,perms=None,strings=None,c2s=None,
                 partial_apis=None,forecasts=None,manifest=None):
        self.apk_metadata=_Meta()
        self.apk_metadata.package_name=pkg
        self.apk_metadata.sha256=f"sha256_{pkg}"
        self.malware_family=family
        self.family_version=version
        self.dead_code=dead_code or[]
        self.unused_permissions=perms or[]
        self.placeholder_strings=strings or[]
        self.c2_stubs=c2s or[]
        self.partial_apis=partial_apis or[]
        self.unfinished_ui_flows=[]
        self.genai_scaffolds=[]
        self.nav_result=None
        self.forecasts=forecasts or[]
        self.manifest=manifest or{"receivers":[],"services":[],"activities":[]}
class TestKINSHIPBDVExtraction(unittest.TestCase):
    def setUp(self):
        from research.kinship.builder_dna import KINSHIPEngine
        self.engine=KINSHIPEngine()
    def _make_rich_mag(self):
        return FakeMAG(
            pkg="com.malware.banking",
            dead_code=[
                _DeadCode("Lcom/evil/OverlayHelper;","initOverlay",
                          '.method public initOverlay()V\n    const-string v0, "https://overlay.c2.com"\n    return-void\n.end method'),
                _DeadCode("Lcom/evil/SmsReader;","readSms",
                          '.method public readSms()V\n    invoke-virtual ...\n    return-void\n.end method'),
            ],
            perms=[_Perm("android.permission.SYSTEM_ALERT_WINDOW")],
            strings=[
                _String("https://banking.phish.example.com/api",4.2),
                _String("https://c2.evil.com/upload",3.9),
            ],
            c2s=[_C2("https://c2.example.com","okhttp3")],
            partial_apis=[_PartialAPI()],
        )
    def test_bdv_extraction_produces_valid_object(self):
        from research.kinship.builder_dna import BuilderDNAVector
        mag=self._make_rich_mag()
        bdv=self.engine.extract_bdv(mag)
        self.assertIsInstance(bdv,BuilderDNAVector)
        self.assertEqual(bdv.apk_package,"com.malware.banking")
    def test_char_ngram_frequencies_normalised(self):
        mag=self._make_rich_mag()
        bdv=self.engine.extract_bdv(mag)
        if bdv.char_ngram_freq:
            total=sum(bdv.char_ngram_freq.values())
            for freq in bdv.char_ngram_freq.values():
                self.assertGreaterEqual(freq,0.0)
                self.assertLessEqual(freq,1.0)
    def test_opcode_ngram_frequencies_normalised(self):
        mag=self._make_rich_mag()
        bdv=self.engine.extract_bdv(mag)
        for freq in bdv.opcode_ngram_freq.values():
            self.assertGreaterEqual(freq,0.0)
            self.assertLessEqual(freq,1.0)
    def test_entropy_statistics_correct(self):
        mag=self._make_rich_mag()
        bdv=self.engine.extract_bdv(mag)
        self.assertEqual(bdv.placeholder_count,2)
        self.assertGreater(bdv.entropy_mean,0.0)
        self.assertGreaterEqual(bdv.entropy_std,0.0)
        self.assertGreater(bdv.entropy_max,0.0)
    def test_c2_framework_fingerprint_extracted(self):
        mag=self._make_rich_mag()
        bdv=self.engine.extract_bdv(mag)
        self.assertEqual(bdv.c2_framework_fingerprint,"okhttp3")
    def test_partial_api_interfaces_extracted(self):
        mag=self._make_rich_mag()
        bdv=self.engine.extract_bdv(mag)
        self.assertIn("android.accessibilityservice.AccessibilityService",
                      bdv.partial_api_interfaces)
    def test_to_text_representation_is_nonempty(self):
        mag=self._make_rich_mag()
        bdv=self.engine.extract_bdv(mag)
        text=bdv.to_text_representation()
        self.assertIsInstance(text,str)
        self.assertGreater(len(text),10)
    def test_cosine_similarity_identical_vectors(self):
        from research.kinship.builder_dna import KINSHIPEngine
        vec=[0.1,0.5,0.3,0.8,0.2]
        score=KINSHIPEngine._cosine(vec,vec)
        self.assertAlmostEqual(score,1.0,places=4)
    def test_cosine_similarity_zero_vectors(self):
        from research.kinship.builder_dna import KINSHIPEngine
        vec_a=[0.1,0.5,0.3]
        vec_b=[0.0,0.0,0.0]
        score=KINSHIPEngine._cosine(vec_a,vec_b)
        self.assertEqual(score,0.0)
    def test_bdv_to_dict_structure(self):
        mag=self._make_rich_mag()
        bdv=self.engine.extract_bdv(mag)
        d=bdv.to_dict()
        required_keys=[
            "apk_hash","apk_package","entropy_mean","entropy_std",
            "c2_stub_count","c2_framework_fingerprint","partial_api_count",
        ]
        for key in required_keys:
            self.assertIn(key,d)
class TestMIRAGERobustness(unittest.TestCase):
    def setUp(self):
        from research.mirage.adversarial_optimizer import MIRAGEEngine
        self.engine=MIRAGEEngine()
    def _make_mag(self):
        return FakeMAG(
            dead_code=[_DeadCode()],
            perms=[_Perm()],
            strings=[_String()],
            c2s=[_C2()],
            forecasts=[_Forecast()],
        )
    def test_robustness_score_in_unit_interval(self):
        result=self.engine.analyze(self._make_mag(),forecasts=[_Forecast()])
        self.assertGreaterEqual(result.robustness_score,0.0)
        self.assertLessEqual(result.robustness_score,1.0)
    def test_all_candidates_have_valid_cost_scores(self):
        result=self.engine.analyze(self._make_mag())
        for candidate in result.poisoning_candidates:
            self.assertGreaterEqual(candidate.cost_score,0.0)
            self.assertLessEqual(candidate.cost_score,1.0)
    def test_most_vulnerable_class_is_known(self):
        from config.stage2_settings import MIRAGE_INJECTION_COSTS
        result=self.engine.analyze(self._make_mag())
        if result.most_vulnerable_class:
            self.assertIn(result.most_vulnerable_class,MIRAGE_INJECTION_COSTS)
    def test_easy_class_has_lower_cost_than_hard(self):
        result=self.engine.analyze(self._make_mag())
        costs={c.artifact_class:c.cost_score for c in result.poisoning_candidates}
        if "unused_permissions" in costs and "dead_code_scaffolding" in costs:
            self.assertLess(
                costs["unused_permissions"],
                costs["dead_code_scaffolding"],
                "Easy class must have lower injection cost than hard class",
            )
    def test_hardness_assignments_correct(self):
        from config.stage2_settings import MIRAGE_INJECTION_COSTS
        result=self.engine.analyze(self._make_mag())
        for candidate in result.poisoning_candidates:
            expected=MIRAGE_INJECTION_COSTS.get(candidate.artifact_class,{}).get("hardness")
            if expected:
                self.assertEqual(candidate.hardness,expected)
    def test_recommendations_are_strings(self):
        result=self.engine.analyze(self._make_mag())
        for rec in result.recommendations:
            self.assertIsInstance(rec,str)
            self.assertGreater(len(rec),10)
    def test_to_dict_structure_valid(self):
        result=self.engine.analyze(self._make_mag())
        d=result.to_dict()
        self.assertIn("robustness_score",d)
        self.assertIn("most_vulnerable_class",d)
        self.assertIn("candidates",d)
        self.assertIn("recommendations",d)
        self.assertIn("vulnerable_stages",d)
class TestCABALEngine(unittest.TestCase):
    def setUp(self):
        from research.cabal.collusion_engine import CABALEngine
        self.engine=CABALEngine()
    def test_single_apk_produces_empty_result(self):
        result=self.engine.run([FakeMAG()],use_llm=False)
        self.assertEqual(result.apks_analysed,1)
        self.assertEqual(len(result.collusion_paths),0)
    def test_two_apks_no_overlap_no_edges(self):
        mag_a=FakeMAG(pkg="com.apk.a")
        mag_b=FakeMAG(pkg="com.apk.b")
        result=self.engine.run([mag_a,mag_b],use_llm=False)
        self.assertEqual(result.total_edges_found,0)
    def test_same_package_not_colluding(self):
        from research.cabal.collusion_engine import IntentStub,IntentFilter
        stub=IntentStub(
            apk_package="com.same.package",
            action="android.provider.Telephony.SMS_RECEIVED",
        )
        intent_filter=IntentFilter(
            apk_package="com.same.package",
            action="android.provider.Telephony.SMS_RECEIVED",
            component_class="Lcom/SmsReceiver;",
        )
        score=self.engine._compute_compatibility(stub,intent_filter,use_llm=False)
        self.assertGreaterEqual(score,0.0)
    def test_pattern_matching_sms_bridge(self):
        from research.cabal.collusion_engine import IntentStub,IntentFilter
        stub=IntentStub(
            apk_package="com.apk.a",
            action="android.provider.Telephony.SMS_RECEIVED",
        )
        intent_filter=IntentFilter(
            apk_package="com.apk.b",
            action="android.provider.Telephony.RECEIVE_SMS",
            component_class="Lcom/SmsReceiver;",
        )
        score=self.engine._pattern_match_score(stub,intent_filter)
        self.assertGreaterEqual(score,0.75)
    def test_direct_action_match_scores_one(self):
        from research.cabal.collusion_engine import IntentStub,IntentFilter
        stub=IntentStub(action="android.intent.action.SEND")
        intent_filter=IntentFilter(action="android.intent.action.SEND")
        score=self.engine._pattern_match_score(stub,intent_filter)
        self.assertAlmostEqual(score,1.0)
    def test_mitre_mapping_returns_string(self):
        result_str=CABALEngine._map_to_mitre("SMS_BRIDGE")
        self.assertIsInstance(result_str,str)
        self.assertIn("T",result_str)
    def test_cabal_result_to_dict(self):
        from research.cabal.collusion_engine import CABALResult
        result=CABALResult(
            apks_analysed=3,
            total_edges_found=2,
            collusion_paths=[],
            high_confidence_paths=[],
            runtime_ms=42.0,
        )
        d=result.to_dict()
        self.assertIn("apks_analysed",d)
        self.assertIn("total_edges_found",d)
        self.assertIn("runtime_ms",d)
        self.assertIn("paths",d)
from research.cabal.collusion_engine import CABALEngine
class TestNetworkAttackAnalyzer(unittest.TestCase):
    def setUp(self):
        from research.network_attack.ddos_analyzer import NetworkAttackAnalyzer
        self.analyzer=NetworkAttackAnalyzer()
    def test_empty_mag_no_threats(self):
        result=self.analyzer.analyze(FakeMAG())
        self.assertEqual(len(result.detected_threats),0)
        self.assertEqual(result.highest_threat_level,"NONE")
        self.assertIsNone(result.dga_profile)
    def test_syn_flood_signature_detected(self):
        smali_with_raw_socket=(
            '.method public sendSyn()V\n'
            '    const-string v0, "socket(PF_INET, SOCK_RAW, IPPROTO_TCP)"\n'
            '    const-string v1, "IPPROTO_TCP"\n'
            '    const-string v2, "SOCK_RAW"\n'
            '    return-void\n'
            '.end method'
        )
        mag=FakeMAG(dead_code=[
            _DeadCode(smali_code=smali_with_raw_socket),
            _DeadCode(smali_code='    const-string v3, "JNI_OnLoad"'),
        ])
        result=self.analyzer.analyze(mag)
        vectors=[t.vector for t in result.detected_threats]
        self.assertIn("SYN Flood",vectors)
    def test_dga_pattern_detected(self):
        dga_smali=(
            '.method public generateDomain()V\n'
            '    invoke-virtual {v0}, Ljava/util/Random;->nextInt(I)I\n'
            '    invoke-virtual {v1}, Ljava/util/Date;->getTime()J\n'
            '    const-string v2, ".com"\n'
            '    const-string v3, ".net"\n'
            '    const-string v4, ".org"\n'
            '    return-void\n'
            '.end method'
        )
        mag=FakeMAG(dead_code=[_DeadCode(smali_code=dga_smali)])
        result=self.analyzer.analyze(mag)
        self.assertIsNotNone(result.dga_profile)
    def test_dga_seed_source_timestamp(self):
        dga_smali=(
            'invoke-virtual {v0}, Ljava/util/Date;->getTime()J\n'
            'invoke-virtual {v1}, Ljava/util/Random;->nextInt(I)I\n'
            '.com .net .org .info .biz'
        )
        mag=FakeMAG(dead_code=[
            _DeadCode(smali_code=dga_smali),
            _DeadCode(smali_code='const-string v0, "java/util/Date"'),
            _DeadCode(smali_code='const-string v0, "java/util/Random"'),
        ])
        result=self.analyzer.analyze(mag)
        if result.dga_profile:
            self.assertEqual(result.dga_profile.seed_source,"TIMESTAMP")
    def test_result_to_dict_structure(self):
        result=self.analyzer.analyze(FakeMAG())
        d=result.to_dict()
        required_keys=[
            "apk_hash","threat_count","highest_threat_level",
            "max_amplification_factor","has_dga","suricata_rules_count",
            "runtime_ms","threats",
        ]
        for key in required_keys:
            self.assertIn(key,d)
    def test_suricata_rules_are_strings(self):
        smali=(
            'socket(PF_INET, SOCK_RAW, IPPROTO_TCP) IPPROTO_TCP SOCK_RAW JNI_OnLoad '
            'Ljava/net/DatagramSocket;'
        )
        mag=FakeMAG(dead_code=[_DeadCode(smali_code=smali)])
        result=self.analyzer.analyze(mag)
        for rule in result.suricata_rules:
            self.assertIsInstance(rule,str)
            self.assertIn("alert",rule.lower())
    def test_stix_indicators_structure(self):
        smali='socket(PF_INET, SOCK_RAW, IPPROTO_TCP) SOCK_RAW IPPROTO_TCP JNI_OnLoad'
        mag=FakeMAG(dead_code=[_DeadCode(smali_code=smali)])
        result=self.analyzer.analyze(mag)
        for indicator in result.stix_indicators:
            self.assertEqual(indicator.get("type"),"indicator")
            self.assertEqual(indicator.get("spec_version"),"2.1")
            self.assertIn("name",indicator)
            self.assertIn("pattern_type",indicator)
if __name__=="__main__":
    unittest.main(verbosity=2)
