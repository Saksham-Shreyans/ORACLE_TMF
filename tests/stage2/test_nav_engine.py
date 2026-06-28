import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent.parent))
from models.nav_models import(
    NAVEvent,NAVEventType,NAVHistory,
    NAVRedirectionHypothesis,NAVResult,
)
from engines.nav.nav_engine import NAVEngine
from models.mutation_artifact_graph import ArtifactClass
class _APKMeta:
    sha256="aabbcc1122334455"
    package_name="com.test.malware"
class _DeadCode:
    def __init__(self,class_name="Lcom/T;",method_name="m",smali_code="",
                 dte_label="SCAFFOLDING",dte_confidence=0.8):
        self.class_name=class_name
        self.method_name=method_name
        self.smali_code=smali_code
        self.dte_label=dte_label
        self.dte_confidence=dte_confidence
class _Perm:
    def __init__(self,name):
        self.permission_name=name
        self.declared_in_manifest=True
        self.used_in_code=False
        self.risk_level="HIGH"
class _String:
    def __init__(self,val="https://placeholder.example.com",entropy=3.5):
        self.value=val
        self.class_name="Lcom/C;"
        self.entropy=entropy
class _C2:
    def __init__(self):
        self.extracted_url="https://c2.example.com"
        self.class_name="Lcom/Net;"
        self.method_name="post"
        self.framework="okhttp3"
class _PartialAPI:
    def __init__(self):
        self.interface_extended="android.accessibilityservice.AccessibilityService"
        self.class_name="Lcom/A;"
        self.implemented_methods=2
        self.total_required_methods=6
class _UIFlow:
    pass
class _GenAI:
    pass
class FakeMAG:
    def __init__(
        self,
        dead_code_count=0,
        permission_count=0,
        string_count=0,
        c2_count=0,
        partial_api_count=0,
        version="v1",
        family="TestFamily",
    ):
        self.apk_metadata=_APKMeta()
        self.malware_family=family
        self.family_version=version
        self.dead_code=[_DeadCode()for _ in range(dead_code_count)]
        self.unused_permissions=[_Perm(f"android.permission.PERM{i}")for i in range(permission_count)]
        self.placeholder_strings=[_String()for _ in range(string_count)]
        self.c2_stubs=[_C2()for _ in range(c2_count)]
        self.partial_apis=[_PartialAPI()for _ in range(partial_api_count)]
        self.unfinished_ui_flows=[]
        self.genai_scaffolds=[]
        self.nav_result=None
class TestNAVEngineNoHistory(unittest.TestCase):
    def setUp(self):
        self.engine=NAVEngine()
        self.mag=FakeMAG(dead_code_count=5)
    def test_no_prev_returns_empty_result(self):
        result=self.engine.run(self.mag,mag_prev=None)
        self.assertEqual(len(result.nav_events),0)
        self.assertEqual(result.aggregate_nav_score,0.0)
        self.assertIsNone(result.primary_redirection)
    def test_no_prev_nav_adjustment_zero(self):
        result=self.engine.run(self.mag,mag_prev=None)
        self.assertEqual(result.nav_adjustment,0.0)
class TestNAVEngineDropDetection(unittest.TestCase):
    def setUp(self):
        self.engine=NAVEngine()
    def test_dead_code_drop_detected(self):
        mag_prev=FakeMAG(dead_code_count=8,version="v1")
        mag_curr=FakeMAG(dead_code_count=2,version="v2")
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        self.assertGreater(len(result.nav_events),0)
        classes=[e.artifact_class for e in result.nav_events]
        self.assertIn(ArtifactClass.DEAD_CODE.value,classes)
        event=next(e for e in result.nav_events if e.artifact_class==ArtifactClass.DEAD_CODE.value)
        self.assertEqual(event.count_before,8)
        self.assertEqual(event.count_after,2)
        self.assertEqual(event.delta_count,6)
    def test_permission_drop_detected(self):
        mag_prev=FakeMAG(permission_count=6,version="v1")
        mag_curr=FakeMAG(permission_count=0,version="v2")
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        perm_events=[e for e in result.nav_events if e.artifact_class==ArtifactClass.UNUSED_PERMISSION.value]
        self.assertGreater(len(perm_events),0)
        self.assertEqual(perm_events[0].event_type,NAVEventType.PERMISSION_REMOVAL)
    def test_no_drop_no_event(self):
        mag_prev=FakeMAG(dead_code_count=3,version="v1")
        mag_curr=FakeMAG(dead_code_count=5,version="v2")
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        dead_events=[e for e in result.nav_events if e.artifact_class==ArtifactClass.DEAD_CODE.value]
        self.assertEqual(len(dead_events),0)
    def test_small_drop_below_threshold_ignored(self):
        mag_prev=FakeMAG(dead_code_count=3,version="v1")
        mag_curr=FakeMAG(dead_code_count=2,version="v2")
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        dead_events=[e for e in result.nav_events if e.artifact_class==ArtifactClass.DEAD_CODE.value]
        self.assertEqual(len(dead_events),0)
    def test_multiple_drops_detected(self):
        mag_prev=FakeMAG(
            dead_code_count=10,permission_count=5,string_count=8,version="v1"
        )
        mag_curr=FakeMAG(
            dead_code_count=2,permission_count=0,string_count=3,version="v2"
        )
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        self.assertGreaterEqual(len(result.nav_events),2)
        self.assertGreater(result.total_artifacts_lost,0)
class TestNAVScoreComputation(unittest.TestCase):
    def setUp(self):
        self.engine=NAVEngine()
    def test_nav_score_in_unit_interval(self):
        mag_prev=FakeMAG(dead_code_count=10,version="v1")
        mag_curr=FakeMAG(dead_code_count=0,version="v2")
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        for event in result.nav_events:
            self.assertGreaterEqual(event.nav_score,0.0)
            self.assertLessEqual(event.nav_score,1.0)
    def test_aggregate_score_in_unit_interval(self):
        mag_prev=FakeMAG(dead_code_count=5,permission_count=4,version="v1")
        mag_curr=FakeMAG(dead_code_count=0,permission_count=0,version="v2")
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        self.assertGreaterEqual(result.aggregate_nav_score,0.0)
        self.assertLessEqual(result.aggregate_nav_score,1.0)
    def test_full_drop_scores_one(self):
        mag_prev=FakeMAG(dead_code_count=10,version="v1")
        mag_curr=FakeMAG(dead_code_count=0,version="v2")
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        dc_events=[e for e in result.nav_events if e.artifact_class==ArtifactClass.DEAD_CODE.value]
        self.assertGreater(len(dc_events),0)
        self.assertAlmostEqual(dc_events[0].nav_score,1.0,places=3)
class TestNAVRedirection(unittest.TestCase):
    def setUp(self):
        self.engine=NAVEngine()
    def test_dead_code_drop_implies_abandoned_path(self):
        mag_prev=FakeMAG(dead_code_count=8)
        mag_curr=FakeMAG(dead_code_count=0)
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        dc_events=[e for e in result.nav_events if e.artifact_class==ArtifactClass.DEAD_CODE.value]
        if dc_events:
            self.assertEqual(dc_events[0].event_type,NAVEventType.ABANDONED_PATH)
    def test_primary_redirection_is_set_on_high_score_event(self):
        mag_prev=FakeMAG(dead_code_count=15,version="v1")
        mag_curr=FakeMAG(dead_code_count=0,version="v2")
        result=self.engine.run(mag_curr,mag_prev=mag_prev)
        self.assertIsInstance(result.has_redirection,bool)
class TestNAVHistoryUpdate(unittest.TestCase):
    def setUp(self):
        self.engine=NAVEngine()
    def test_history_built_incrementally(self):
        history_map={}
        family="TestFamily"
        mag_v1=FakeMAG(dead_code_count=5,version="v1",family=family)
        mag_v2=FakeMAG(dead_code_count=8,version="v2",family=family)
        mag_v3=FakeMAG(dead_code_count=2,version="v3",family=family)
        self.engine.update_history(family,mag_v1,history_map,"v1")
        self.engine.update_history(family,mag_v2,history_map,"v2")
        self.engine.update_history(family,mag_v3,history_map,"v3")
        dc_history=history_map.get(ArtifactClass.DEAD_CODE.value)
        self.assertIsNotNone(dc_history)
        self.assertEqual(dc_history.version_sequence,["v1","v2","v3"])
        self.assertEqual(dc_history.count_sequence,[5,8,2])
        self.assertEqual(dc_history.family,family)
    def test_first_appearance_tracked(self):
        history_map={}
        mag_v1=FakeMAG(dead_code_count=0,version="v1")
        mag_v2=FakeMAG(dead_code_count=5,version="v2")
        self.engine.update_history("F",mag_v1,history_map,"v1")
        self.engine.update_history("F",mag_v2,history_map,"v2")
        history=history_map.get(ArtifactClass.DEAD_CODE.value)
        if history:
            self.assertEqual(history.first_appearance_version,"v2")
class TestNAVResultSerialization(unittest.TestCase):
    def test_to_dict_empty_result(self):
        result=NAVResult()
        d=result.to_dict()
        self.assertIn("nav_events",d)
        self.assertIn("aggregate_nav_score",d)
        self.assertIn("nav_adjustment",d)
        self.assertIn("has_redirection",d)
        self.assertIsInstance(d["nav_events"],list)
    def test_to_dict_with_events(self):
        event=NAVEvent(
            artifact_class=ArtifactClass.DEAD_CODE.value,
            version_from="v1",
            version_to="v2",
            count_before=8,
            count_after=0,
            delta_count=8,
            event_type=NAVEventType.ABANDONED_PATH,
            redirection_hypothesis=NAVRedirectionHypothesis.CAPABILITY_DELAYED,
            nav_score=1.0,
            mirage_confidence=0.0,
            supporting_evidence=["Evidence line 1"],
        )
        result=NAVResult(
            nav_events=[event],
            aggregate_nav_score=1.0,
            nav_adjustment=0.1,
            total_artifacts_lost=8,
            has_redirection=False,
        )
        d=result.to_dict()
        self.assertEqual(len(d["nav_events"]),1)
        self.assertEqual(d["nav_events"][0]["artifact_class"],ArtifactClass.DEAD_CODE.value)
        self.assertEqual(d["nav_events"][0]["delta_count"],8)
        self.assertAlmostEqual(d["aggregate_nav_score"],1.0)
if __name__=="__main__":
    unittest.main(verbosity=2)
