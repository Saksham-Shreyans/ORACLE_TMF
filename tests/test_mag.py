"""
ORACLE-TMF  ·  tests/test_mag.py
==================================
Unit tests for the MutationArtifactGraph (MAG) data schema.

Tests cover:
  • Dataclass instantiation for all 7 artifact types
  • MAG serialisation (to_dict, to_json, to_llm_context)
  • MAG deserialisation (from_dict round-trip)
  • Computed properties (total_artifact_count, artifact_class_counts)
  • Bayesian density computation
  • LLM context truncation safety

These tests have ZERO external dependencies beyond the standard library.
They validate that the shared data schema behaves correctly in isolation.
"""

import json
import sys
import unittest
from pathlib import Path

# Allow imports from project root regardless of cwd
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.mutation_artifact_graph import (
    APKMetadata,
    ArtifactClass,
    C2EndpointStubArtifact,
    DTEClass,
    DeadCodeArtifact,
    GenAIAPIScaffoldArtifact,
    MutationArtifactGraph,
    MutationForecast,
    PartialAPIArtifact,
    PlaceholderStringArtifact,
    UnfinishedUIFlowArtifact,
    UnusedPermissionArtifact,
    VersionDelta,
)


class TestAPKMetadata(unittest.TestCase):
    """Test APKMetadata dataclass."""

    def test_default_instantiation(self):
        m = APKMetadata()
        self.assertEqual(m.sha256, "")
        self.assertEqual(m.min_sdk, 0)
        self.assertFalse(m.is_packed)
        self.assertIsInstance(m.entry_points, list)

    def test_full_instantiation(self):
        m = APKMetadata(
            apk_path      = "/tmp/test.apk",
            package_name  = "com.evil.bank",
            sha256        = "abc123",
            is_packed     = True,
            packer_hint   = "StubApp",
            entry_points  = ["Lcom/evil/MainActivity;"],
        )
        self.assertEqual(m.package_name, "com.evil.bank")
        self.assertTrue(m.is_packed)
        self.assertEqual(len(m.entry_points), 1)


class TestDeadCodeArtifact(unittest.TestCase):
    """Test Class 1 artifact dataclass."""

    def test_default_label(self):
        a = DeadCodeArtifact(
            class_name  = "Lcom/evil/Payload;",
            method_name = "execute()V",
            smali_code  = ".method public execute()V\n    return-void\n.end method",
            opcode_count= 1,
        )
        self.assertEqual(a.dte_label, DTEClass.SCAFFOLDING)
        self.assertEqual(a.dte_confidence, 0.0)
        self.assertEqual(a.pseudo_java, "")

    def test_logic_bomb_assignment(self):
        a = DeadCodeArtifact(
            class_name   = "Lcom/evil/Bomb;",
            method_name  = "trigger()V",
            smali_code   = ".method public trigger()V\n    return-void\n.end method",
            opcode_count = 25,
            trigger_depth= 5,
            guard_entropy= 4.2,
            api_sensitivity=0.9,
        )
        a.dte_label = DTEClass.LOGIC_BOMB
        self.assertEqual(a.dte_label, DTEClass.LOGIC_BOMB)


class TestArtifactVariety(unittest.TestCase):
    """Smoke-test instantiation of all 7 artifact classes."""

    def test_unused_permission(self):
        a = UnusedPermissionArtifact(
            permission_name          = "android.permission.SEND_SMS",
            android_permission_group = "SMS",
            expected_apis            = ["android/telephony/SmsManager;->sendTextMessage("],
        )
        self.assertEqual(a.permission_name, "android.permission.SEND_SMS")

    def test_placeholder_string(self):
        a = PlaceholderStringArtifact(
            value           = "http://dev-c2-v2.local/api/upload",
            source          = "string_pool",
            entropy         = 4.1,
            matched_pattern = "staging_url",
        )
        self.assertGreater(a.entropy, 0)

    def test_c2_stub(self):
        a = C2EndpointStubArtifact(
            class_name    = "Lcom/evil/NetClient;",
            method_name   = "init()V",
            framework     = "OkHttpClient",
            extracted_url = "/api/v2/exfiltrate",
            http_method   = "POST",
        )
        self.assertEqual(a.framework, "OkHttpClient")

    def test_partial_api(self):
        a = PartialAPIArtifact(
            class_name         = "Lcom/evil/A11y;",
            interface_extended = "android/accessibilityservice/AccessibilityService",
            method_stubs       = ["onAccessibilityEvent"],
            opcode_counts      = {"onAccessibilityEvent": 3},
        )
        self.assertIn("onAccessibilityEvent", a.method_stubs)

    def test_unfinished_ui(self):
        a = UnfinishedUIFlowArtifact(
            layout_file    = "res/layout/activity_fake_login.xml",
            suspected_type = "phishing_overlay",
            asset_refs     = ["ic_hdfc_logo", "btn_login"],
        )
        self.assertEqual(a.suspected_type, "phishing_overlay")

    def test_genai_scaffold(self):
        a = GenAIAPIScaffoldArtifact(
            class_name   = "Lcom/evil/AiBot;",
            method_name  = "askGemini()V",
            provider     = "Gemini",
            api_endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro",
            model_hint   = "gemini-1.5-pro",
        )
        self.assertEqual(a.provider, "Gemini")


class TestMutationArtifactGraph(unittest.TestCase):
    """Test the root MAG schema."""

    def _make_populated_mag(self) -> MutationArtifactGraph:
        mag = MutationArtifactGraph()
        mag.apk_metadata   = APKMetadata(sha256="deadbeef", package_name="com.evil.trojan")
        mag.malware_family = "SpyNote"
        mag.family_version = "v4.1"

        mag.dead_code = [
            DeadCodeArtifact("Lcom/evil/A;", "run()V", ".method", 20, DTEClass.SCAFFOLDING, 0.85)
        ]
        mag.unused_permissions = [
            UnusedPermissionArtifact("android.permission.SEND_SMS")
        ]
        mag.c2_stubs = [
            C2EndpointStubArtifact("Lcom/evil/Net;", "connect()V", "OkHttp", "/api/drop")
        ]
        mag.genai_scaffolds = [
            GenAIAPIScaffoldArtifact("Lcom/evil/Ai;", "ask()V", "Gemini")
        ]
        mag.forecasts = [
            MutationForecast(
                predicted_tactic   = "TA0011",
                predicted_technique= "T1568.002",
                technique_name     = "Domain Generation Algorithms",
                p_llm              = 0.82,
                confidence_score   = 0.78,
                passes_gate        = True,
            )
        ]
        return mag

    def test_total_artifact_count(self):
        mag = self._make_populated_mag()
        # dead(1) + unused_perm(1) + c2(1) + genai(1) = 4
        self.assertEqual(mag.total_artifact_count(), 4)

    def test_artifact_class_counts(self):
        mag = self._make_populated_mag()
        counts = mag.artifact_class_counts()
        self.assertEqual(counts[ArtifactClass.DEAD_CODE.value], 1)
        self.assertEqual(counts[ArtifactClass.UNUSED_PERMISSION.value], 1)
        self.assertEqual(counts[ArtifactClass.C2_ENDPOINT_STUB.value], 1)
        self.assertEqual(counts[ArtifactClass.GENAI_API_SCAFFOLD.value], 1)
        self.assertEqual(counts[ArtifactClass.PARTIAL_API.value], 0)

    def test_high_confidence_forecasts(self):
        mag = self._make_populated_mag()
        passed = mag.high_confidence_forecasts(threshold=0.72)
        self.assertEqual(len(passed), 1)
        self.assertEqual(passed[0].predicted_technique, "T1568.002")

    def test_high_confidence_filter(self):
        mag = self._make_populated_mag()
        # Raise the threshold above the forecast's score
        passed = mag.high_confidence_forecasts(threshold=0.90)
        self.assertEqual(len(passed), 0)

    def test_scaffolding_artifacts(self):
        mag = self._make_populated_mag()
        scaffolding = mag.scaffolding_artifacts()
        self.assertEqual(len(scaffolding), 1)
        self.assertEqual(scaffolding[0].dte_label, DTEClass.SCAFFOLDING)

    def test_compute_artifact_density_three_classes(self):
        mag = self._make_populated_mag()
        # dead + unused_perm + c2 = 3 classes active → density 1.0
        density = mag.compute_artifact_density()
        self.assertEqual(density, 1.00)

    def test_compute_artifact_density_one_class(self):
        mag = MutationArtifactGraph()
        mag.dead_code = [DeadCodeArtifact("Lcom/A;", "m()V", "", 10)]
        density = mag.compute_artifact_density()
        self.assertEqual(density, 0.33)

    def test_compute_artifact_density_empty(self):
        mag = MutationArtifactGraph()
        self.assertEqual(mag.compute_artifact_density(), 0.0)


class TestMAGSerialisation(unittest.TestCase):
    """Test MAG serialisation and round-trip fidelity."""

    def _make_mag(self) -> MutationArtifactGraph:
        mag = MutationArtifactGraph()
        mag.apk_metadata   = APKMetadata(sha256="cafebabe", package_name="com.test.app")
        mag.malware_family = "FluBot"
        mag.dead_code      = [DeadCodeArtifact("Lcom/A;", "run()V", ".method\n    return-void", 5)]
        mag.unused_permissions = [UnusedPermissionArtifact("android.permission.CAMERA")]
        mag.forecasts      = [MutationForecast(predicted_technique="T1406", confidence_score=0.75, passes_gate=True)]
        mag.stage_timings_ms = {"STAGE_A": 120.5, "STAGE_B": 2540.3}
        mag.stage_errors     = {}
        return mag

    def test_to_dict_structure(self):
        mag  = self._make_mag()
        data = mag.to_dict()
        self.assertIn("apk_metadata", data)
        self.assertIn("mutation_artifacts", data)
        self.assertIn("forecasts", data)
        self.assertIn("stage_timings_ms", data)
        self.assertEqual(data["malware_family"], "FluBot")
        self.assertEqual(data["apk_metadata"]["sha256"], "cafebabe")

    def test_to_json_valid(self):
        mag  = self._make_mag()
        raw  = mag.to_json()
        data = json.loads(raw)   # Must not raise
        self.assertEqual(data["malware_family"], "FluBot")
        self.assertEqual(len(data["mutation_artifacts"]["dead_code"]), 1)

    def test_to_llm_context_respects_limit(self):
        mag = self._make_mag()
        # Add a very large smali_code to force truncation
        mag.dead_code[0].smali_code = "x" * 100_000
        ctx = mag.to_llm_context(max_chars=5000)
        self.assertLessEqual(len(ctx), 5200)   # Allow small margin for truncation marker

    def test_from_dict_round_trip(self):
        mag_orig = self._make_mag()
        data     = mag_orig.to_dict()
        mag_rt   = MutationArtifactGraph.from_dict(data)
        self.assertEqual(mag_rt.malware_family, "FluBot")
        self.assertEqual(mag_rt.apk_metadata.sha256, "cafebabe")
        self.assertEqual(len(mag_rt.dead_code), 1)
        self.assertEqual(mag_rt.dead_code[0].class_name, "Lcom/A;")

    def test_to_dict_no_external_deps(self):
        """Serialisation must work with zero external libraries."""
        mag = MutationArtifactGraph()
        try:
            mag.to_dict()
            mag.to_json()
        except ImportError as exc:
            self.fail(f"to_dict/to_json raised ImportError: {exc}")


class TestVersionDelta(unittest.TestCase):
    """Test VersionDelta dataclass."""

    def test_default_mvv(self):
        delta = VersionDelta()
        self.assertEqual(delta.mvv_normalized, 1.0)
        self.assertEqual(delta.mvv_raw, 1.0)
        self.assertEqual(delta.edit_distance, 0.0)

    def test_populated_delta(self):
        delta = VersionDelta(
            artifacts_added   = [{"type": "dead_code"}],
            artifacts_removed = [],
            edit_distance     = 1.0,
            mvv_raw           = 0.5,
            mvv_normalized    = 1.0,
        )
        self.assertEqual(len(delta.artifacts_added), 1)


class TestMutationForecast(unittest.TestCase):
    """Test MutationForecast dataclass."""

    def test_gate_default_false(self):
        f = MutationForecast()
        self.assertFalse(f.passes_gate)
        self.assertEqual(f.confidence_score, 0.0)

    def test_gate_true_when_set(self):
        f = MutationForecast(confidence_score=0.85, passes_gate=True)
        self.assertTrue(f.passes_gate)

    def test_supporting_artifacts_list(self):
        f = MutationForecast(
            supporting_artifacts = ["CLASS_1_DEAD_CODE", "CLASS_4_C2_ENDPOINT_STUB"]
        )
        self.assertEqual(len(f.supporting_artifacts), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
