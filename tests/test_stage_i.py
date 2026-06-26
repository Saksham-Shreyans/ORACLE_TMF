"""
ORACLE-TMF  ·  tests/test_stage_i.py
=======================================
Unit tests for Stage I — Version Diff Engine.

Tests cover:
  • Empty delta when both MAGs are identical (same fingerprints)
  • Artifacts added (curr has more than prev)
  • Artifacts removed (prev has more than curr)
  • MVV_raw formula: n_added / (n_added + n_removed + 1)
  • MVV_normalized: clip(MVV_raw * 3.0, 0.5, 1.5)
  • Edit distance equals |added| + |removed|
  • None prev_mag → equivalent to empty baseline
  • Fingerprint set construction for all 7 artifact classes
  • High-velocity evolution → MVV clipped to 1.5

No external dependencies beyond the standard library.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import MVV_CLIP_HIGH, MVV_CLIP_LOW
from engines.dte_engine import DTEClass
from models.mutation_artifact_graph import (
    C2EndpointStubArtifact,
    DeadCodeArtifact,
    GenAIAPIScaffoldArtifact,
    MutationArtifactGraph,
    PartialAPIArtifact,
    PlaceholderStringArtifact,
    UnfinishedUIFlowArtifact,
    UnusedPermissionArtifact,
    VersionDelta,
)
from pipeline.stage_i_version_diff import VersionDiffEngine


def _dead(class_name: str, method: str = "m()V") -> DeadCodeArtifact:
    return DeadCodeArtifact(class_name=class_name, method_name=method, smali_code="", opcode_count=10)


def _perm(name: str) -> UnusedPermissionArtifact:
    return UnusedPermissionArtifact(permission_name=name)


def _c2(class_name: str, url: str = "") -> C2EndpointStubArtifact:
    return C2EndpointStubArtifact(class_name=class_name, method_name="c()V", framework="OkHttp", extracted_url=url)


class TestVersionDiffEngineBasic(unittest.TestCase):
    """Basic delta computation tests."""

    def setUp(self):
        self.engine = VersionDiffEngine()

    def test_identical_mags_zero_delta(self):
        """Identical current and previous MAG must produce zero-change delta."""
        mag = MutationArtifactGraph()
        mag.dead_code = [_dead("Lcom/evil/A;")]
        mag.unused_permissions = [_perm("android.permission.SEND_SMS")]

        delta = self.engine.run(mag_curr=mag, mag_prev=mag)

        self.assertEqual(len(delta.artifacts_added),   0)
        self.assertEqual(len(delta.artifacts_removed), 0)
        self.assertEqual(delta.edit_distance, 0.0)

    def test_none_prev_treated_as_empty(self):
        """If prev_mag is None, all current artifacts are treated as 'added'."""
        mag = MutationArtifactGraph()
        mag.dead_code           = [_dead("Lcom/evil/A;")]
        mag.unused_permissions  = [_perm("android.permission.SEND_SMS")]

        delta = self.engine.run(mag_curr=mag, mag_prev=None)

        self.assertEqual(len(delta.artifacts_added), 2,
                         "Both dead_code and unused_perm should be 'added' vs empty baseline")
        self.assertEqual(len(delta.artifacts_removed), 0)

    def test_artifacts_added(self):
        """New artifact in curr not in prev → appears in artifacts_added."""
        prev = MutationArtifactGraph()
        prev.dead_code = [_dead("Lcom/evil/A;")]

        curr = MutationArtifactGraph()
        curr.dead_code = [_dead("Lcom/evil/A;"), _dead("Lcom/evil/B;")]   # B is new

        delta = self.engine.run(mag_curr=curr, mag_prev=prev)
        self.assertEqual(len(delta.artifacts_added), 1)
        added_fps = [a.get("fingerprint", "") for a in delta.artifacts_added]
        self.assertTrue(any("B" in fp for fp in added_fps), "Lcom/evil/B; should be in added")

    def test_artifacts_removed(self):
        """Artifact in prev but not in curr → appears in artifacts_removed."""
        prev = MutationArtifactGraph()
        prev.dead_code = [_dead("Lcom/evil/A;"), _dead("Lcom/evil/Old;")]

        curr = MutationArtifactGraph()
        curr.dead_code = [_dead("Lcom/evil/A;")]   # Old removed

        delta = self.engine.run(mag_curr=curr, mag_prev=prev)
        self.assertEqual(len(delta.artifacts_removed), 1)
        removed_fps = [a.get("fingerprint", "") for a in delta.artifacts_removed]
        self.assertTrue(any("Old" in fp for fp in removed_fps))

    def test_edit_distance_equals_added_plus_removed(self):
        """Edit distance = |added| + |removed|."""
        prev = MutationArtifactGraph()
        prev.dead_code = [_dead("Lcom/evil/A;"), _dead("Lcom/evil/B;")]

        curr = MutationArtifactGraph()
        curr.dead_code = [_dead("Lcom/evil/A;"), _dead("Lcom/evil/C;")]   # B removed, C added

        delta = self.engine.run(mag_curr=curr, mag_prev=prev)
        expected_dist = len(delta.artifacts_added) + len(delta.artifacts_removed)
        self.assertEqual(delta.edit_distance, float(expected_dist))

    def test_permission_artifacts_tracked(self):
        """Unused permission artifacts must be tracked in the diff."""
        prev = MutationArtifactGraph()
        prev.unused_permissions = [_perm("android.permission.CAMERA")]

        curr = MutationArtifactGraph()
        curr.unused_permissions = [
            _perm("android.permission.CAMERA"),
            _perm("android.permission.SEND_SMS"),
        ]

        delta = self.engine.run(mag_curr=curr, mag_prev=prev)
        self.assertEqual(len(delta.artifacts_added), 1)
        added_types = [a.get("type") for a in delta.artifacts_added]
        self.assertIn("unused_permission", added_types)


class TestMVVFormula(unittest.TestCase):
    """Test the Mutation Velocity Vector formula."""

    def setUp(self):
        self.engine = VersionDiffEngine()

    def _make_delta(self, n_added: int, n_removed: int) -> VersionDelta:
        """Create MAGs with exactly n_added new artifacts and n_removed removed."""
        prev = MutationArtifactGraph()
        curr = MutationArtifactGraph()

        # Add artifacts in prev that won't be in curr (to be 'removed')
        prev.dead_code = [_dead(f"Lcom/evil/Removed{i};") for i in range(n_removed)]

        # Add artifacts in curr that weren't in prev (to be 'added')
        curr.dead_code = [_dead(f"Lcom/evil/Added{i};") for i in range(n_added)]

        return self.engine.run(mag_curr=curr, mag_prev=prev)

    def test_mvv_raw_formula(self):
        """MVV_raw = n_added / (n_added + n_removed + 1)."""
        n_added, n_removed = 6, 2
        delta = self._make_delta(n_added, n_removed)

        expected_raw = n_added / (n_added + n_removed + 1)
        self.assertAlmostEqual(delta.mvv_raw, round(expected_raw, 4), places=3)

    def test_mvv_normalized_clipped_low(self):
        """MVV_norm must never go below MVV_CLIP_LOW=0.5."""
        # 0 added, many removed → very low raw MVV
        delta = self._make_delta(0, 20)
        self.assertGreaterEqual(delta.mvv_normalized, MVV_CLIP_LOW)

    def test_mvv_normalized_clipped_high(self):
        """MVV_norm must never exceed MVV_CLIP_HIGH=1.5."""
        # Many added, 0 removed → potentially very high raw MVV
        delta = self._make_delta(100, 0)
        self.assertLessEqual(delta.mvv_normalized, MVV_CLIP_HIGH)

    def test_mvv_normalized_steady_state(self):
        """
        When n_added ≈ n_removed, MVV should be near 1.0.
        MVV_raw = 3 / (3+3+1) = 3/7 ≈ 0.429
        MVV_norm = clip(0.429 * 3.0, 0.5, 1.5) = clip(1.286, 0.5, 1.5) ≈ 1.286
        """
        delta = self._make_delta(3, 3)
        self.assertGreater(delta.mvv_normalized, MVV_CLIP_LOW)
        self.assertLess(delta.mvv_normalized,    MVV_CLIP_HIGH)

    def test_zero_changes_delta(self):
        """No changes at all → MVV_raw = 0/(0+0+1) = 0, MVV_norm = clip(0, 0.5, 1.5) = 0.5."""
        delta = self._make_delta(0, 0)
        self.assertAlmostEqual(delta.mvv_raw, 0.0, places=5)
        self.assertAlmostEqual(delta.mvv_normalized, MVV_CLIP_LOW, places=5)

    def test_mvv_in_bounds_always(self):
        """MVV_normalized must always be in [MVV_CLIP_LOW, MVV_CLIP_HIGH]."""
        for n_added, n_removed in [(0, 0), (0, 5), (5, 0), (10, 10), (100, 1), (1, 100)]:
            delta = self._make_delta(n_added, n_removed)
            self.assertGreaterEqual(delta.mvv_normalized, MVV_CLIP_LOW,
                                    f"MVV_norm too low for ({n_added},{n_removed})")
            self.assertLessEqual(delta.mvv_normalized, MVV_CLIP_HIGH,
                                 f"MVV_norm too high for ({n_added},{n_removed})")


class TestFingerprintConstruction(unittest.TestCase):
    """Test the _build_fingerprint_set method."""

    def setUp(self):
        self.engine = VersionDiffEngine()

    def test_dead_code_fingerprint(self):
        mag = MutationArtifactGraph()
        mag.dead_code = [_dead("Lcom/evil/A;", "run()V")]
        fps = self.engine._build_fingerprint_set(mag)
        self.assertIn("DC:Lcom/evil/A;::run()V", fps)

    def test_unused_permission_fingerprint(self):
        mag = MutationArtifactGraph()
        mag.unused_permissions = [_perm("android.permission.SEND_SMS")]
        fps = self.engine._build_fingerprint_set(mag)
        self.assertIn("UP:android.permission.SEND_SMS", fps)

    def test_placeholder_string_fingerprint(self):
        mag = MutationArtifactGraph()
        mag.placeholder_strings = [
            PlaceholderStringArtifact(value="http://dev.local/api", source="string_pool")
        ]
        fps = self.engine._build_fingerprint_set(mag)
        # Fingerprint uses first 64 chars of value
        self.assertTrue(any(fp.startswith("PS:") for fp in fps))

    def test_c2_stub_fingerprint(self):
        mag = MutationArtifactGraph()
        mag.c2_stubs = [_c2("Lcom/evil/Net;", "/api/v2/drop")]
        fps = self.engine._build_fingerprint_set(mag)
        self.assertTrue(any(fp.startswith("C2:") for fp in fps))

    def test_partial_api_fingerprint(self):
        mag = MutationArtifactGraph()
        mag.partial_apis = [PartialAPIArtifact(
            class_name="Lcom/evil/Acc;",
            interface_extended="android/accessibilityservice/AccessibilityService"
        )]
        fps = self.engine._build_fingerprint_set(mag)
        self.assertTrue(any(fp.startswith("PA:") for fp in fps))

    def test_unfinished_ui_fingerprint(self):
        mag = MutationArtifactGraph()
        mag.unfinished_ui_flows = [UnfinishedUIFlowArtifact(
            layout_file="res/layout/activity_fake_login.xml"
        )]
        fps = self.engine._build_fingerprint_set(mag)
        self.assertTrue(any(fp.startswith("UI:") for fp in fps))

    def test_genai_scaffold_fingerprint(self):
        mag = MutationArtifactGraph()
        mag.genai_scaffolds = [GenAIAPIScaffoldArtifact(
            class_name="Lcom/evil/Ai;", method_name="ask()V", provider="Gemini"
        )]
        fps = self.engine._build_fingerprint_set(mag)
        self.assertTrue(any(fp.startswith("GS:") for fp in fps))

    def test_empty_mag_empty_fingerprints(self):
        mag = MutationArtifactGraph()
        fps = self.engine._build_fingerprint_set(mag)
        self.assertEqual(len(fps), 0)


class TestClipHelper(unittest.TestCase):
    """Test the _clip utility method."""

    def test_clip_below(self):
        self.assertEqual(VersionDiffEngine._clip(0.1, 0.5, 1.5), 0.5)

    def test_clip_above(self):
        self.assertEqual(VersionDiffEngine._clip(2.0, 0.5, 1.5), 1.5)

    def test_clip_within(self):
        self.assertAlmostEqual(VersionDiffEngine._clip(1.2, 0.5, 1.5), 1.2, places=10)

    def test_clip_at_boundary_low(self):
        self.assertAlmostEqual(VersionDiffEngine._clip(0.5, 0.5, 1.5), 0.5, places=10)

    def test_clip_at_boundary_high(self):
        self.assertAlmostEqual(VersionDiffEngine._clip(1.5, 0.5, 1.5), 1.5, places=10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
