"""
ORACLE-TMF  ·  research/synthetic_variant/variant_generator.py
================================================================
Synthetic V(N+1) Generation — Stage 2 Tier 3.

PURPOSE (defensive only)
------------------------
Generates synthetic APK TEST FIXTURES for evaluating whether the ORACLE-TMF
forecasting pipeline correctly classifies staging variants.  This is
analogous to antivirus vendors creating labelled test malware samples to
benchmark detection accuracy.

What this generates
-------------------
  • Smali scaffold files (structural, not functional — no live C2, no payloads)
  • AndroidManifest.xml with controlled permission/component profiles
  • A MAG object with ground-truth technique label attached
  • APK wrappers using apktool reassemble (disabled by default, requires opt-in)

What this does NOT generate
----------------------------
  • Live C2 communication code
  • Functional payload delivery
  • Obfuscated dropper logic
  • Anything designed to evade real device security controls

Design principle: every generated file is structurally consistent with the
target staging pattern but behaviourally inert.  The only "malicious" aspects
are the artifact signatures (dead code blocks, unused permissions, placeholder
strings) that ORACLE-TMF's static analysis detects.

Two generation paths
--------------------
  Path 1 - MAG Synthesis:
    Generates a synthetic MAG object directly — no real APK file.
    Used for pipeline unit tests and regression testing.
    
  Path 2 - Smali Scaffold:
    Generates .smali template files that can be assembled with apktool.
    Produces an installable APK for PHANTOM detonation testing.
    Requires SYNTHETIC_AIRGAP_REQUIRED = True (no outbound connections).
    Requires explicit enable_apk_build=True from the caller.
"""
from __future__ import annotations

import hashlib
import logging
import os
import random
import string
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from config.stage2_settings import (
    SYNTHETIC_AIRGAP_REQUIRED,
    SYNTHETIC_APKTOOL_PATH,
    SYNTHETIC_MAX_APK_SIZE_BYTES,
    SYNTHETIC_WORK_DIR,
)
from models.mutation_artifact_graph import (
    DeadCodeArtifact,
    UnusedPermissionArtifact,
    PlaceholderStringArtifact,
    PartialAPIArtifact,
    C2EndpointStubArtifact,
    MutationArtifactGraph,
)

logger = logging.getLogger(__name__)

# ── Staging artifact profiles per technique family ───────────────────────────
# Defines what artifact counts a v_staging should have for each target technique
_STAGING_PROFILES: dict[str, dict] = {
    "T1417 - GUI Input Capture (ATS)": {
        "dead_code_count":      (3, 8),   # Overlay / Accessibility scaffolding
        "unused_permissions":   ["android.permission.SYSTEM_ALERT_WINDOW",
                                  "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "placeholder_strings":  (5, 15),  # ATS-related URL stubs
        "c2_stubs":             (1, 3),   # Partial HTTP C2 stub
        "partial_apis":         (1, 2),   # Partial AccessibilityService
    },
    "T1636.004 - Protected User Data: SMS": {
        "dead_code_count":      (2, 5),   # SMS reader scaffolding
        "unused_permissions":   ["android.permission.RECEIVE_SMS",
                                  "android.permission.READ_SMS"],
        "placeholder_strings":  (3, 10),
        "c2_stubs":             (1, 2),
        "partial_apis":         (1, 2),   # Partial BroadcastReceiver
    },
    "T1640 - Account Access Removal (Banking)": {
        "dead_code_count":      (4, 10),  # Banking UI overlay scaffolding
        "unused_permissions":   ["android.permission.SYSTEM_ALERT_WINDOW",
                                  "android.permission.GET_ACCOUNTS"],
        "placeholder_strings":  (8, 20),  # Bank-specific URL stubs
        "c2_stubs":             (2, 4),   # Multiple C2 channel stubs
        "partial_apis":         (2, 3),
    },
    "T1430 - Location Tracking": {
        "dead_code_count":      (1, 3),
        "unused_permissions":   ["android.permission.ACCESS_FINE_LOCATION",
                                  "android.permission.ACCESS_BACKGROUND_LOCATION"],
        "placeholder_strings":  (2, 8),
        "c2_stubs":             (1, 2),
        "partial_apis":         (1, 1),
    },
    "T1513 - Screen Capture": {
        "dead_code_count":      (2, 6),
        "unused_permissions":   ["android.permission.RECORD_AUDIO",
                                  "android.permission.WRITE_EXTERNAL_STORAGE"],
        "placeholder_strings":  (3, 12),
        "c2_stubs":             (1, 3),
        "partial_apis":         (1, 2),
    },
}


@dataclass
class SyntheticVariantSpec:
    """
    Specification for a single synthetic staging variant.

    Created by SyntheticVariantGenerator and passed to both
    the MAG synthesis path and the Smali scaffold path.
    """

    target_technique: str = ""
    seed: int = 0
    dead_code_count: int = 0
    unused_permissions: list[str] = field(default_factory=list)
    placeholder_count: int = 0
    c2_stub_count: int = 0
    partial_api_count: int = 0
    package_name: str = ""
    apk_hash: str = ""
    ground_truth_label: str = ""


@dataclass
class SyntheticMAGResult:
    """
    A synthetic MAG with ground-truth technique label.
    Used for pipeline regression testing.
    """

    mag: Optional[MutationArtifactGraph] = None
    spec: Optional[SyntheticVariantSpec] = None
    ground_truth_technique: str = ""
    generation_path: str = "MAG_SYNTHESIS"
    apk_path: Optional[str] = None   # Set only if APK was built


class SyntheticVariantGenerator:
    """
    Synthetic V(N+1) Staging Variant Generator.

    Generates labelled staging APK test fixtures for ORACLE-TMF
    pipeline evaluation and OUROBOROS training data.

    Usage (MAG synthesis — no real APK):
    >>> gen = SyntheticVariantGenerator()
    >>> result = gen.generate_mag("T1417 - GUI Input Capture (ATS)")
    >>> result = gen.generate_batch(technique_list, n_per_technique=5)

    Usage (Smali scaffold — produces buildable APK):
    >>> result = gen.generate_smali_scaffold("T1417 ...", enable_apk_build=True)
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)
        os.makedirs(SYNTHETIC_WORK_DIR, exist_ok=True)
        logger.info("[SyntheticVariant] Generator initialised (work_dir=%s)", SYNTHETIC_WORK_DIR)

    def generate_mag(
        self,
        target_technique: str,
        seed: Optional[int] = None,
    ) -> SyntheticMAGResult:
        """
        Generate a synthetic MAG directly (Path 1 — no real APK file).

        Parameters
        ----------
        target_technique : str
            The MITRE technique the staging variant is progressing toward.
        seed : int | None
            Random seed for reproducibility.

        Returns
        -------
        SyntheticMAGResult
        """
        rng = random.Random(seed or self._rng.randint(0, 2**31))
        spec = self._build_spec(target_technique, rng)

        mag = self._synthesize_mag(spec, rng)
        return SyntheticMAGResult(
            mag=mag,
            spec=spec,
            ground_truth_technique=target_technique,
            generation_path="MAG_SYNTHESIS",
        )

    def generate_batch(
        self,
        technique_list: Optional[list[str]] = None,
        n_per_technique: int = 3,
    ) -> list[SyntheticMAGResult]:
        """
        Generate a batch of synthetic staging variants.

        Parameters
        ----------
        technique_list : list[str] | None
            Techniques to generate variants for.  None = all known profiles.
        n_per_technique : int
            How many independent variants per technique.

        Returns
        -------
        list[SyntheticMAGResult]
        """
        techniques = technique_list or list(_STAGING_PROFILES.keys())
        results: list[SyntheticMAGResult] = []
        for technique in techniques:
            for i in range(n_per_technique):
                result = self.generate_mag(technique, seed=self._rng.randint(0, 2**31))
                results.append(result)
        logger.info(
            "[SyntheticVariant] Generated batch: %d variants across %d techniques",
            len(results), len(techniques),
        )
        return results

    def generate_smali_scaffold(
        self,
        target_technique: str,
        enable_apk_build: bool = False,
        seed: Optional[int] = None,
    ) -> SyntheticMAGResult:
        """
        Generate Smali scaffold files for a staging variant (Path 2).

        Parameters
        ----------
        target_technique : str
            Target MITRE technique.
        enable_apk_build : bool
            If True, run apktool to assemble a real APK.
            Default False — only writes smali files.
        seed : int | None
            Random seed.

        Returns
        -------
        SyntheticMAGResult
        """
        rng = random.Random(seed or self._rng.randint(0, 2**31))
        spec = self._build_spec(target_technique, rng)

        # Write scaffold files to work directory
        scaffold_dir = Path(SYNTHETIC_WORK_DIR) / f"scaffold_{spec.apk_hash[:8]}"
        scaffold_dir.mkdir(parents=True, exist_ok=True)

        self._write_manifest(scaffold_dir, spec)
        self._write_smali_scaffolds(scaffold_dir, spec, rng)

        apk_path: Optional[str] = None
        if enable_apk_build:
            apk_path = self._build_apk(scaffold_dir, spec)

        # Also synthesize a MAG for immediate pipeline use
        mag = self._synthesize_mag(spec, rng)

        logger.info(
            "[SyntheticVariant] Smali scaffold written: dir=%s apk_built=%s",
            scaffold_dir, apk_path is not None,
        )
        return SyntheticMAGResult(
            mag=mag,
            spec=spec,
            ground_truth_technique=target_technique,
            generation_path="SMALI_SCAFFOLD",
            apk_path=apk_path,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _build_spec(self, technique: str, rng: random.Random) -> SyntheticVariantSpec:
        """Build a SyntheticVariantSpec from a technique profile."""
        profile = _STAGING_PROFILES.get(technique, _STAGING_PROFILES[
            "T1417 - GUI Input Capture (ATS)"
        ])
        seed = rng.randint(0, 2**31)
        pkg = f"com.synthetic.stage2.{self._random_pkg(rng)}"
        apk_hash = hashlib.sha256(f"{technique}{seed}".encode()).hexdigest()

        dc_min, dc_max = profile["dead_code_count"]
        ph_min, ph_max = profile["placeholder_strings"]
        c2_min, c2_max = profile["c2_stubs"]
        pa_min, pa_max = profile["partial_apis"]

        return SyntheticVariantSpec(
            target_technique=technique,
            seed=seed,
            dead_code_count=rng.randint(dc_min, dc_max),
            unused_permissions=profile["unused_permissions"],
            placeholder_count=rng.randint(ph_min, ph_max),
            c2_stub_count=rng.randint(c2_min, c2_max),
            partial_api_count=rng.randint(pa_min, pa_max),
            package_name=pkg,
            apk_hash=apk_hash,
            ground_truth_label=technique,
        )

    def _synthesize_mag(
        self, spec: SyntheticVariantSpec, rng: random.Random
    ) -> MutationArtifactGraph:
        """Create a MutationArtifactGraph directly from a spec (no real APK)."""
        mag = MutationArtifactGraph()
        mag.malware_family = f"SYNTHETIC_{spec.target_technique[:20].replace(' ', '_')}"
        mag.apk_metadata.sha256 = spec.apk_hash
        mag.apk_metadata.package_name = spec.package_name
        mag.family_version = "v_staging_synthetic"

        # Dead code scaffolding blocks
        for i in range(spec.dead_code_count):
            class_name = f"Lcom/synthetic/{self._random_class(rng)};"
            mag.dead_code.append(DeadCodeArtifact(
                class_name=class_name,
                method_name=self._random_method(rng),
                smali_code=self._gen_stub_smali(rng),
                dte_label="SCAFFOLDING",
                dte_confidence=rng.uniform(0.72, 0.95),
            ))

        # Unused permissions
        for perm in spec.unused_permissions:
            mag.unused_permissions.append(UnusedPermissionArtifact(
                permission_name=perm,
                declared_in_manifest=True,
                used_in_code=False,
                risk_level="HIGH",
            ))

        # Placeholder strings
        for i in range(spec.placeholder_count):
            val = f"https://placeholder{rng.randint(1,99)}.example.com/api/v{i}"
            mag.placeholder_strings.append(PlaceholderStringArtifact(
                value=val,
                class_name=f"Lcom/synthetic/Config{i};",
                entropy=rng.uniform(3.2, 4.8),
            ))

        # C2 stubs
        for i in range(spec.c2_stub_count):
            mag.c2_stubs.append(C2EndpointStubArtifact(
                extracted_url=f"https://c2placeholder{i}.example.com",
                class_name=f"Lcom/synthetic/Network{i};",
                method_name="sendData",
                framework=rng.choice(["okhttp3", "retrofit2", "volley"]),
            ))

        # Partial APIs
        for i in range(spec.partial_api_count):
            mag.partial_apis.append(PartialAPIArtifact(
                interface_extended=rng.choice([
                    "android.accessibilityservice.AccessibilityService",
                    "android.content.BroadcastReceiver",
                    "android.app.admin.DeviceAdminReceiver",
                ]),
                class_name=f"Lcom/synthetic/Partial{i};",
                implemented_methods=rng.randint(1, 3),
                total_required_methods=rng.randint(4, 8),
            ))

        return mag

    # ─── Smali scaffold writers ───────────────────────────────────────────────

    def _write_manifest(self, scaffold_dir: Path, spec: SyntheticVariantSpec) -> None:
        """Write a minimal AndroidManifest.xml with the staging permissions."""
        perms = "\n    ".join(
            f'<uses-permission android:name="{p}"/>'
            for p in spec.unused_permissions
        )
        manifest = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            f'    package="{spec.package_name}">\n'
            f'    {perms}\n'
            '    <application android:label="@string/app_name">\n'
            '        <activity android:name=".MainActivity">\n'
            '            <intent-filter>\n'
            '                <action android:name="android.intent.action.MAIN"/>\n'
            '                <category android:name="android.intent.category.LAUNCHER"/>\n'
            '            </intent-filter>\n'
            '        </activity>\n'
            '    </application>\n'
            '</manifest>\n'
        )
        manifest_path = scaffold_dir / "AndroidManifest.xml"
        manifest_path.write_text(manifest, encoding="utf-8")

    def _write_smali_scaffolds(
        self, scaffold_dir: Path, spec: SyntheticVariantSpec, rng: random.Random
    ) -> None:
        """Write .smali scaffold files to the scaffold directory."""
        smali_dir = scaffold_dir / "smali" / "com" / "synthetic"
        smali_dir.mkdir(parents=True, exist_ok=True)

        for i in range(spec.dead_code_count):
            class_name = self._random_class(rng)
            smali_content = (
                f".class public Lcom/synthetic/{class_name};\n"
                ".super Ljava/lang/Object;\n\n"
                f"# Synthetic scaffold - {spec.target_technique[:40]}\n"
                f"# Generated by ORACLE-TMF SyntheticVariantGenerator\n\n"
                f".method public constructor <init>()V\n"
                f"    .registers 1\n"
                f"    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V\n"
                f"    return-void\n"
                f".end method\n\n"
                + self._gen_stub_smali(rng, as_smali_file=True)
            )
            (smali_dir / f"{class_name}.smali").write_text(smali_content, encoding="utf-8")

        logger.debug(
            "[SyntheticVariant] Wrote %d smali scaffolds to %s",
            spec.dead_code_count, smali_dir,
        )

    def _build_apk(self, scaffold_dir: Path, spec: SyntheticVariantSpec) -> Optional[str]:
        """
        Assemble a real APK from scaffold files using apktool.
        Requires enable_apk_build=True AND apktool on PATH.
        """
        import subprocess
        output_apk = str(scaffold_dir / f"{spec.apk_hash[:8]}_staging.apk")
        try:
            result = subprocess.run(
                [SYNTHETIC_APKTOOL_PATH, "b", str(scaffold_dir), "-o", output_apk],
                capture_output=True, text=True, timeout=120, check=False,
            )
            if result.returncode == 0:
                logger.info("[SyntheticVariant] APK built: %s", output_apk)
                return output_apk
            else:
                logger.error("[SyntheticVariant] apktool failed: %s", result.stderr[:200])
                return None
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.error("[SyntheticVariant] apktool not available: %s", exc)
            return None

    # ─── Text helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _random_class(rng: random.Random) -> str:
        prefixes = ["System", "Manager", "Helper", "Utils", "Service", "Worker"]
        suffixes = ["Impl", "Handler", "Base", "Core", "Module", "Bridge"]
        return rng.choice(prefixes) + rng.choice(suffixes)

    @staticmethod
    def _random_method(rng: random.Random) -> str:
        verbs = ["init", "prepare", "setup", "configure", "load", "fetch"]
        nouns = ["Data", "Config", "Module", "Handler", "State", "Context"]
        return rng.choice(verbs) + rng.choice(nouns)

    @staticmethod
    def _random_pkg(rng: random.Random) -> str:
        parts = ["system", "manager", "service", "helper", "data"]
        return ".".join(rng.choices(parts, k=2))

    @staticmethod
    def _gen_stub_smali(rng: random.Random, as_smali_file: bool = False) -> str:
        """Generate a structurally plausible but behaviourally inert stub method."""
        method_name = random.choice(["initModule", "loadConfig", "prepareHandler"])
        stub = (
            f".method public {method_name}()V\n"
            f"    .registers 2\n"
            f"    const-string v0, \"placeholder_{rng.randint(1000,9999)}\"\n"
            f"    return-void\n"
            f".end method\n"
        )
        return stub
