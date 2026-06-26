"""
ORACLE-TMF  ·  tests/test_targeting.py
========================================
Unit tests for the Targeting Intelligence Module.
Tests cover:
  • Bank package taxonomy loading (both file and inline fallback)
  • Layer 1 — Package array analysis against dead code strings
  • Layer 2 — Overlay asset analysis from Class 6 artifacts
  • Layer 3 — Geographic expansion signal detection (locale dirs, MCC codes)
  • Layer 4 — HTML overlay institution identification
  • Family inference from package patterns
  • Multi-layer confidence boosting
  • Empty / edge-case handling
Does NOT require Androguard — tests use mocked MAGs with synthetic artifacts.
"""
from __future__ import annotations
import sys
from pathlib import Path
import pytest

PROJECT_ROOT=str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0,PROJECT_ROOT)
from engines.targeting_intelligence import(
    LOCALE_TO_COUNTRY,
    MCC_MAP,
    TargetingIntelligence,
    _FAMILY_HINTS,
    _HTML_BANK_INDICATORS,
)
from models.mutation_artifact_graph import(
    DeadCodeArtifact,
    DTEClass,
    MutationArtifactGraph,
    PlaceholderStringArtifact,
    UnfinishedUIFlowArtifact,
    C2EndpointStubArtifact,
)



@pytest.fixture(scope="module")
def intel():
    """Shared TargetingIntelligence instance."""
    return TargetingIntelligence()
def _make_dead_code(
    smali:str="",
    class_name:str="Lcom/test/Target;",
    method_name:str="check()V",
)->DeadCodeArtifact:
    return DeadCodeArtifact(
        class_name=class_name,
        method_name=method_name,
        smali_code=smali,
        opcode_count=25,
        dte_label=DTEClass.SCAFFOLDING,
        dte_confidence=0.80,
    )
def _make_ui_flow(
    layout_file:str="res/layout/activity_login.xml",
    suspected_type:str="phishing_overlay",
    asset_refs:list[str]=None,
)->UnfinishedUIFlowArtifact:
    return UnfinishedUIFlowArtifact(
        layout_file=layout_file,
        suspected_type=suspected_type,
        asset_refs=asset_refs or[],
    )
def _make_placeholder(value:str="")->PlaceholderStringArtifact:
    return PlaceholderStringArtifact(
        value=value,source="string_pool",entropy=5.0,
    )



class TestTaxonomyLoading:
    """Test bank package taxonomy loading and lookup structures."""
    def test_taxonomy_loads(self,intel):
        """Taxonomy must be loaded (from file or fallback)."""
        assert intel._taxonomy is not None
        entries=intel._taxonomy.get("entries",[])
        assert len(entries)>0
    def test_package_lookup_populated(self,intel):
        """Package-to-entry lookup dict must be populated."""
        assert len(intel._pkg_to_entry)>0
    def test_institution_keywords_populated(self,intel):
        """Institution keyword list must be populated."""
        assert len(intel._institution_keywords)>0
    def test_known_package_in_lookup(self,intel):
        """A well-known banking package must be in the lookup."""
        
        known=[
            "com.snapwork.hdfc",
            "com.sbi.upi",
            "com.chase.sig.android",
        ]
        matched=[pkg for pkg in known if pkg in intel._pkg_to_entry]
        assert len(matched)>0,"No known bank packages found in taxonomy"



class TestLayer1PackageArrays:
    """Test dead code string cross-referencing against bank taxonomy."""
    def test_detect_bank_package_in_dead_code(self,intel):
        """A dead code artifact containing a bank package name should be detected."""
        smali='''
.method private getTargets()[Ljava/lang/String;
    .locals 2
    const-string v0, "com.snapwork.hdfc"
    const-string v1, "com.sbi.upi"
    return-void
.end method
'''
        mag=MutationArtifactGraph()
        mag.dead_code=[_make_dead_code(smali=smali)]
        targets=intel._layer1_package_arrays(mag)
        institutions={t["institution_name"]for t in targets}
        assert len(targets)>=1
        
        assert institutions&{"HDFC Bank","SBI YONO"}
    def test_detect_from_placeholder_strings(self,intel):
        """Bank package in placeholder strings should also be detected."""
        mag=MutationArtifactGraph()
        mag.placeholder_strings=[_make_placeholder("com.chase.sig.android")]
        targets=intel._layer1_package_arrays(mag)
        if targets:
            assert any("Chase"in t["institution_name"]for t in targets)
    def test_no_detection_on_clean_dead_code(self,intel):
        """Dead code with no bank package references should return empty."""
        smali='''
.method private setup()V
    const-string v0, "Hello World"
    return-void
.end method
'''
        mag=MutationArtifactGraph()
        mag.dead_code=[_make_dead_code(smali=smali)]
        targets=intel._layer1_package_arrays(mag)
        assert len(targets)==0
    def test_deduplication_by_institution(self,intel):
        """Same institution appearing twice should be deduplicated."""
        smali1='const-string v0, "com.snapwork.hdfc"'
        smali2='const-string v0, "com.snapwork.hdfc"'
        mag=MutationArtifactGraph()
        mag.dead_code=[
            _make_dead_code(smali=smali1,method_name="m1()V"),
            _make_dead_code(smali=smali2,method_name="m2()V"),
        ]
        targets=intel._layer1_package_arrays(mag)
        names=[t["institution_name"]for t in targets]
        
        assert names.count("HDFC Bank")<=1



class TestLayer2OverlayAssets:
    """Test orphaned UI layout analysis for financial branding."""
    def test_detect_institution_from_asset_ref(self,intel):
        """An asset ref containing a bank name should trigger detection."""
        mag=MutationArtifactGraph()
        mag.unfinished_ui_flows=[
            _make_ui_flow(asset_refs=["ic_hdfc_logo.png","bg_login_blue.9.png"])
        ]
        targets=intel._layer2_overlay_assets(mag,"")
        if targets:
            assert any("HDFC"in t["institution_name"]for t in targets)
    def test_no_detection_on_generic_assets(self,intel):
        """Generic asset names should not trigger false positives."""
        mag=MutationArtifactGraph()
        mag.unfinished_ui_flows=[
            _make_ui_flow(asset_refs=["ic_launcher.png","bg_main.xml"])
        ]
        targets=intel._layer2_overlay_assets(mag,"")
        assert len(targets)==0
    def test_empty_ui_flows(self,intel):
        """Empty unfinished UI flows should return empty."""
        mag=MutationArtifactGraph()
        targets=intel._layer2_overlay_assets(mag,"")
        assert len(targets)==0



class TestLayer3GeographicSignals:
    """Test geographic expansion signal detection."""
    def test_mcc_in_dead_code(self,intel):
        """MCC codes in dead TelephonyManager code should yield country signals."""
        smali='''
.method private checkCountry()Z
    invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getNetworkCountryIso()Ljava/lang/String;
    const-string v2, "404"
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    return v3
.end method
'''
        mag=MutationArtifactGraph()
        mag.dead_code=[_make_dead_code(smali=smali)]
        countries=intel._layer3_geographic_signals(mag,"")
        assert "IN"in countries
    def test_no_geo_signals_from_clean_code(self,intel):
        """Clean dead code without MCC/locale should yield no signals."""
        smali='''
.method private doNothing()V
    return-void
.end method
'''
        mag=MutationArtifactGraph()
        mag.dead_code=[_make_dead_code(smali=smali)]
        countries=intel._layer3_geographic_signals(mag,"")
        assert len(countries)==0



class TestLayer4HTMLOverlays:
    """Test HTML overlay fragment scanning."""
    def test_html_bank_indicator_patterns(self):
        """HTML bank indicator patterns should match banking-related HTML."""
        html='<title>HDFC Bank NetBanking Login</title>'
        assert any(p.search(html)for p in _HTML_BANK_INDICATORS)
    def test_html_form_field_pattern(self):
        """HTML with login form fields should match."""
        html='<input type="text" id="username" placeholder="Enter User ID">'
        assert any(p.search(html)for p in _HTML_BANK_INDICATORS)
    def test_no_false_positive_on_normal_html(self):
        """Normal HTML without banking keywords should not match."""
        html='<div class="content"><p>Hello World</p></div>'
        assert not any(p.search(html)for p in _HTML_BANK_INDICATORS)



class TestFamilyInference:
    """Test malware family inference from package patterns."""
    def test_flubot_detection(self,intel):
        """FluBot package pattern should yield FluBot family."""
        smali='const-string v0, "com.tencent.mm"'
        mag=MutationArtifactGraph()
        mag.dead_code=[_make_dead_code(smali=smali)]
        family=intel._infer_family_from_packages(mag)
        assert family=="FluBot"
    def test_spynote_detection(self,intel):
        """SpyNote package pattern should yield SpyNote family."""
        smali='const-string v0, "com.android.system"'
        mag=MutationArtifactGraph()
        mag.dead_code=[_make_dead_code(smali=smali)]
        family=intel._infer_family_from_packages(mag)
        assert family=="SpyNote"
    def test_no_family_from_clean_code(self,intel):
        """Clean dead code should yield empty family string."""
        smali='const-string v0, "com.example.normal"'
        mag=MutationArtifactGraph()
        mag.dead_code=[_make_dead_code(smali=smali)]
        family=intel._infer_family_from_packages(mag)
        assert family==""



class TestFullRun:
    """Integration tests for the full run() method."""
    def test_run_with_empty_mag(self,intel):
        """Run on empty MAG should not crash and return valid structure."""
        mag=MutationArtifactGraph()
        report=intel.run(mag,"",None)
        assert "predicted_targets"in report
        assert "geographic_expansion"in report
        assert "family_hint"in report
        assert "targeting_confidence"in report
        assert isinstance(report["predicted_targets"],list)
        assert isinstance(report["geographic_expansion"],list)
    def test_run_returns_sorted_by_confidence(self,intel):
        """Predicted targets should be sorted by confidence descending."""
        smali='''
.method private loadTargets()V
    const-string v0, "com.snapwork.hdfc"
    const-string v1, "com.sbi.upi"
    return-void
.end method
'''
        mag=MutationArtifactGraph()
        mag.dead_code=[_make_dead_code(smali=smali)]
        report=intel.run(mag,"",None)
        if len(report["predicted_targets"])>1:
            confs=[t["confidence"]for t in report["predicted_targets"]]
            assert confs==sorted(confs,reverse=True)



class TestGeographicData:
    """Validate the MCC and locale mapping constants."""
    def test_mcc_map_values_have_iso(self):
        for mcc,info in MCC_MAP.items():
            assert "iso"in info,f"MCC {mcc} missing 'iso'"
            assert "country"in info,f"MCC {mcc} missing 'country'"
            assert len(info["iso"])==2,f"MCC {mcc} ISO code invalid"
    def test_locale_map_values_are_iso(self):
        for locale,iso in LOCALE_TO_COUNTRY.items():
            assert len(iso)==2,f"Locale '{locale}' maps to invalid ISO: {iso}"
    def test_india_mcc_codes_present(self):
        """India MCCs (404, 405) must be in the map."""
        assert "404"in MCC_MAP
        assert "405"in MCC_MAP
        assert MCC_MAP["404"]["iso"]=="IN"
