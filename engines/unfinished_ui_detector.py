"""
ORACLE-TMF  ·  engines/unfinished_ui_detector.py
=================================================
CLASS 6 — Unfinished UI Flow Detection

RATIONALE:
  Malware graphical assets (phishing overlays, fake banking screens, WebView
  shells) are typically finalised by UI designers BEFORE the backend payload
  logic is wired in.  A banking trojan developer creates a pixel-perfect
  HDFC Bank login overlay months before the credential-stealing AccessibilityService
  is complete.

  This results in XML layout files physically present inside the APK's
  res/layout/ directory but NEVER referenced by any Java/Kotlin/Smali code
  via setContentView(), Fragment.inflate(), or LayoutInflater.inflate().

  These "orphaned layouts" are Class 6 mutation artifacts.

DETECTION ALGORITHM:

  Step 1 — Enumerate layouts:
    List all XML files under res/layout/ in the extracted APK directory.
    Also check res/layout-land/, res/layout-sw600dp/, etc. (alternative layouts).

  Step 2 — Build the inflation reference set:
    Scan all DEX Smali code for:
      a) setContentView(<integer>)  — Activity layout inflation
      b) LayoutInflater.inflate(<integer>, ...)  — Fragment/View inflation
      c) DataBindingUtil.inflate(...)  — DataBinding inflation
      d) View.inflate(<integer>, ...)  — In-code inflation
    Extract the integer constant argument from each call.

  Step 3 — Map integers to layout names:
    Use Androguard's resource parser to map resource IDs to layout names.
    Fallback: Parse res/values/public.xml for the ID ↔ name mapping.
    Second fallback: String-based matching (layout file name in DEX string pool).

  Step 4 — Identify orphaned layouts:
    Any layout file whose resource ID is NOT found in the inflation reference set
    is an unfinished UI flow.

  Step 5 — Classify each orphaned layout:
    Parse the XML to determine its likely purpose:
      • "phishing_overlay"    — login form with financial field names
      • "webview_shell"       — WebView element with no Activity code
      • "banking_overlay"     — layout referencing bank branding assets
      • "credential_harvester"— password/PIN input fields
      • "generic_dormant"    — unclassified orphaned layout

Research basis:
  • Android documentation: developer.android.com/reference/android/app/Activity#setContentView
  • ORACLE-TMF Section V-A: "Artifact Class 6: Unfinished UI Flows"
  • Threat Fabric Android banking trojan UI overlay methodology (2024)
"""

from __future__ import annotations

import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

from models.mutation_artifact_graph import UnfinishedUIFlowArtifact

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
#  SMALI PATTERNS FOR LAYOUT INFLATION CALLS
# ─────────────────────────────────────────────────────────────

# setContentView(int) — Activity primary layout inflation
_SET_CONTENT_VIEW_RE = re.compile(
    r"invoke-virtual\s+\{[^}]+\},\s*L\w+/Activity[^;]*;->setContentView\s*\(I\)V",
    re.MULTILINE,
)

# inflate(int, ViewGroup, boolean) — Fragment/LayoutInflater inflation
_INFLATE_RE = re.compile(
    r"invoke-virtual\s+\{[^}]+\},\s*Landroid/view/LayoutInflater;->inflate\s*\(I",
    re.MULTILINE,
)

# const integer extraction before the inflate/setContentView call
_CONST_INT_RE = re.compile(
    r"const(?:/high16|/4|/16|/range)?\s+[vp]\d+,\s*(0x[0-9A-Fa-f]+|\d+)"
)

# Android layout resource IDs always start with 0x7F04 (layout type prefix is 0x04)
_LAYOUT_ID_PREFIX = 0x7F040000
_LAYOUT_ID_MASK   = 0xFF000000
_LAYOUT_TYPE_MASK = 0x00FF0000
_LAYOUT_TYPE_LAYOUT = 0x00040000   # layout type = 0x04

# Keywords indicating financial/phishing purpose in XML content
_FINANCIAL_KEYWORDS: frozenset[str] = frozenset({
    "username", "password", "pin", "upi", "otp", "cvv",
    "account", "card", "atm", "debit", "credit", "bank",
    "login", "signin", "sign_in", "net_banking", "mobile_banking",
    "transaction", "transfer", "beneficiary", "ifsc", "swift",
    "wallet", "balance", "statement", "passbook",
})

# Keywords for WebView shells
_WEBVIEW_TAGS: frozenset[str] = frozenset({"WebView", "webview", "android.webkit.WebView"})


class UnfinishedUIDetector:
    """
    Class 6: Unfinished UI Flow Detector.

    Identifies XML layout files present in the APK that are never
    inflated by any Java/Kotlin code — indicating dormant phishing
    overlays or incomplete attack UI components.

    Usage
    -----
    >>> detector = UnfinishedUIDetector()
    >>> orphaned = detector.run(apk_path, extract_dir, analysis)
    """

    STAGE_NAME = "UI_DETECT"

    # ─────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────

    def run(
        self,
        apk_path: str,
        extract_dir: str,
        analysis: Optional[Any],
    ) -> list[UnfinishedUIFlowArtifact]:
        """
        Execute Class 6 unfinished UI flow detection.

        Parameters
        ----------
        apk_path    : str — path to the original .apk file
        extract_dir : str — extracted APK directory (Stage A output)
        analysis    : Androguard Analysis object (Stage B output), or None

        Returns
        -------
        list[UnfinishedUIFlowArtifact]
        """
        t0 = time.perf_counter()
        logger.info("[Class 6] Starting unfinished UI flow detection")

        artifacts: list[UnfinishedUIFlowArtifact] = []

        # Step 1: Enumerate all layout XML files
        layout_files = self._enumerate_layout_files(extract_dir, apk_path)
        if not layout_files:
            logger.debug("[Class 6] No layout files found — skipping")
            return artifacts

        logger.debug("[Class 6] Layout files found: %d", len(layout_files))

        # Step 2: Build inflation reference set from DEX Smali
        inflated_ids, inflated_names = self._build_inflation_reference_set(analysis)
        logger.debug("[Class 6] Inflated resource IDs: %d", len(inflated_ids))

        # Step 3: Build resource ID → layout name mapping
        id_to_name = self._build_resource_id_map(extract_dir, apk_path)

        # Step 4+5: Identify and classify orphaned layouts
        for layout_path, layout_name in layout_files:
            is_referenced = self._is_layout_referenced(
                layout_name, inflated_ids, inflated_names, id_to_name
            )
            if not is_referenced:
                artifact = self._classify_layout(layout_path, layout_name, extract_dir)
                if artifact is not None:
                    artifacts.append(artifact)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[Class 6] Complete in %.1f ms | layouts_checked=%d | orphaned=%d",
            elapsed_ms, len(layout_files), len(artifacts),
        )
        return artifacts

    # ─────────────────────────────────────────────────────────
    #  STEP 1 — ENUMERATE LAYOUT FILES
    # ─────────────────────────────────────────────────────────

    def _enumerate_layout_files(
        self, extract_dir: str, apk_path: str
    ) -> list[tuple[str, str]]:
        """
        List all XML files under res/layout*/ directories.

        Returns a list of (absolute_path, layout_stem) tuples.
        E.g., ("/tmp/extracted/res/layout/activity_login.xml", "activity_login")
        """
        results: list[tuple[str, str]] = []

        if extract_dir and os.path.isdir(extract_dir):
            res_dir = os.path.join(extract_dir, "res")
            if os.path.isdir(res_dir):
                for subdir in os.listdir(res_dir):
                    if subdir.startswith("layout"):
                        layout_dir = os.path.join(res_dir, subdir)
                        if os.path.isdir(layout_dir):
                            for fname in os.listdir(layout_dir):
                                if fname.endswith(".xml"):
                                    fpath = os.path.join(layout_dir, fname)
                                    stem  = Path(fname).stem
                                    results.append((fpath, stem))

        # Fallback: use Androguard APK file listing
        if not results:
            try:
                from androguard.core.bytecodes.apk import APK  # type: ignore
                apk = APK(apk_path)
                for fpath in apk.get_files():
                    if re.match(r"res/layout[^/]*/[^/]+\.xml$", fpath):
                        stem = Path(fpath).stem
                        results.append((fpath, stem))
            except Exception as exc:
                logger.debug("[Class 6] APK file listing fallback failed: %s", exc)

        return results

    # ─────────────────────────────────────────────────────────
    #  STEP 2 — BUILD INFLATION REFERENCE SET
    # ─────────────────────────────────────────────────────────

    def _build_inflation_reference_set(
        self, analysis: Optional[Any]
    ) -> tuple[set[int], set[str]]:
        """
        Scan all DEX Smali methods for layout inflation calls and extract
        the integer resource ID arguments.

        Returns:
          inflated_ids   : set[int]  — resource integer IDs referenced in inflation calls
          inflated_names : set[str]  — layout name strings found in DEX string pool
        """
        inflated_ids:   set[int] = set()
        inflated_names: set[str] = set()

        if analysis is None:
            return inflated_ids, inflated_names

        try:
            for method_analysis in analysis.get_methods():
                if method_analysis.is_android_api() or method_analysis.is_external():
                    continue

                smali = self._get_smali(method_analysis)
                if not smali:
                    continue

                # Check if this method inflates a layout
                has_inflation = (
                    _SET_CONTENT_VIEW_RE.search(smali) is not None
                    or _INFLATE_RE.search(smali) is not None
                    or "DataBindingUtil" in smali
                    or "ViewBinding" in smali
                )
                if not has_inflation:
                    continue

                # Extract integer constants from this method body
                for match in _CONST_INT_RE.finditer(smali):
                    raw = match.group(1)
                    try:
                        value = int(raw, 16) if raw.startswith("0x") else int(raw)
                        # Filter to plausible Android resource IDs (0x7F000000 range)
                        if (value & _LAYOUT_ID_MASK) == 0x7F000000:
                            inflated_ids.add(value)
                    except ValueError:
                        continue

            # Also collect layout name strings from the string pool
            for string_analysis in analysis.get_strings():
                value = str(string_analysis.get_value()).strip()
                # Layout file names follow snake_case convention
                if re.match(r"^[a-z][a-z0-9_]+$", value) and 5 <= len(value) <= 60:
                    inflated_names.add(value)

        except Exception as exc:
            logger.warning("[Class 6] Inflation reference set build error: %s", exc)

        return inflated_ids, inflated_names

    # ─────────────────────────────────────────────────────────
    #  STEP 3 — RESOURCE ID MAP
    # ─────────────────────────────────────────────────────────

    def _build_resource_id_map(
        self, extract_dir: str, apk_path: str
    ) -> dict[int, str]:
        """
        Build a mapping from integer resource ID → layout file name.

        Tries two sources in order:
          1. res/values/public.xml (present in some APKs after aapt2 compilation)
          2. Androguard's ARSCParser for the binary resources.arsc
        """
        id_to_name: dict[int, str] = {}

        # Source 1: public.xml (text format, present in some APKs)
        public_xml = os.path.join(extract_dir, "res", "values", "public.xml")
        if os.path.isfile(public_xml):
            try:
                tree = ET.parse(public_xml)
                for element in tree.getroot().findall(".//public"):
                    if element.get("type") == "layout":
                        name = element.get("name", "")
                        id_hex = element.get("id", "0x0")
                        try:
                            res_id = int(id_hex, 16)
                            if name:
                                id_to_name[res_id] = name
                        except ValueError:
                            continue
                logger.debug("[Class 6] Resource map from public.xml: %d entries", len(id_to_name))
                return id_to_name
            except Exception as exc:
                logger.debug("[Class 6] public.xml parse failed: %s", exc)

        # Source 2: Androguard ARSCParser on resources.arsc
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
            apk = APK(apk_path)
            res = apk.get_android_resources()
            if res:
                for package in res.get_packages():
                    for res_type in ["layout"]:
                        try:
                            type_id = res.get_id(package, res_type)
                            if isinstance(type_id, dict):
                                for name, res_id in type_id.items():
                                    id_to_name[res_id] = name
                        except Exception:
                            continue
            logger.debug("[Class 6] Resource map from ARSC: %d entries", len(id_to_name))
        except Exception as exc:
            logger.debug("[Class 6] ARSC resource map failed: %s", exc)

        return id_to_name

    # ─────────────────────────────────────────────────────────
    #  STEP 4 — REFERENCE CHECK
    # ─────────────────────────────────────────────────────────

    def _is_layout_referenced(
        self,
        layout_name: str,
        inflated_ids: set[int],
        inflated_names: set[str],
        id_to_name: dict[int, str],
    ) -> bool:
        """
        Determine if a layout is referenced anywhere in the DEX bytecode.

        Returns True if referenced (layout IS used), False if orphaned.
        """
        # Direct name match in string pool
        if layout_name in inflated_names:
            return True

        # Resource ID reverse lookup
        for res_id, name in id_to_name.items():
            if name == layout_name and res_id in inflated_ids:
                return True

        # Substring match (e.g., "activity_main" in "R.layout.activity_main")
        for name_str in inflated_names:
            if layout_name in name_str or name_str in layout_name:
                return True

        return False

    # ─────────────────────────────────────────────────────────
    #  STEP 5 — LAYOUT CLASSIFICATION
    # ─────────────────────────────────────────────────────────

    def _classify_layout(
        self, layout_path: str, layout_name: str, extract_dir: str
    ) -> Optional[UnfinishedUIFlowArtifact]:
        """
        Parse the orphaned layout XML and classify its likely malicious purpose.

        Returns None if the layout appears benign (e.g., alternative theme XML).
        """
        # Try to read the layout XML
        xml_content = ""
        if os.path.isfile(layout_path):
            try:
                xml_content = Path(layout_path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass

        if not xml_content:
            # File not readable (binary resources.arsc format) — skip
            return None

        # Parse XML
        root_tag = ""
        layout_id = ""
        asset_refs: list[str] = []
        suspected_type = "generic_dormant"

        try:
            tree = ET.fromstring(xml_content)
            root_tag = tree.tag

            # Collect all @+id/ declarations and @drawable/ references
            id_re   = re.compile(r'@\+id/(\w+)')
            draw_re = re.compile(r'@drawable/(\w+)|@mipmap/(\w+)')

            for elem in tree.iter():
                for attr_val in elem.attrib.values():
                    for m in id_re.finditer(attr_val):
                        if not layout_id:
                            layout_id = m.group(1)
                    for m in draw_re.finditer(attr_val):
                        ref = m.group(1) or m.group(2)
                        if ref and ref not in asset_refs:
                            asset_refs.append(ref)

        except ET.ParseError:
            pass

        # Determine suspected type
        xml_lower = xml_content.lower()

        # Check for WebView → webview_shell
        if any(tag in xml_content for tag in _WEBVIEW_TAGS):
            suspected_type = "webview_shell"

        # Check for financial field names → phishing overlay or credential harvester
        elif any(kw in xml_lower for kw in _FINANCIAL_KEYWORDS):
            # Distinguish overlay vs credential harvester by field count
            field_count = xml_lower.count("edittext") + xml_lower.count("textinputlayout")
            if field_count >= 2:
                suspected_type = "credential_harvester"
            else:
                suspected_type = "phishing_overlay"

        # Check for bank branding in drawable references
        elif any(
            any(bank in ref.lower() for bank in ["bank", "hdfc", "sbi", "icici", "axis", "pay", "upi"])
            for ref in asset_refs
        ):
            suspected_type = "banking_overlay"

        # Check layout filename for hints
        elif any(hint in layout_name.lower() for hint in ["login", "bank", "pay", "crypto", "wallet"]):
            suspected_type = "phishing_overlay"

        # Skip clearly benign orphans (alternative density/orientation layouts)
        if suspected_type == "generic_dormant" and not asset_refs and not layout_id:
            logger.debug("[Class 6] Skipping likely benign orphaned layout: %s", layout_name)
            return None

        relative_path = f"res/layout/{layout_name}.xml"

        logger.debug(
            "[Class 6] Orphaned layout: %s | type=%s | assets=%d",
            layout_name, suspected_type, len(asset_refs),
        )

        return UnfinishedUIFlowArtifact(
            layout_file    = relative_path,
            layout_id      = layout_id,
            suspected_type = suspected_type,
            asset_refs     = asset_refs[:20],   # Cap list size
        )

    # ─────────────────────────────────────────────────────────
    #  UTILITY
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _get_smali(method_analysis: Any) -> str:
        """Safely extract Smali source."""
        try:
            return method_analysis.method.get_source() or ""
        except Exception:
            return ""
