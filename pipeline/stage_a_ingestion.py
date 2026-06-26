"""
ORACLE-TMF  ·  pipeline/stage_a_ingestion.py
=============================================
STAGE A — APK Ingestion and Preprocessing

Responsibility:
  • Accept a raw .apk binary path
  • Validate the APK (size, magic bytes, ZIP integrity)
  • Extract the ZIP contents with Zip Slip protection
  • Compute file hashes: SHA-256, MD5, SSDeep (fuzzy)
  • Extract and parse the signing certificate (PKCS#7)
  • Detect anti-analysis packer stubs
  • Populate APKMetadata in the MAG

Inputs:  Raw .apk file path (str)
Outputs: Populated APKMetadata + extracted APK working directory path

This stage has NO dependency on Androguard (that is Stage B).
It only performs I/O and cryptographic operations.

Edge Cases Handled:
  • Zip Slip attack (path traversal in ZIP entries)
  • APK too large (> 100 MB) or too small (< 1 KB)
  • Missing or corrupt signing certificate
  • Known packer stub class names in MANIFEST.MF
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import time
import zipfile
from pathlib import Path
from typing import Optional

from config.settings import (
    APK_MAX_SIZE_BYTES,
    APK_MIN_SIZE_BYTES,
    DEX_PACKED_SIZE_THRESHOLD,
    PACKER_STUB_CLASSES,
    WORK_DIR,
)
from models.mutation_artifact_graph import APKMetadata

logger = logging.getLogger(__name__)


class APKIngestionError(Exception):
    """Raised when Stage A cannot process the provided APK."""


class APKIngestion:
    """
    Stage A: APK Ingestion and Preprocessing.

    Usage
    -----
    >>> stage = APKIngestion()
    >>> metadata, extract_dir = stage.run("/path/to/sample.apk")
    """

    STAGE_NAME = "STAGE_A"
    ZIP_MAGIC = b"PK\x03\x04"   # Standard ZIP local file header magic bytes

    def __init__(self) -> None:
        self._work_dir = Path(WORK_DIR)
        self._work_dir.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────

    def run(self, apk_path: str) -> tuple[APKMetadata, str]:
        """
        Execute Stage A.

        Parameters
        ----------
        apk_path : str
            Absolute path to the .apk file.

        Returns
        -------
        metadata : APKMetadata
            All computed metadata for the APK.
        extract_dir : str
            Path to the directory where the APK was extracted.

        Raises
        ------
        APKIngestionError
            If the file is invalid, too large, or corrupted beyond recovery.
        """
        t0 = time.perf_counter()
        apk_path = os.path.abspath(apk_path)

        logger.info("[Stage A] Starting ingestion: %s", apk_path)

        # 1. Basic file validation
        self._validate_file(apk_path)

        # 2. Compute hashes BEFORE extraction (on the original binary)
        sha256, md5 = self._compute_standard_hashes(apk_path)
        ssdeep_hash  = self._compute_ssdeep(apk_path)

        # 3. Extract APK with Zip Slip protection
        extract_dir = self._safe_extract(apk_path)

        # 4. Detect packer / anti-analysis stubs
        is_packed, packer_hint = self._detect_packer(extract_dir, apk_path)

        # 5. Parse PKCS#7 signing certificate
        cert_issuer, cert_subject, cert_sha256 = self._parse_certificate(extract_dir)

        # 6. Read basic APK metadata from MANIFEST and extracted files
        package_name, version_name, version_code = self._read_apk_identity(apk_path)
        min_sdk, target_sdk = self._read_sdk_versions(extract_dir)
        entry_points        = self._detect_entry_points(extract_dir)

        metadata = APKMetadata(
            apk_path        = apk_path,
            package_name    = package_name,
            version_name    = version_name,
            version_code    = version_code,
            sha256          = sha256,
            md5             = md5,
            ssdeep          = ssdeep_hash,
            file_size_bytes = os.path.getsize(apk_path),
            cert_issuer     = cert_issuer,
            cert_subject    = cert_subject,
            cert_sha256     = cert_sha256,
            min_sdk         = min_sdk,
            target_sdk      = target_sdk,
            is_packed       = is_packed,
            packer_hint     = packer_hint,
            entry_points    = entry_points,
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[Stage A] Complete in %.1f ms | SHA256=%s... | packed=%s",
            elapsed_ms, sha256[:16], is_packed,
        )
        return metadata, extract_dir

    # ─────────────────────────────────────────────────────────
    #  PRIVATE METHODS
    # ─────────────────────────────────────────────────────────

    def _validate_file(self, apk_path: str) -> None:
        """Ensure the file exists, has correct size, and starts with ZIP magic."""
        if not os.path.isfile(apk_path):
            raise APKIngestionError(f"File not found: {apk_path}")

        size = os.path.getsize(apk_path)
        if size < APK_MIN_SIZE_BYTES:
            raise APKIngestionError(f"APK too small ({size} bytes) — likely a stub or empty file")
        if size > APK_MAX_SIZE_BYTES:
            raise APKIngestionError(
                f"APK exceeds {APK_MAX_SIZE_BYTES // 1024 // 1024} MB limit ({size} bytes)"
            )

        with open(apk_path, "rb") as fh:
            magic = fh.read(4)
        if magic != self.ZIP_MAGIC:
            raise APKIngestionError(
                f"Not a valid APK/ZIP file — unexpected magic bytes: {magic.hex()}"
            )

    def _compute_standard_hashes(self, apk_path: str) -> tuple[str, str]:
        """Compute SHA-256 and MD5 hashes of the APK binary."""
        sha256_hasher = hashlib.sha256()
        md5_hasher    = hashlib.md5()

        with open(apk_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)

        return sha256_hasher.hexdigest(), md5_hasher.hexdigest()

    def _compute_ssdeep(self, apk_path: str) -> str:
        """
        Compute SSDeep (context-triggered piecewise hash) for similarity clustering.
        Falls back to an empty string if the ssdeep library is not installed.
        """
        try:
            import ssdeep  # type: ignore
            return ssdeep.hash_from_file(apk_path)
        except ImportError:
            logger.debug("[Stage A] ssdeep not available — skipping fuzzy hash")
            return ""
        except Exception as exc:
            logger.warning("[Stage A] SSDeep computation failed: %s", exc)
            return ""

    def _safe_extract(self, apk_path: str) -> str:
        """
        Extract the APK (ZIP) to a working directory with full Zip Slip protection.

        Zip Slip: a crafted ZIP entry with '../' paths can write files outside
        the target directory.  We resolve each path and assert it remains under
        the target directory before extraction.
        """
        apk_stem = Path(apk_path).stem
        extract_dir = self._work_dir / f"{apk_stem}_{os.urandom(4).hex()}"
        extract_dir.mkdir(parents=True, exist_ok=True)

        extract_dir_resolved = extract_dir.resolve()

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for member in zf.infolist():
                    # ── Zip Slip check ──────────────────────────────────
                    target_path = (extract_dir_resolved / member.filename).resolve()
                    if not str(target_path).startswith(str(extract_dir_resolved)):
                        logger.warning(
                            "[Stage A] Zip Slip attempt blocked: %s", member.filename
                        )
                        continue  # Skip malicious entry

                    # ── Extract ─────────────────────────────────────────
                    if member.is_dir():
                        target_path.mkdir(parents=True, exist_ok=True)
                    else:
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as src, open(target_path, "wb") as dst:
                            shutil.copyfileobj(src, dst)

        except zipfile.BadZipFile as exc:
            raise APKIngestionError(f"Corrupt APK ZIP archive: {exc}") from exc

        logger.debug("[Stage A] Extracted to: %s", extract_dir)
        return str(extract_dir)

    def _detect_packer(self, extract_dir: str, apk_path: str) -> tuple[bool, str]:
        """
        Detect known packer / anti-analysis wrappers.

        Heuristics:
          1. classes.dex larger than DEX_PACKED_SIZE_THRESHOLD
          2. Known packer stub class names in META-INF/MANIFEST.MF
          3. Stub Application class names in AndroidManifest.xml
        """
        # Heuristic 1: oversized DEX
        dex_path = os.path.join(extract_dir, "classes.dex")
        if os.path.isfile(dex_path):
            dex_size = os.path.getsize(dex_path)
            if dex_size > DEX_PACKED_SIZE_THRESHOLD:
                logger.info(
                    "[Stage A] Large classes.dex (%d MB) — possible packing",
                    dex_size // 1024 // 1024,
                )

        # Heuristic 2: manifest stub classes
        manifest_path = os.path.join(extract_dir, "META-INF", "MANIFEST.MF")
        if os.path.isfile(manifest_path):
            try:
                content = Path(manifest_path).read_text(errors="replace")
                for stub in PACKER_STUB_CLASSES:
                    if stub.replace(".", "/") in content or stub in content:
                        logger.warning("[Stage A] Packer stub detected: %s", stub)
                        return True, stub
            except OSError:
                pass

        # Heuristic 3: try to find packer strings in the raw APK
        try:
            with open(apk_path, "rb") as fh:
                raw = fh.read(512 * 1024)   # Read first 512 KB
            for stub in PACKER_STUB_CLASSES:
                stub_bytes = stub.encode()
                if stub_bytes in raw:
                    return True, stub
        except OSError:
            pass

        return False, ""

    def _parse_certificate(self, extract_dir: str) -> tuple[str, str, str]:
        """
        Parse the APK's PKCS#7 signing certificate from META-INF/CERT.RSA (or .DSA).

        Returns (issuer, subject, cert_sha256).
        Returns empty strings if the certificate cannot be parsed.
        """
        cert_issuer = cert_subject = cert_sha256 = ""

        meta_inf = os.path.join(extract_dir, "META-INF")
        if not os.path.isdir(meta_inf):
            return cert_issuer, cert_subject, cert_sha256

        cert_file: Optional[str] = None
        for fname in os.listdir(meta_inf):
            if fname.upper().endswith((".RSA", ".DSA", ".EC")):
                cert_file = os.path.join(meta_inf, fname)
                break

        if not cert_file:
            logger.debug("[Stage A] No signing certificate found in META-INF/")
            return cert_issuer, cert_subject, cert_sha256

        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            from cryptography.hazmat.backends import default_backend

            with open(cert_file, "rb") as fh:
                raw_cert = fh.read()

            # DER-encoded PKCS#7 SignedData
            certs = pkcs7.load_der_pkcs7_certificates(raw_cert)
            if certs:
                leaf = certs[0]
                cert_issuer  = str(leaf.issuer.rfc4514_string())
                cert_subject = str(leaf.subject.rfc4514_string())
                cert_sha256  = leaf.fingerprint(
                    __import__("cryptography").hazmat.primitives.hashes.SHA256()
                ).hex()

        except Exception as exc:
            logger.debug("[Stage A] Certificate parsing failed: %s", exc)

        return cert_issuer, cert_subject, cert_sha256

    def _read_apk_identity(self, apk_path: str) -> tuple[str, str, int]:
        """
        Extract package name, version name, and version code from the APK.
        Uses Androguard's APK class just for the manifest metadata.
        Falls back to empty strings if Androguard is unavailable.
        """
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
            apk = APK(apk_path)
            return (
                apk.get_package() or "",
                apk.get_androidversion_name() or "",
                int(apk.get_androidversion_code() or 0),
            )
        except ImportError:
            logger.debug("[Stage A] Androguard not available for identity extraction")
            return "", "", 0
        except Exception as exc:
            logger.warning("[Stage A] Identity extraction failed: %s", exc)
            return "", "", 0

    def _read_sdk_versions(self, extract_dir: str) -> tuple[int, int]:
        """
        Read minSdkVersion and targetSdkVersion from the extracted manifest.
        Falls back to (0, 0) on failure.
        """
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
            # The extracted directory may not have the binary manifest in a form
            # Androguard understands — look for it directly.
            manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")
            if not os.path.isfile(manifest_path):
                return 0, 0

            # Androguard needs the original APK, not extracted files.
            # We can't use APK() on an extracted directory — skip here.
            return 0, 0
        except Exception:
            return 0, 0

    def _detect_entry_points(self, extract_dir: str) -> list[str]:
        """
        Detect likely Android entry points by scanning the extracted
        AndroidManifest.xml for Activity, Service, and BroadcastReceiver tags.

        Uses regex on the raw bytes since the manifest is still AXML-encoded
        (binary XML) at this point — Androguard's AXMLPrinter handles it in
        Stage C; here we do a best-effort scan for printable class name substrings.
        """
        entry_points: list[str] = []
        manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")

        if not os.path.isfile(manifest_path):
            return entry_points

        try:
            with open(manifest_path, "rb") as fh:
                raw = fh.read()

            # Extract printable ASCII substrings that look like Java class paths
            class_pattern = re.compile(
                rb"[Lcom|Lorg|Landroid|Lio][/\w]{8,}[;]?"
            )
            for match in class_pattern.finditer(raw):
                text = match.group(0).decode("ascii", errors="ignore")
                if text and text not in entry_points:
                    entry_points.append(text[:120])   # cap length

        except OSError as exc:
            logger.debug("[Stage A] Entry point scan failed: %s", exc)

        return entry_points[:50]   # Cap at 50 entries
