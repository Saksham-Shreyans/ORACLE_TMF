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
from config.settings import(
    APK_MAX_SIZE_BYTES,
    APK_MIN_SIZE_BYTES,
    DEX_PACKED_SIZE_THRESHOLD,
    PACKER_STUB_CLASSES,
    WORK_DIR,
    ZIP_MAX_FILE_COUNT,
    ZIP_MAX_ENTRY_BYTES,
    ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES,
    ZIP_MAX_COMPRESSION_RATIO,
)
from models.mutation_artifact_graph import APKMetadata
logger=logging.getLogger(__name__)
class APKIngestionError(Exception):
    pass
class APKIngestion:
    STAGE_NAME="STAGE_A"
    ZIP_MAGIC=b"PK\x03\x04"
    def __init__(self)->None:
        self._work_dir=Path(WORK_DIR)
        self._work_dir.mkdir(parents=True,exist_ok=True)
    def run(self,apk_path:str)->tuple[APKMetadata,str]:
        t0=time.perf_counter()
        apk_path=os.path.abspath(apk_path)
        logger.info("[Stage A] Starting ingestion: %s",apk_path)
        self._validate_file(apk_path)
        sha256,md5=self._compute_standard_hashes(apk_path)
        ssdeep_hash=self._compute_ssdeep(apk_path)
        extract_dir=self._safe_extract(apk_path)
        is_packed,packer_hint=self._detect_packer(extract_dir,apk_path)
        cert_issuer,cert_subject,cert_sha256=self._parse_certificate(extract_dir)
        package_name,version_name,version_code=self._read_apk_identity(apk_path)
        min_sdk,target_sdk=self._read_sdk_versions(apk_path)
        entry_points=self._detect_entry_points(extract_dir)
        metadata=APKMetadata(
            apk_path=apk_path,
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            sha256=sha256,
            md5=md5,
            ssdeep=ssdeep_hash,
            file_size_bytes=os.path.getsize(apk_path),
            cert_issuer=cert_issuer,
            cert_subject=cert_subject,
            cert_sha256=cert_sha256,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            is_packed=is_packed,
            packer_hint=packer_hint,
            entry_points=entry_points,
        )
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage A] Complete in %.1f ms | SHA256=%s... | packed=%s",
            elapsed_ms,sha256[:16],is_packed,
        )
        return metadata,extract_dir
    def _validate_file(self,apk_path:str)->None:
        if not os.path.isfile(apk_path):
            raise APKIngestionError(f"File not found:{apk_path}")
        size=os.path.getsize(apk_path)
        if size<APK_MIN_SIZE_BYTES:
            raise APKIngestionError(f"APK too small({size}bytes)— likely a stub or empty file")
        if size>APK_MAX_SIZE_BYTES:
            raise APKIngestionError(
                f"APK exceeds{APK_MAX_SIZE_BYTES//1024//1024}MB limit({size}bytes)"
            )
        with open(apk_path,"rb")as fh:
            magic=fh.read(4)
        if magic!=self.ZIP_MAGIC:
            raise APKIngestionError(
                f"Not a valid APK/ZIP file — unexpected magic bytes:{magic.hex()}"
            )
    def _compute_standard_hashes(self,apk_path:str)->tuple[str,str]:
        sha256_hasher=hashlib.sha256()
        md5_hasher=hashlib.md5()
        with open(apk_path,"rb")as fh:
            for chunk in iter(lambda:fh.read(65536),b""):
                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)
        return sha256_hasher.hexdigest(),md5_hasher.hexdigest()
    def _compute_ssdeep(self,apk_path:str)->str:
        try:
            try:
                import ssdeep
            except ImportError:
                import ppdeep as ssdeep
            return ssdeep.hash_from_file(apk_path)
        except ImportError:
            logger.debug("[Stage A] ssdeep not available — skipping fuzzy hash")
            return ""
        except Exception as exc:
            logger.warning("[Stage A] SSDeep computation failed: %s",exc)
            return ""
    def _safe_extract(self,apk_path:str)->str:
        apk_stem=Path(apk_path).stem
        extract_dir=self._work_dir/f"{apk_stem}_{os.urandom(4).hex()}"
        extract_dir.mkdir(parents=True,exist_ok=True)
        try:
            os.chmod(extract_dir,0o700)
        except OSError:
            pass
        extract_dir_resolved=extract_dir.resolve()
        try:
            with zipfile.ZipFile(apk_path,"r")as zf:
                members=zf.infolist()
                if len(members)>ZIP_MAX_FILE_COUNT:
                    raise APKIngestionError(
                        f"APK contains{len(members)}entries,exceeding limit of{ZIP_MAX_FILE_COUNT}"
                    )
                total_uncompressed=0
                for member in members:
                    if member.file_size>ZIP_MAX_ENTRY_BYTES:
                        logger.warning(
                            "[Stage A] ZIP entry too large (%d bytes), skipping: %s",
                            member.file_size,member.filename,
                        )
                        continue
                    if member.compress_size>0:
                        ratio=member.file_size/member.compress_size
                        if ratio>ZIP_MAX_COMPRESSION_RATIO:
                            logger.warning(
                                "[Stage A] Suspicious compression ratio %.0f:1, skipping: %s",
                                ratio,member.filename,
                            )
                            continue
                    total_uncompressed+=member.file_size
                    if total_uncompressed>ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES:
                        raise APKIngestionError(
                            f"APK total uncompressed size exceeds{ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES//1024//1024}MB limit"
                        )
                    try:
                        target_path=(extract_dir_resolved/member.filename).resolve()
                        target_path.relative_to(extract_dir_resolved)
                    except ValueError:
                        logger.warning(
                            "[Stage A] Zip Slip attempt blocked: %s",member.filename
                        )
                        continue
                    if member.filename.startswith(("/","\\"))or(len(member.filename)>1 and member.filename[1]==":"):
                        logger.warning(
                            "[Stage A] Absolute/drive path blocked: %s",member.filename
                        )
                        continue
                    if member.is_dir():
                        target_path.mkdir(parents=True,exist_ok=True)
                    else:
                        target_path.parent.mkdir(parents=True,exist_ok=True)
                        with zf.open(member)as src,open(target_path,"wb")as dst:
                            shutil.copyfileobj(src,dst)
        except zipfile.BadZipFile as exc:
            raise APKIngestionError(f"Corrupt APK ZIP archive:{exc}")from exc
        logger.debug("[Stage A] Extracted to: %s",extract_dir)
        return str(extract_dir)
    def _detect_packer(self,extract_dir:str,apk_path:str)->tuple[bool,str]:
        dex_path=os.path.join(extract_dir,"classes.dex")
        if os.path.isfile(dex_path):
            dex_size=os.path.getsize(dex_path)
            if dex_size>DEX_PACKED_SIZE_THRESHOLD:
                logger.info(
                    "[Stage A] Large classes.dex (%d MB) — possible packing",
                    dex_size//1024//1024,
                )
        manifest_path=os.path.join(extract_dir,"META-INF","MANIFEST.MF")
        if os.path.isfile(manifest_path):
            try:
                content=Path(manifest_path).read_text(errors="replace")
                for stub in PACKER_STUB_CLASSES:
                    if stub.replace(".","/")in content or stub in content:
                        logger.warning("[Stage A] Packer stub detected: %s",stub)
                        return True,stub
            except OSError:
                pass
        try:
            with open(apk_path,"rb")as fh:
                raw=fh.read(512*1024)
            for stub in PACKER_STUB_CLASSES:
                stub_bytes=stub.encode()
                if stub_bytes in raw:
                    return True,stub
        except OSError:
            pass
        return False,""
    def _parse_certificate(self,extract_dir:str)->tuple[str,str,str]:
        cert_issuer=cert_subject=cert_sha256=""
        meta_inf=os.path.join(extract_dir,"META-INF")
        if not os.path.isdir(meta_inf):
            return cert_issuer,cert_subject,cert_sha256
        cert_file:Optional[str]=None
        for fname in os.listdir(meta_inf):
            if fname.upper().endswith((".RSA",".DSA",".EC")):
                cert_file=os.path.join(meta_inf,fname)
                break
        if not cert_file:
            logger.debug("[Stage A] No signing certificate found in META-INF/")
            return cert_issuer,cert_subject,cert_sha256
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            from cryptography.hazmat.backends import default_backend
            with open(cert_file,"rb")as fh:
                raw_cert=fh.read()
            certs=pkcs7.load_der_pkcs7_certificates(raw_cert)
            if certs:
                leaf=certs[0]
                cert_issuer=str(leaf.issuer.rfc4514_string())
                cert_subject=str(leaf.subject.rfc4514_string())
                cert_sha256=leaf.fingerprint(
                    __import__("cryptography").hazmat.primitives.hashes.SHA256()
                ).hex()
        except Exception as exc:
            logger.debug("[Stage A] Certificate parsing failed: %s",exc)
        return cert_issuer,cert_subject,cert_sha256
    def _read_apk_identity(self,apk_path:str)->tuple[str,str,int]:
        try:
            from androguard.core.bytecodes.apk import APK
            apk=APK(apk_path)
            return(
                apk.get_package()or "",
                apk.get_androidversion_name()or "",
                int(apk.get_androidversion_code()or 0),
            )
        except ImportError:
            logger.debug("[Stage A] Androguard not available for identity extraction")
            return "","",0
        except Exception as exc:
            logger.warning("[Stage A] Identity extraction failed: %s",exc)
            return "","",0
    def _read_sdk_versions(self,apk_path:str)->tuple[int,int]:
        try:
            from androguard.core.bytecodes.apk import APK
            apk=APK(apk_path)
            min_sdk=apk.get_min_sdk_version()
            target_sdk=apk.get_target_sdk_version()
            return int(min_sdk) if min_sdk else 0, int(target_sdk) if target_sdk else 0
        except ImportError:
            logger.debug("[Stage A] Androguard not available for sdk extraction, trying fallback")
            try:
                import subprocess
                out = subprocess.check_output(["aapt", "dump", "badging", apk_path], stderr=subprocess.STDOUT, timeout=5).decode(errors="ignore")
                min_sdk, target_sdk = 0, 0
                for line in out.splitlines():
                    if line.startswith("sdkVersion:"):
                        min_sdk = int(line.split("'")[1])
                    elif line.startswith("targetSdkVersion:"):
                        target_sdk = int(line.split("'")[1])
                return min_sdk, target_sdk
            except Exception as e:
                logger.debug(f"[Stage A] SDK fallback failed: {e}")
                return 0, 0
        except Exception as exc:
            logger.debug("[Stage A] SDK extraction failed: %s", exc)
            return 0,0
    def _detect_entry_points(self,extract_dir:str)->list[str]:
        entry_points:list[str]=[]
        manifest_path=os.path.join(extract_dir,"AndroidManifest.xml")
        if not os.path.isfile(manifest_path):
            return entry_points
        try:
            with open(manifest_path,"rb")as fh:
                raw=fh.read()
            class_pattern=re.compile(
                rb"[Lcom|Lorg|Landroid|Lio][/\w]{8,}[;]?"
            )
            for match in class_pattern.finditer(raw):
                text=match.group(0).decode("ascii",errors="ignore")
                text=re.sub(r"[\x00-\x1f\x7f-\x9f]","",text)
                if text and text not in entry_points:
                    entry_points.append(text[:120])
        except OSError as exc:
            logger.debug("[Stage A] Entry point scan failed: %s",exc)
        return entry_points[:50]
