"""
ORACLE-TMF  Â·  pipeline/stage_f_string_mining.py
=================================================
STAGE F â€” String Resource and Placeholder Mining
Responsibility:
  â€¢ Scan the DEX global string pool for high-entropy or patterned strings
  â€¢ Scan res/values/strings.xml for placeholder keys and staging values
  â€¢ Detect: TODO/FIXME markers, staging URLs, hardcoded IPs, empty JSON
    schemas, C2 path patterns, .onion addresses, crypto wallet addresses
  â€¢ Compute Shannon entropy for each candidate string
  â€¢ Return a list of PlaceholderStringArtifact objects
Inputs:
  apk_path    : str  â€” path to .apk
  extract_dir : str  â€” extracted APK directory (Stage A output)
  analysis    : Androguard Analysis object (Stage B output)
Outputs: list[PlaceholderStringArtifact]
Algorithm:
  Two-pass strategy:
    Pass 1 â€” DEX String Pool:
      Androguard's dx.get_strings() yields every string constant embedded
      in the DEX bytecode.  Each string is evaluated against:
        a) Shannon entropy >= STRING_HIGH_ENTROPY_THRESHOLD
        b) PLACEHOLDER_PATTERNS regex dictionary
    Pass 2 â€” res/values/strings.xml:
      Parse the XML resource file from the extracted APK directory.
      Flag any string value matching PLACEHOLDER_PATTERNS.
"""
from __future__ import annotations
import logging
import math
import os
import re
import time
from typing import Any
from config.settings import(
    PLACEHOLDER_PATTERNS,
    STRING_HIGH_ENTROPY_THRESHOLD,
    STRING_MIN_LENGTH,
    XML_MAX_BYTES,
)
from models.mutation_artifact_graph import PlaceholderStringArtifact
from security import safe_xml_parse
logger=logging.getLogger(__name__)
_COMPILED_PATTERNS:dict[str,re.Pattern]={
    name:re.compile(pattern,re.IGNORECASE)
    for name,pattern in PLACEHOLDER_PATTERNS.items()
}
_BENIGN_PREFIXES:tuple[str,...]=(
    "AAAAgASU",
    "com.google.",
    "com.android.",
    "android.util.",
    "java.lang.",
    "androidx.",
)
class StringMiner:
    """
    Stage F: String Resource and Placeholder Mining.
    Usage
    -----
    >>> stage = StringMiner()
    >>> strings = stage.run(apk_path, extract_dir, analysis)
    """
    STAGE_NAME="STAGE_F"
    def run(
        self,apk_path:str,extract_dir:str,analysis:Any
    )->list[PlaceholderStringArtifact]:
        """
        Execute Stage F.
        Parameters
        ----------
        apk_path    : str â€” path to the original .apk
        extract_dir : str â€” extracted APK directory
        analysis    : Androguard Analysis object
        Returns
        -------
        list[PlaceholderStringArtifact]
        """
        t0=time.perf_counter()
        logger.info("[Stage F] Starting string resource and placeholder mining")
        artifacts:list[PlaceholderStringArtifact]=[]
        dex_artifacts=self._mine_dex_string_pool(analysis)
        artifacts.extend(dex_artifacts)
        res_artifacts=self._mine_resource_strings(extract_dir)
        artifacts.extend(res_artifacts)
        seen:set[str]=set()
        unique:list[PlaceholderStringArtifact]=[]
        for a in artifacts:
            if a.value not in seen:
                seen.add(a.value)
                unique.append(a)
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage F] Complete in %.1f ms | dex_hits=%d | res_hits=%d | total=%d",
            elapsed_ms,len(dex_artifacts),len(res_artifacts),len(unique),
        )
        return unique
    def _mine_dex_string_pool(self,analysis:Any)->list[PlaceholderStringArtifact]:
        """Scan every string constant in the DEX global string pool."""
        artifacts:list[PlaceholderStringArtifact]=[]
        try:
            for string_analysis in analysis.get_strings():
                value=str(string_analysis.get_value())
                if len(value)<STRING_MIN_LENGTH:
                    continue
                if any(value.startswith(prefix)for prefix in _BENIGN_PREFIXES):
                    continue
                artifact=self._evaluate_string(value,source="string_pool")
                if artifact is not None:
                    artifacts.append(artifact)
        except Exception as exc:
            logger.warning("[Stage F] DEX string pool mining error: %s",exc)
        return artifacts
    def _mine_resource_strings(self,extract_dir:str)->list[PlaceholderStringArtifact]:
        """Parse res/values/strings.xml and flag suspicious entries."""
        artifacts:list[PlaceholderStringArtifact]=[]
        strings_xml=os.path.join(extract_dir,"res","values","strings.xml")
        if not os.path.isfile(strings_xml):
            logger.debug("[Stage F] No res/values/strings.xml found")
            return artifacts
        try:
            if os.path.getsize(strings_xml)>XML_MAX_BYTES:
                logger.warning("[Stage F] strings.xml exceeds XML size limit")
                return artifacts
            tree=safe_xml_parse(strings_xml)
            root=tree.getroot()
            for element in root.findall(".//string"):
                key_name=element.get("name","")
                value=(element.text or "").strip()
                if len(value)<STRING_MIN_LENGTH:
                    continue
                artifact=self._evaluate_string(
                    value,source="res/values/strings.xml",key_name=key_name
                )
                if artifact is not None:
                    artifacts.append(artifact)
        except Exception as exc:
            logger.debug("[Stage F] strings.xml parse/mining error: %s",exc)
        return artifacts
    def _evaluate_string(
        self,value:str,source:str,key_name:str=""
    )->PlaceholderStringArtifact|None:
        """
        Evaluate a single string against entropy and pattern checks.
        Returns an artifact if suspicious, None otherwise.
        """
        entropy=self._shannon_entropy(value)
        matched_pattern=""
        is_high_entropy=entropy>=STRING_HIGH_ENTROPY_THRESHOLD
        for pattern_name,compiled_re in _COMPILED_PATTERNS.items():
            if compiled_re.search(value):
                matched_pattern=pattern_name
                break
        if is_high_entropy or matched_pattern:
            return PlaceholderStringArtifact(
                value=value[:256],
                source=source,
                entropy=round(entropy,4),
                matched_pattern=matched_pattern,
                key_name=key_name,
            )
        return None
    @staticmethod
    def _shannon_entropy(text:str)->float:
        """
        Compute the Shannon entropy of a string.
        H(X) = -Î£ p(x) * logâ‚‚(p(x))
        A high entropy value (> 4.5) indicates a string that is random-looking
        (encrypted payload, encoded URL, base64 data, etc.).
        Pure lowercase English text has entropy â‰ˆ 3.0â€“4.0.
        Completely random bytes have entropy â‰ˆ 7.5â€“8.0.
        """
        if not text:
            return 0.0
        freq:dict[str,int]={}
        for char in text:
            freq[char]=freq.get(char,0)+1
        total=len(text)
        return-sum((c/total)*math.log2(c/total)for c in freq.values())
