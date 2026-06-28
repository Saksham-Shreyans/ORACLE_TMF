"""
ORACLE-TMF  ·  research/network_attack/ddos_analyzer.py
=========================================================
Network Attack Layer: DDoS / ANC Signature Detector — Stage 2 Tier 3.

PURPOSE (detection only)
------------------------
Identifies DDoS and Advanced Network Coercion (ANC) capability signatures
ALREADY PRESENT in malware APK artifacts.  Classifies the threat vector,
estimates amplification factor, and generates Suricata detection rules for
the network operations team to deploy.

This module is a DETECTOR, not an attacker.  It reads what is already
inside a malware sample and produces:
  • Threat classification (which DDoS vector the malware targets)
  • Amplification factor estimate (how severe a potential attack would be)
  • Suricata rules to block C2 channels for that malware family
  • STIX threat indicator bundles for sharing with network defenders

Detection heuristics
--------------------
  SYN Flood:
    Raw socket Smali: socket(PF_INET, SOCK_RAW) pattern in dead code
    JNI bridge to native raw socket API
  
  DNS Amplification:
    DNS ANY / TXT query construction patterns
    Spoofed source IP assembly patterns in JNI/native code
  
  NTP Amplification:
    NTP monlist request byte patterns (0x16, 0x03, 0x01, 0x2a)
    Random source IP generation loops
  
  HTTP Flood / Slowloris:
    OkHttpClient with randomized User-Agent pools
    Long connection hold patterns (1-byte send loops)
  
  DGA C2 Migration:
    java.util.Random seeded with timestamp
    TLD array + string concatenation
    High-entropy domain generation patterns

All signatures are extracted from existing static analysis artifacts
(dead code, C2 stubs, string mining output) — no dynamic execution.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from config.stage2_settings import (
    ANC_RAW_SOCKET_SIGNATURES,
    DGA_SEED_SIGNATURES,
    DDOS_AMPLIFICATION_FACTORS,
)
from models.mutation_artifact_graph import (
    MutationArtifactGraph,
    DeadCodeArtifact,
)

logger = logging.getLogger(__name__)


@dataclass
class DDoSThreat:
    """A single detected DDoS/ANC capability in a malware sample."""

    vector: str = ""
    threat_level: str = ""        # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    amplification_factor: float = 1.0
    evidence_snippets: list[str] = field(default_factory=list)
    affected_classes: list[str] = field(default_factory=list)
    mitre_technique: str = ""

    # Suricata rule for blocking C2 channel that controls this vector
    suricata_rule: str = ""


@dataclass
class DGAProfile:
    """Detected Domain Generation Algorithm profile."""

    seed_source: str = ""       # "TIMESTAMP", "DEVICE_ID", "HYBRID"
    tld_pool: list[str] = field(default_factory=list)
    estimated_daily_domains: int = 0
    generator_class: str = ""
    detection_regex: str = ""


@dataclass
class NetworkAttackResult:
    """Output of the Network Attack Layer analysis."""

    apk_hash: str = ""
    detected_threats: list[DDoSThreat] = field(default_factory=list)
    dga_profile: Optional[DGAProfile] = None
    highest_threat_level: str = "NONE"
    max_amplification_factor: float = 0.0
    suricata_rules: list[str] = field(default_factory=list)
    stix_indicators: list[dict] = field(default_factory=list)
    runtime_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "apk_hash": self.apk_hash,
            "threat_count": len(self.detected_threats),
            "highest_threat_level": self.highest_threat_level,
            "max_amplification_factor": round(self.max_amplification_factor, 1),
            "has_dga": self.dga_profile is not None,
            "suricata_rules_count": len(self.suricata_rules),
            "runtime_ms": round(self.runtime_ms, 2),
            "threats": [
                {
                    "vector": t.vector,
                    "level": t.threat_level,
                    "amplification": t.amplification_factor,
                    "mitre": t.mitre_technique,
                    "evidence_count": len(t.evidence_snippets),
                }
                for t in self.detected_threats
            ],
            "dga_profile": (
                {
                    "seed_source": self.dga_profile.seed_source,
                    "tld_count": len(self.dga_profile.tld_pool),
                    "estimated_daily_domains": self.dga_profile.estimated_daily_domains,
                }
                if self.dga_profile else None
            ),
        }


class NetworkAttackAnalyzer:
    """
    DDoS and ANC Capability Detector for Android Malware.

    Scans a MAG's existing artifacts for network attack capability signatures
    and produces detection rules and STIX threat indicators.

    Usage
    -----
    >>> analyzer = NetworkAttackAnalyzer()
    >>> result = analyzer.analyze(mag)
    """

    ENGINE_NAME = "NETWORK_ATTACK_ANALYZER"

    # Threat level priority for ordering
    _THREAT_PRIORITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

    def __init__(self) -> None:
        logger.info("[NetworkAttackAnalyzer] Engine initialised")

    def analyze(self, mag: MutationArtifactGraph) -> NetworkAttackResult:
        """
        Scan a MAG's artifacts for DDoS/ANC capability signatures.

        Parameters
        ----------
        mag : MutationArtifactGraph

        Returns
        -------
        NetworkAttackResult
        """
        t0 = time.perf_counter()
        apk_hash = mag.apk_metadata.sha256[:16] or "unknown"
        logger.info("[NetworkAttackAnalyzer] Analyzing APK %s", apk_hash)

        result = NetworkAttackResult(apk_hash=apk_hash)
        detected: list[DDoSThreat] = []

        # Collect all smali text for scanning
        all_smali = self._collect_smali(mag)
        all_strings = [s.value for s in mag.placeholder_strings]
        all_c2_urls = [c.extracted_url for c in mag.c2_stubs]

        # Run each detector
        syn_threat = self._detect_syn_flood(all_smali, mag.dead_code)
        if syn_threat:
            detected.append(syn_threat)

        dns_threat = self._detect_dns_amplification(all_smali, all_strings)
        if dns_threat:
            detected.append(dns_threat)

        ntp_threat = self._detect_ntp_amplification(all_smali)
        if ntp_threat:
            detected.append(ntp_threat)

        http_threat = self._detect_http_flood(all_smali, all_strings)
        if http_threat:
            detected.append(http_threat)

        snmp_threat = self._detect_snmp_amplification(all_smali, all_strings)
        if snmp_threat:
            detected.append(snmp_threat)

        dga_profile = self._detect_dga(all_smali, all_strings)

        result.detected_threats = detected
        result.dga_profile = dga_profile

        if detected:
            best = max(detected, key=lambda t: self._THREAT_PRIORITY.get(t.threat_level, 0))
            result.highest_threat_level = best.threat_level
            result.max_amplification_factor = max(t.amplification_factor for t in detected)
            result.suricata_rules = self._generate_suricata_rules(detected, mag)
            result.stix_indicators = self._generate_stix_indicators(detected, mag)

        result.runtime_ms = round((time.perf_counter() - t0) * 1000, 2)
        logger.info(
            "[NetworkAttackAnalyzer] Complete: apk=%s threats=%d level=%s amp=%.0fx (%.1f ms)",
            apk_hash, len(detected), result.highest_threat_level,
            result.max_amplification_factor, result.runtime_ms,
        )
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Individual detectors
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_syn_flood(
        self,
        all_smali: str,
        dead_code: list[DeadCodeArtifact],
    ) -> Optional[DDoSThreat]:
        """Detect raw socket / SYN flood capability signatures."""
        evidence: list[str] = []
        affected: list[str] = []

        for sig in ANC_RAW_SOCKET_SIGNATURES:
            if sig in all_smali:
                evidence.append(f"Signature found: '{sig}'")

        for block in dead_code:
            if any(sig in block.smali_code for sig in ANC_RAW_SOCKET_SIGNATURES):
                affected.append(block.class_name)

        if not evidence:
            return None

        spec = DDOS_AMPLIFICATION_FACTORS["syn_flood"]
        return DDoSThreat(
            vector=spec["vector"],
            threat_level=spec["threat_level"],
            amplification_factor=spec["amplification"],
            evidence_snippets=evidence[:5],
            affected_classes=list(set(affected))[:10],
            mitre_technique="T1499 - Endpoint Denial of Service",
            suricata_rule=(
                'alert tcp any any -> any any (msg:"ORACLE-TMF SYN Flood C2 detected"; '
                'flags:S; threshold:type both,track by_src,count 100,seconds 1; sid:9000001;)'
            ),
        )

    def _detect_dns_amplification(
        self, all_smali: str, all_strings: list[str]
    ) -> Optional[DDoSThreat]:
        """Detect DNS amplification attack construction patterns."""
        evidence: list[str] = []

        dns_patterns = [
            r"DNS\s+ANY", r"DNS\s+TXT", r"DatagramPacket",
            r"dnsjava", r"Inet4Address.*spoof",
        ]
        for pattern in dns_patterns:
            if re.search(pattern, all_smali, re.IGNORECASE):
                evidence.append(f"DNS pattern: {pattern}")

        # Check strings for DNS resolver hardcoding
        for s in all_strings:
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s):
                evidence.append(f"Hardcoded IP (potential reflector): {s}")
                break

        if len(evidence) < 2:
            return None

        spec = DDOS_AMPLIFICATION_FACTORS["dns_amplification"]
        return DDoSThreat(
            vector=spec["vector"],
            threat_level=spec["threat_level"],
            amplification_factor=spec["amplification"],
            evidence_snippets=evidence[:5],
            mitre_technique="T1498.002 - Network Denial of Service: Reflection Amplification",
            suricata_rule=(
                'alert udp any any -> any 53 (msg:"ORACLE-TMF DNS Amplification probe"; '
                'content:"|00 00 FF 00 01|"; depth:5; sid:9000002;)'
            ),
        )

    def _detect_ntp_amplification(self, all_smali: str) -> Optional[DDoSThreat]:
        """Detect NTP monlist amplification patterns."""
        ntp_bytes = ["\\x16\\x03\\x01", "0x2a", "monlist", "\\x00\\x2a", "NTP"]
        evidence = [b for b in ntp_bytes if b in all_smali]

        if len(evidence) < 2:
            return None

        spec = DDOS_AMPLIFICATION_FACTORS["ntp_amplification"]
        return DDoSThreat(
            vector=spec["vector"],
            threat_level=spec["threat_level"],
            amplification_factor=spec["amplification"],
            evidence_snippets=[f"NTP byte pattern: {e}" for e in evidence[:5]],
            mitre_technique="T1498.002 - Network Denial of Service: Reflection Amplification",
            suricata_rule=(
                'alert udp any any -> any 123 (msg:"ORACLE-TMF NTP Monlist probe"; '
                'content:"|00 2a|"; offset:2; depth:2; sid:9000003;)'
            ),
        )

    def _detect_http_flood(
        self, all_smali: str, all_strings: list[str]
    ) -> Optional[DDoSThreat]:
        """Detect HTTP flood / Slowloris construction patterns."""
        evidence: list[str] = []

        http_patterns = [
            "OkHttpClient", "randomized.*User-Agent", "User-Agent.*array",
            "HttpURLConnection", "sendRequestLine",
        ]
        for p in http_patterns:
            if re.search(p, all_smali, re.IGNORECASE):
                evidence.append(f"HTTP pattern: {p}")

        # Check for User-Agent pool arrays in strings
        ua_count = sum(1 for s in all_strings if "Mozilla" in s or "Gecko" in s)
        if ua_count >= 3:
            evidence.append(f"User-Agent pool: {ua_count} entries")

        if len(evidence) < 2:
            return None

        spec = DDOS_AMPLIFICATION_FACTORS["http_flood_slowloris"]
        return DDoSThreat(
            vector=spec["vector"],
            threat_level=spec["threat_level"],
            amplification_factor=spec["amplification"],
            evidence_snippets=evidence[:5],
            mitre_technique="T1499.003 - Endpoint Denial of Service: Application Exhaustion",
            suricata_rule=(
                'alert http any any -> any $HTTP_PORTS (msg:"ORACLE-TMF HTTP Flood C2"; '
                'flow:to_server,established; threshold:type threshold,track by_src,'
                'count 50,seconds 1; sid:9000004;)'
            ),
        )

    def _detect_snmp_amplification(
        self, all_smali: str, all_strings: list[str]
    ) -> Optional[DDoSThreat]:
        """Detect SNMP amplification construction patterns."""
        snmp_sigs = ["GetBulkRequest", "community string", "snmp4j", "public", "161"]
        evidence = [s for s in snmp_sigs if s.lower() in all_smali.lower()]

        if len(evidence) < 3:
            return None

        spec = DDOS_AMPLIFICATION_FACTORS["snmp_amplification"]
        return DDoSThreat(
            vector=spec["vector"],
            threat_level=spec["threat_level"],
            amplification_factor=spec["amplification"],
            evidence_snippets=[f"SNMP sig: {e}" for e in evidence[:5]],
            mitre_technique="T1498.002 - Network Denial of Service: Reflection Amplification",
            suricata_rule=(
                'alert udp any any -> any 161 (msg:"ORACLE-TMF SNMP Amplification probe"; '
                'content:"public"; sid:9000005;)'
            ),
        )

    def _detect_dga(
        self, all_smali: str, all_strings: list[str]
    ) -> Optional[DGAProfile]:
        """Detect Domain Generation Algorithm patterns."""
        evidence_count = sum(1 for sig in DGA_SEED_SIGNATURES if sig in all_smali)
        if evidence_count < 3:
            return None

        # Identify seed source
        seed_source = "UNKNOWN"
        if "getTime()" in all_smali or "currentTimeMillis" in all_smali:
            seed_source = "TIMESTAMP"
        elif "getDeviceId" in all_smali or "getImei" in all_smali:
            seed_source = "DEVICE_ID"
        elif "getTime()" in all_smali and "getDeviceId" in all_smali:
            seed_source = "HYBRID"

        # Extract TLD pool from strings
        tlds = [s for s in all_strings if re.match(r"^\.\w{2,6}$", s)]

        # Estimate daily domains (rough: 1 domain per hour with timestamp seed)
        daily_estimate = 24 if seed_source == "TIMESTAMP" else 365

        # Build detection regex from observed TLDs
        tld_pattern = "|".join(re.escape(t) for t in tlds[:10]) if tlds else r"\.\w{2,6}"
        detection_regex = rf"[a-z0-9]{{8,15}}({tld_pattern})"

        logger.info(
            "[NetworkAttackAnalyzer] DGA detected: seed=%s tlds=%d daily=%d",
            seed_source, len(tlds), daily_estimate,
        )
        return DGAProfile(
            seed_source=seed_source,
            tld_pool=tlds[:20],
            estimated_daily_domains=daily_estimate,
            generator_class="java.util.Random",
            detection_regex=detection_regex,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Detection rule generation
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_suricata_rules(
        self,
        threats: list[DDoSThreat],
        mag: MutationArtifactGraph,
    ) -> list[str]:
        """Collect Suricata rules from all detected threats."""
        rules: list[str] = []
        for threat in threats:
            if threat.suricata_rule:
                rules.append(threat.suricata_rule)

        # Add C2 blocking rules from existing c2_stubs
        for i, c2 in enumerate(mag.c2_stubs[:10]):
            if c2.extracted_url and c2.extracted_url.startswith("http"):
                host = re.sub(r"https?://([^/]+).*", r"\1", c2.extracted_url)
                rules.append(
                    f'alert http any any -> any any (msg:"ORACLE-TMF C2 block: {host}"; '
                    f'content:"{host}"; http_host; sid:{9000100 + i}; rev:1;)'
                )
        return rules

    def _generate_stix_indicators(
        self,
        threats: list[DDoSThreat],
        mag: MutationArtifactGraph,
    ) -> list[dict]:
        """Generate STIX 2.1 indicator objects for detected DDoS threats."""
        indicators: list[dict] = []
        for threat in threats:
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--oracle-tmf-ddos-{threat.vector.replace(' ', '-').lower()}",
                "name": f"ORACLE-TMF: {threat.vector} capability in {mag.malware_family}",
                "description": (
                    f"DDoS capability detected via static analysis. "
                    f"Amplification: {threat.amplification_factor}x. "
                    f"Evidence: {'; '.join(threat.evidence_snippets[:2])}"
                ),
                "pattern": f"[malware:name = '{mag.malware_family}']",
                "pattern_type": "stix",
                "valid_from": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "labels": ["malicious-activity", "ddos"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack-mobile", "phase_name": "impact"}
                ],
            })
        return indicators

    # ─────────────────────────────────────────────────────────────────────────
    # Utility
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _collect_smali(mag: MutationArtifactGraph) -> str:
        """Collect all smali text from the MAG's dead code artifacts."""
        return "\n".join(block.smali_code for block in mag.dead_code)
