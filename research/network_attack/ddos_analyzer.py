from __future__ import annotations
import logging
import re
import time
from dataclasses import dataclass,field
from typing import Optional
from config.stage2_settings import(
    ANC_RAW_SOCKET_SIGNATURES,
    DGA_SEED_SIGNATURES,
    DDOS_AMPLIFICATION_FACTORS,
)
from models.mutation_artifact_graph import(
    MutationArtifactGraph,
    DeadCodeArtifact,
)
logger=logging.getLogger(__name__)
@dataclass
class DDoSThreat:
    vector:str=""
    threat_level:str=""
    amplification_factor:float=1.0
    evidence_snippets:list[str]=field(default_factory=list)
    affected_classes:list[str]=field(default_factory=list)
    mitre_technique:str=""
    suricata_rule:str=""
@dataclass
class DGAProfile:
    seed_source:str=""
    tld_pool:list[str]=field(default_factory=list)
    estimated_daily_domains:int=0
    generator_class:str=""
    detection_regex:str=""
@dataclass
class NetworkAttackResult:
    apk_hash:str=""
    detected_threats:list[DDoSThreat]=field(default_factory=list)
    dga_profile:Optional[DGAProfile]=None
    highest_threat_level:str="NONE"
    max_amplification_factor:float=0.0
    suricata_rules:list[str]=field(default_factory=list)
    stix_indicators:list[dict]=field(default_factory=list)
    runtime_ms:float=0.0
    def to_dict(self)->dict:
        return{
            "apk_hash":self.apk_hash,
            "threat_count":len(self.detected_threats),
            "highest_threat_level":self.highest_threat_level,
            "max_amplification_factor":round(self.max_amplification_factor,1),
            "has_dga":self.dga_profile is not None,
            "suricata_rules_count":len(self.suricata_rules),
            "runtime_ms":round(self.runtime_ms,2),
            "threats":[
                {
                    "vector":t.vector,
                    "level":t.threat_level,
                    "amplification":t.amplification_factor,
                    "mitre":t.mitre_technique,
                    "evidence_count":len(t.evidence_snippets),
                }
                for t in self.detected_threats
            ],
            "dga_profile":(
                {
                    "seed_source":self.dga_profile.seed_source,
                    "tld_count":len(self.dga_profile.tld_pool),
                    "estimated_daily_domains":self.dga_profile.estimated_daily_domains,
                }
                if self.dga_profile else None
            ),
        }
class NetworkAttackAnalyzer:
    ENGINE_NAME="NETWORK_ATTACK_ANALYZER"
    _THREAT_PRIORITY={"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"NONE":0}
    def __init__(self)->None:
        logger.info("[NetworkAttackAnalyzer] Engine initialised")
    def analyze(self,mag:MutationArtifactGraph)->NetworkAttackResult:
        t0=time.perf_counter()
        apk_hash=mag.apk_metadata.sha256[:16]or "unknown"
        logger.info("[NetworkAttackAnalyzer] Analyzing APK %s",apk_hash)
        result=NetworkAttackResult(apk_hash=apk_hash)
        detected:list[DDoSThreat]=[]
        all_smali=self._collect_smali(mag)
        all_strings=[s.value for s in mag.placeholder_strings]
        all_c2_urls=[c.extracted_url for c in mag.c2_stubs]
        syn_threat=self._detect_syn_flood(all_smali,mag.dead_code)
        if syn_threat:
            detected.append(syn_threat)
        dns_threat=self._detect_dns_amplification(all_smali,all_strings)
        if dns_threat:
            detected.append(dns_threat)
        ntp_threat=self._detect_ntp_amplification(all_smali)
        if ntp_threat:
            detected.append(ntp_threat)
        http_threat=self._detect_http_flood(all_smali,all_strings)
        if http_threat:
            detected.append(http_threat)
        snmp_threat=self._detect_snmp_amplification(all_smali,all_strings)
        if snmp_threat:
            detected.append(snmp_threat)
        dga_profile=self._detect_dga(all_smali,all_strings)
        result.detected_threats=detected
        result.dga_profile=dga_profile
        if detected:
            best=max(detected,key=lambda t:self._THREAT_PRIORITY.get(t.threat_level,0))
            result.highest_threat_level=best.threat_level
            result.max_amplification_factor=max(t.amplification_factor for t in detected)
            result.suricata_rules=self._generate_suricata_rules(detected,mag)
            result.stix_indicators=self._generate_stix_indicators(detected,mag)
        result.runtime_ms=round((time.perf_counter()-t0)*1000,2)
        logger.info(
            "[NetworkAttackAnalyzer] Complete: apk=%s threats=%d level=%s amp=%.0fx (%.1f ms)",
            apk_hash,len(detected),result.highest_threat_level,
            result.max_amplification_factor,result.runtime_ms,
        )
        return result
    def _detect_syn_flood(
        self,
        all_smali:str,
        dead_code:list[DeadCodeArtifact],
    )->Optional[DDoSThreat]:
        evidence:list[str]=[]
        affected:list[str]=[]
        for sig in ANC_RAW_SOCKET_SIGNATURES:
            if sig in all_smali:
                evidence.append(f"Signature found:'{sig}'")
        for block in dead_code:
            if any(sig in block.smali_code for sig in ANC_RAW_SOCKET_SIGNATURES):
                affected.append(block.class_name)
        if not evidence:
            return None
        spec=DDOS_AMPLIFICATION_FACTORS["syn_flood"]
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
        self,all_smali:str,all_strings:list[str]
    )->Optional[DDoSThreat]:
        evidence:list[str]=[]
        dns_patterns=[
            r"DNS\s+ANY",r"DNS\s+TXT",r"DatagramPacket",
            r"dnsjava",r"Inet4Address.*spoof",
        ]
        for pattern in dns_patterns:
            if re.search(pattern,all_smali,re.IGNORECASE):
                evidence.append(f"DNS pattern:{pattern}")
        for s in all_strings:
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",s):
                evidence.append(f"Hardcoded IP(potential reflector):{s}")
                break
        if len(evidence)<2:
            return None
        spec=DDOS_AMPLIFICATION_FACTORS["dns_amplification"]
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
    def _detect_ntp_amplification(self,all_smali:str)->Optional[DDoSThreat]:
        ntp_bytes=["\\x16\\x03\\x01","0x2a","monlist","\\x00\\x2a","NTP"]
        evidence=[b for b in ntp_bytes if b in all_smali]
        if len(evidence)<2:
            return None
        spec=DDOS_AMPLIFICATION_FACTORS["ntp_amplification"]
        return DDoSThreat(
            vector=spec["vector"],
            threat_level=spec["threat_level"],
            amplification_factor=spec["amplification"],
            evidence_snippets=[f"NTP byte pattern:{e}" for e in evidence[:5]],
            mitre_technique="T1498.002 - Network Denial of Service: Reflection Amplification",
            suricata_rule=(
                'alert udp any any -> any 123 (msg:"ORACLE-TMF NTP Monlist probe"; '
                'content:"|00 2a|"; offset:2; depth:2; sid:9000003;)'
            ),
        )
    def _detect_http_flood(
        self,all_smali:str,all_strings:list[str]
    )->Optional[DDoSThreat]:
        evidence:list[str]=[]
        http_patterns=[
            "OkHttpClient","randomized.*User-Agent","User-Agent.*array",
            "HttpURLConnection","sendRequestLine",
        ]
        for p in http_patterns:
            if re.search(p,all_smali,re.IGNORECASE):
                evidence.append(f"HTTP pattern:{p}")
        ua_count=sum(1 for s in all_strings if "Mozilla" in s or "Gecko" in s)
        if ua_count>=3:
            evidence.append(f"User-Agent pool:{ua_count}entries")
        if len(evidence)<2:
            return None
        spec=DDOS_AMPLIFICATION_FACTORS["http_flood_slowloris"]
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
        self,all_smali:str,all_strings:list[str]
    )->Optional[DDoSThreat]:
        snmp_sigs=["GetBulkRequest","community string","snmp4j","public","161"]
        evidence=[s for s in snmp_sigs if s.lower()in all_smali.lower()]
        if len(evidence)<3:
            return None
        spec=DDOS_AMPLIFICATION_FACTORS["snmp_amplification"]
        return DDoSThreat(
            vector=spec["vector"],
            threat_level=spec["threat_level"],
            amplification_factor=spec["amplification"],
            evidence_snippets=[f"SNMP sig:{e}" for e in evidence[:5]],
            mitre_technique="T1498.002 - Network Denial of Service: Reflection Amplification",
            suricata_rule=(
                'alert udp any any -> any 161 (msg:"ORACLE-TMF SNMP Amplification probe"; '
                'content:"public"; sid:9000005;)'
            ),
        )
    def _detect_dga(
        self,all_smali:str,all_strings:list[str]
    )->Optional[DGAProfile]:
        evidence_count=sum(1 for sig in DGA_SEED_SIGNATURES if sig in all_smali)
        if evidence_count<3:
            return None
        seed_source="UNKNOWN"
        has_time = "getTime()" in all_smali or "currentTimeMillis" in all_smali
        has_device = "getDeviceId" in all_smali or "getImei" in all_smali
        if has_time and has_device:
            seed_source="HYBRID"
        elif has_time:
            seed_source="TIMESTAMP"
        elif has_device:
            seed_source="DEVICE_ID"
        tlds=[s for s in all_strings if re.match(r"^\.\w{2,6}$",s)]
        daily_estimate=24 if seed_source=="TIMESTAMP" else 365
        tld_pattern="|".join(re.escape(t)for t in tlds[:10])if tlds else r"\.\w{2,6}"
        detection_regex=rf"[a-z0-9]{{8,15}}({tld_pattern})"
        logger.info(
            "[NetworkAttackAnalyzer] DGA detected: seed=%s tlds=%d daily=%d",
            seed_source,len(tlds),daily_estimate,
        )
        return DGAProfile(
            seed_source=seed_source,
            tld_pool=tlds[:20],
            estimated_daily_domains=daily_estimate,
            generator_class="java.util.Random",
            detection_regex=detection_regex,
        )
    def _generate_suricata_rules(
        self,
        threats:list[DDoSThreat],
        mag:MutationArtifactGraph,
    )->list[str]:
        rules:list[str]=[]
        for threat in threats:
            if threat.suricata_rule:
                rules.append(threat.suricata_rule)
        for i,c2 in enumerate(mag.c2_stubs[:10]):
            if c2.extracted_url and c2.extracted_url.startswith("http"):
                host=re.sub(r"https?://([^/]+).*",r"\1",c2.extracted_url)
                rules.append(
                    f'alert http any any -> any any (msg:"ORACLE-TMF C2 block: {host}"; '
                    f'content:"{host}"; http_host; sid:{9000100+i}; rev:1;)'
                )
        return rules
    def _generate_stix_indicators(
        self,
        threats:list[DDoSThreat],
        mag:MutationArtifactGraph,
    )->list[dict]:
        indicators:list[dict]=[]
        for threat in threats:
            indicators.append({
                "type":"indicator",
                "spec_version":"2.1",
                "id":f"indicator--oracle-tmf-ddos-{threat.vector.replace(' ','-').lower()}",
                "name":f"ORACLE-TMF:{threat.vector}capability in{mag.malware_family}",
                "description":(
                    f"DDoS capability detected via static analysis."
                    f"Amplification:{threat.amplification_factor}x."
                    f"Evidence:{'; '.join(threat.evidence_snippets[:2])}"
                ),
                "pattern":f"[malware:name='{mag.malware_family}']",
                "pattern_type":"stix",
                "valid_from":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
                "labels":["malicious-activity","ddos"],
                "kill_chain_phases":[
                    {"kill_chain_name":"mitre-attack-mobile","phase_name":"impact"}
                ],
            })
        return indicators
    @staticmethod
    def _collect_smali(mag:MutationArtifactGraph)->str:
        return "\n".join(block.smali_code for block in mag.dead_code)
