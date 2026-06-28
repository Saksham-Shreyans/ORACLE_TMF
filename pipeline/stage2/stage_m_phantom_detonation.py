from __future__ import annotations
import logging
import time
from dataclasses import dataclass,field
from typing import Optional
from config.stage2_settings import PHANTOM_MAX_SESSION_TURNS
from models.mutation_artifact_graph import MutationArtifactGraph,MutationForecast
from phantom.deception_engine import PhantomDeceptionEngine,PhantomSession
logger=logging.getLogger(__name__)
@dataclass
class StageMResult:
    session:Optional[PhantomSession]=None
    behaviors_confirmed:list[str]=field(default_factory=list)
    exfiltration_detected:bool=False
    exfiltration_items:list[str]=field(default_factory=list)
    dynamic_c2_hosts:list[str]=field(default_factory=list)
    confidence_boosts:dict[str,float]=field(default_factory=dict)
    detonation_duration_s:float=0.0
    skipped:bool=False
    skip_reason:str=""
    error:str=""
class StageMPhantomDetonation:
    STAGE_ID="M"
    STAGE_NAME="PHANTOM_DETONATION"
    def __init__(self,enabled:bool=False)->None:
        self._enabled=enabled
        self._engine:Optional[PhantomDeceptionEngine]=None
        if enabled:
            self._engine=PhantomDeceptionEngine()
        logger.info("[Stage M] Initialised (enabled=%s)",enabled)
    def run(
        self,
        mag:MutationArtifactGraph,
        forecasts:list[MutationForecast],
        apk_path:str="",
        simulated_commands:Optional[list[str]]=None,
    )->StageMResult:
        t0=time.perf_counter()
        result=StageMResult()
        if not self._enabled or self._engine is None:
            result.skipped=True
            result.skip_reason="PHANTOM not enabled — set phantom_enabled=True in config"
            logger.info("[Stage M] Skipped: disabled")
            return result
        active_forecasts=[f for f in forecasts if f.passes_gate]
        if not active_forecasts:
            result.skipped=True
            result.skip_reason="No forecasts above confidence gate — detonation not warranted"
            logger.info("[Stage M] Skipped: no qualifying forecasts")
            return result
        has_scaffolding=any(
            dc.dte_label=="SCAFFOLDING"
            for dc in mag.dead_code
        )
        if not has_scaffolding and not simulated_commands:
            result.skipped=True
            result.skip_reason="No SCAFFOLDING artifacts detected — detonation unlikely to succeed"
            logger.info("[Stage M] Skipped: no scaffolding detected")
            return result
        try:
            session=self._engine.start_session(apk_path=apk_path or mag.apk_metadata.sha256)
            commands=simulated_commands or self._build_probe_sequence(mag,forecasts)
            for cmd in commands[:PHANTOM_MAX_SESSION_TURNS]:
                if not session.is_active:
                    break
                self._engine.respond(session,cmd)
            self._engine.end_session(session)
            result.session=session
            result.behaviors_confirmed=list(set(session.behaviors_captured))
            all_exfil=[
                ex for turn in session.turns for ex in turn.exfiltration_attempts
            ]
            result.exfiltration_detected=len(all_exfil)>0
            result.exfiltration_items=all_exfil[:20]
            result.dynamic_c2_hosts=self._extract_c2_hosts(session)
            result.confidence_boosts=self._compute_confidence_boosts(
                result.behaviors_confirmed,forecasts
            )
        except Exception as exc:
            logger.error("[Stage M] Detonation failed: %s",exc)
            result.error=str(exc)
        result.detonation_duration_s=round(time.perf_counter()-t0,2)
        logger.info(
            "[Stage M] Complete: behaviors=%d exfil=%s boosts=%d (%.1fs)",
            len(result.behaviors_confirmed),
            result.exfiltration_detected,
            len(result.confidence_boosts),
            result.detonation_duration_s,
        )
        return result
    @staticmethod
    def _build_probe_sequence(
        mag:MutationArtifactGraph,
        forecasts:list[MutationForecast],
    )->list[str]:
        probes=[
            '{"action": "LAUNCH_MAIN_ACTIVITY"}',
            '{"action": "REQUEST_SMS_PERMISSION_GRANTED"}',
            '{"action": "REQUEST_ACCESSIBILITY_PERMISSION_GRANTED"}',
            '{"action": "RECEIVE_SMS", "sender": "VM-SBIBNK", '
            '"body": "SBI: OTP for login is 123456. Valid 10 mins."}',
            '{"action": "CONTACT_LIST_QUERIED", "count": 150}',
            '{"action": "CLIPBOARD_READ", "content": "4111111111111234"}',
            '{"action": "SCREEN_ON", "app_foreground": "com.sbi.lotusintouch"}',
        ]
        for forecast in forecasts[:2]:
            if "ATS" in forecast.predicted_technique or "Accessibility" in forecast.predicted_technique:
                probes.append('{"action": "ACCESSIBILITY_EVENT", "eventType": 1, '
                              '"packageName": "com.sbi.lotusintouch"}')
            if "SMS" in forecast.predicted_technique:
                probes.append('{"action": "SMS_RECEIVED", "address": "VM-HDFCBK", '
                              '"body": "HDFC: OTP 789012 for transaction Rs 25000"}')
        return probes
    @staticmethod
    def _extract_c2_hosts(session:PhantomSession)->list[str]:
        import re
        hosts:set[str]=set()
        for turn in session.turns:
            matches=re.findall(r"https?://([^/\"'\\s]+)",turn.malware_command)
            hosts.update(matches)
        return sorted(hosts)
    @staticmethod
    def _compute_confidence_boosts(
        confirmed_behaviors:list[str],
        forecasts:list[MutationForecast],
    )->dict[str,float]:
        boosts:dict[str,float]={}
        behavior_to_technique={
            "SMS_READ":"T1636.004",
            "OTP_INTERCEPT":"T1636.004",
            "ACCESSIBILITY_ABUSE":"T1417",
            "OVERLAY_ATTACK":"T1417",
            "SCREEN_CAPTURE":"T1513",
            "CONTACTS_READ":"T1636.003",
            "LOCATION_HARVEST":"T1430",
            "UPI_FRAUD":"T1640",
        }
        for behavior in confirmed_behaviors:
            technique_id=behavior_to_technique.get(behavior)
            if technique_id:
                for forecast in forecasts:
                    if technique_id in forecast.predicted_technique:
                        boosts[forecast.predicted_technique]=boosts.get(
                            forecast.predicted_technique,0.0
                        )+0.10
        return boosts
