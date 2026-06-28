from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass,field
from typing import Optional
from config.settings import ANTHROPIC_API_KEY,LLM_MODEL,LLM_MAX_TOKENS
from config.stage2_settings import(
    PHANTOM_MAX_SESSION_TURNS,
    PHANTOM_SESSION_TIMEOUT_S,
)
from phantom.device_persona import AndroidPersona,DevicePersonaGenerator
from phantom.honeytoken_generator import HoneytokenGenerator,PhantomHoneytokenBundle
from phantom.sensory_emulation import SensoryEmulator,SensorSample
from phantom.behavioral_biometrics import BehavioralBiometricGenerator
logger=logging.getLogger(__name__)
@dataclass
class PhantomTurn:
    turn_index:int=0
    timestamp:float=0.0
    malware_command:str=""
    phantom_response:str=""
    sensor_snapshot:dict=field(default_factory=dict)
    detected_behaviors:list[str]=field(default_factory=list)
    exfiltration_attempts:list[str]=field(default_factory=list)
@dataclass
class PhantomSession:
    session_id:str=""
    apk_path:str=""
    persona:Optional[AndroidPersona]=None
    bundle:Optional[PhantomHoneytokenBundle]=None
    turns:list[PhantomTurn]=field(default_factory=list)
    started_at:float=0.0
    completed_at:float=0.0
    is_active:bool=False
    total_turns:int=0
    timed_out:bool=False
    behaviors_captured:list[str]=field(default_factory=list)
    def elapsed_s(self)->float:
        return time.time()-self.started_at
    def to_dict(self)->dict:
        return{
            "session_id":self.session_id,
            "apk_path":self.apk_path,
            "persona_model":self.persona.model if self.persona else "",
            "started_at":self.started_at,
            "completed_at":self.completed_at,
            "total_turns":self.total_turns,
            "timed_out":self.timed_out,
            "behaviors_captured":self.behaviors_captured,
            "exfiltration_attempts":[
                ex for turn in self.turns
                for ex in turn.exfiltration_attempts
            ],
            "turns":[
                {
                    "turn":t.turn_index,
                    "command_preview":t.malware_command[:200],
                    "response_preview":t.phantom_response[:200],
                    "behaviors":t.detected_behaviors,
                    "exfil_attempts":t.exfiltration_attempts,
                }
                for t in self.turns
            ],
        }
class PhantomDeceptionEngine:
    def __init__(self)->None:
        self._persona_gen=DevicePersonaGenerator()
        self._honeytoken_gen=HoneytokenGenerator()
        self._sensor_emulator=SensoryEmulator()
        self._biometric_gen=BehavioralBiometricGenerator()
        logger.info("[PHANTOM] Deception engine initialised")
    def start_session(
        self,
        apk_path:str,
        persona_index:Optional[int]=None,
    )->PhantomSession:
        persona=self._persona_gen.generate(persona_index=persona_index)
        bundle=self._honeytoken_gen.generate(persona)
        self._sensor_emulator.reset()
        session=PhantomSession(
            session_id=persona.session_id,
            apk_path=apk_path,
            persona=persona,
            bundle=bundle,
            started_at=time.time(),
            is_active=True,
        )
        logger.info(
            "[PHANTOM] Session started: id=%s persona=%s",
            session.session_id[:8],persona.model,
        )
        return session
    def respond(
        self,
        session:PhantomSession,
        command:str,
    )->str:
        if not session.is_active:
            return '{"error": "session_expired"}'
        if session.total_turns>=PHANTOM_MAX_SESSION_TURNS:
            logger.warning(
                "[PHANTOM] Session %s hit turn limit (%d)",
                session.session_id[:8],PHANTOM_MAX_SESSION_TURNS,
            )
            self.end_session(session,reason="turn_limit")
            return '{"error": "session_expired"}'
        if session.elapsed_s()>PHANTOM_SESSION_TIMEOUT_S:
            logger.warning(
                "[PHANTOM] Session %s timed out",session.session_id[:8]
            )
            self.end_session(session,reason="timeout")
            return '{"error": "session_expired"}'
        sensor_sample=self._sensor_emulator.next_sample()
        sensor_json=self._sensor_emulator.sample_as_android_json(sensor_sample)
        exfil_attempts=self._detect_exfiltration(command,session.bundle)
        prompt=self._build_simulation_prompt(session,command,sensor_json)
        response_text=self._call_llm(prompt,session)
        turn=PhantomTurn(
            turn_index=session.total_turns,
            timestamp=time.time(),
            malware_command=command,
            phantom_response=response_text,
            sensor_snapshot=sensor_json,
            detected_behaviors=self._classify_behaviors(command,response_text),
            exfiltration_attempts=exfil_attempts,
        )
        session.turns.append(turn)
        session.total_turns+=1
        session.behaviors_captured.extend(turn.detected_behaviors)
        if any("OTP" in ex or "otp" in ex for ex in exfil_attempts)and session.bundle:
            self._honeytoken_gen.refresh_otp(session.bundle,purpose="detonation")
            logger.info("[PHANTOM] OTP exfil detected — honeytoken refreshed")
        return response_text
    def end_session(
        self,
        session:PhantomSession,
        reason:str="normal",
    )->PhantomSession:
        session.is_active=False
        session.completed_at=time.time()
        session.timed_out=(reason=="timeout")
        logger.info(
            "[PHANTOM] Session ended: id=%s reason=%s turns=%d behaviors=%d",
            session.session_id[:8],
            reason,
            session.total_turns,
            len(set(session.behaviors_captured)),
        )
        return session
    def _build_simulation_prompt(
        self,
        session:PhantomSession,
        command:str,
        sensor_json:dict,
    )->str:
        if not session.persona or not session.bundle:
            return command
        persona_ctx=self._persona_gen.to_llm_context(session.persona)
        sms_rows=self._honeytoken_gen.format_as_android_sms_db(session.bundle)
        history_ctx=""
        recent=session.turns[-5:]
        for turn in recent:
            history_ctx+=(
                f"\n[TURN{turn.turn_index}]\n"
                f"MALWARE:{turn.malware_command[:300]}\n"
                f"ANDROID:{turn.phantom_response[:300]}\n"
            )
        system=(
            "You are simulating an Android device for a controlled malware analysis "
            "environment (PHANTOM). Your role is to respond authentically as the Android "
            "OS or any server infrastructure the malware communicates with, using ONLY "
            "the device state and credentials provided below. NEVER introduce real "
            "credentials — all data below is synthetic honeytokens.\n\n"
            +persona_ctx
            +f"\nACTIVE OTP:{session.bundle.active_otp}(bank:{session.bundle.otp_target_bank})\n"
            +f"\nSMS INBOX SAMPLE:\n"
            +"\n".join(
                f"[{i+1}]FROM={s['sender']}:{s['body']}"
                for i,s in enumerate(session.bundle.synthetic_sms[:3])
            )
            +f"\n\nSENSOR STATE:\n"
            +f"  Gyro:x={sensor_json['TYPE_GYROSCOPE']['values'][0]:.4f}"
            +f"y={sensor_json['TYPE_GYROSCOPE']['values'][1]:.4f}"
            +f"z={sensor_json['TYPE_GYROSCOPE']['values'][2]:.4f}rad/s\n"
            +f"  Light:{sensor_json['TYPE_LIGHT']['values'][0]:.1f}lux\n"
            +f"\nSESSION HISTORY:{history_ctx}\n"
            +"\nRespond ONLY with the raw Android API result or HTTP response the malware "
            "would receive. Output valid JSON or plain text as appropriate. "
            "Never explain your role or break character."
        )
        return f"SYSTEM:\n{system}\n\nMALWARE_COMMAND:\n{command}"
    def _call_llm(self,prompt:str,session:PhantomSession)->str:
        if not ANTHROPIC_API_KEY:
            logger.warning("[PHANTOM] No API key — using stub responder")
            return self._stub_response(prompt)
        try:
            import anthropic
            client=anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            parts=prompt.split("\nMALWARE_COMMAND:\n",1)
            system_content=parts[0].replace("SYSTEM:\n","").strip()
            user_content=parts[1].strip()if len(parts)>1 else prompt
            msg=client.messages.create(
                model=LLM_MODEL,
                max_tokens=LLM_MAX_TOKENS,
                system=system_content,
                messages=[{"role":"user","content":user_content}],
            )
            response="".join(
                block.text for block in msg.content if hasattr(block,"text")
            )
            logger.debug("[PHANTOM] LLM response length=%d",len(response))
            return response
        except Exception as exc:
            logger.error("[PHANTOM] LLM call failed: %s",exc)
            return self._stub_response(prompt)
    @staticmethod
    def _stub_response(prompt:str)->str:
        if "sms" in prompt.lower():
            return '{"status": "ok", "sms_count": 15}'
        if "otp" in prompt.lower():
            return '{"status": "ok", "otp_sent": true}'
        if "contact" in prompt.lower():
            return '{"status": "ok", "contacts": []}'
        return '{"status": "ok"}'
    @staticmethod
    def _detect_exfiltration(
        command:str,bundle:Optional[PhantomHoneytokenBundle]
    )->list[str]:
        if bundle is None:
            return[]
        exfil:list[str]=[]
        cmd_lower=command.lower()
        if bundle.active_otp and bundle.active_otp in command:
            exfil.append(f"OTP_EXFIL:{bundle.active_otp}")
        if bundle.primary_account.upi_vpa and bundle.primary_account.upi_vpa in command:
            exfil.append(f"UPI_VPA_EXFIL:{bundle.primary_account.upi_vpa}")
        if bundle.primary_account.net_banking_pass in command:
            exfil.append(f"NETBANKING_PASS_EXFIL")
        if bundle.primary_card.card_number in command:
            exfil.append(f"CARD_NUMBER_EXFIL:{bundle.primary_card.last_four}")
        if "oracle_pha" in cmd_lower:
            exfil.append(f"HONEYTOKEN_MARKER_DETECTED")
        return exfil
    @staticmethod
    def _classify_behaviors(command:str,response:str)->list[str]:
        behaviors:list[str]=[]
        cmd_lower=command.lower()
        behavior_patterns=[
            ("sms","SMS_READ"),
            ("contact","CONTACTS_READ"),
            ("otp","OTP_INTERCEPT"),
            ("overlay","OVERLAY_ATTACK"),
            ("accessibility","ACCESSIBILITY_ABUSE"),
            ("keylog","KEYLOGGER_ACTIVE"),
            ("screen","SCREEN_CAPTURE"),
            ("location","LOCATION_HARVEST"),
            ("camera","CAMERA_ACCESS"),
            ("microphone","MIC_ACCESS"),
            ("clipboard","CLIPBOARD_HARVEST"),
            ("upi","UPI_FRAUD"),
            ("neft","BANK_TRANSFER_FRAUD"),
            ("imei","DEVICE_ID_HARVEST"),
            ("install","APK_DROPPER"),
        ]
        for pattern,label in behavior_patterns:
            if pattern in cmd_lower:
                behaviors.append(label)
        return list(set(behaviors))
