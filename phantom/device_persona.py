"""
ORACLE-TMF  ·  phantom/device_persona.py
==========================================
PHANTOM Device Persona Generator — Stage 2 Tier 2.

Generates a deterministic, internally consistent Android device persona for
the PHANTOM Active Deception Engine.  The persona is used to populate:
  • Frida hook return values (Build.*, TelephonyManager.*)
  • PHANTOM LLM simulation context
  • Synthetic sensor data calibration

The persona must be 100% internally consistent (IMEI checksum valid,
build fingerprint format correct, SDK int matching Android version, etc.)
otherwise sophisticated malware anti-analysis checks will detect the
deception environment.

Design principle: One persona per detonation session (randomly selected
from PHANTOM_DEVICE_PERSONAS) with per-session randomised sub-fields
(IMEI, phone number, account ID, ICCID) so that honeytokens are unique
and cannot be reused across sessions.
"""
from __future__ import annotations

import hashlib
import logging
import random
import string
import time
from dataclasses import dataclass, field
from typing import Optional

from config.stage2_settings import PHANTOM_DEVICE_PERSONAS

logger = logging.getLogger(__name__)


@dataclass
class AndroidPersona:
    """
    A fully-specified Android device persona for PHANTOM detonation.

    All fields are internally consistent — no contradictions that would
    trigger anti-emulation checks in real-world malware.
    """

    # Build identity
    manufacturer: str = ""
    model: str = ""
    brand: str = ""
    device: str = ""
    product: str = ""
    android_version: str = ""
    sdk_int: int = 33
    build_id: str = ""
    fingerprint: str = ""

    # Telephony identity
    country_iso: str = "in"
    network_operator: str = ""
    network_operator_name: str = ""
    sim_operator: str = ""
    sim_operator_name: str = ""
    imei: str = ""
    imsi: str = ""
    iccid: str = ""
    phone_number: str = ""

    # Sensor calibration reference
    ou_gyro_mu: float = 0.0         # Gyroscope mean
    ou_accel_mu: float = 9.81       # Accelerometer mean (gravity)
    ou_light_mu: float = 250.0      # Ambient light mean (lux)

    # Session identity
    session_id: str = ""
    created_at: float = 0.0


class DevicePersonaGenerator:
    """
    Generates AndroidPersona instances for PHANTOM detonation sessions.

    Usage
    -----
    >>> generator = DevicePersonaGenerator()
    >>> persona = generator.generate()
    >>> persona = generator.generate(persona_index=0)  # Specific device
    """

    # Indian MNO codes (for realistic SIM configuration)
    _INDIAN_OPERATORS: list[dict] = [
        {
            "sim_operator": "40410",
            "sim_operator_name": "Airtel",
            "network_operator": "40410",
            "network_operator_name": "Bharti Airtel",
            "phone_prefix": "+919",
        },
        {
            "sim_operator": "40420",
            "sim_operator_name": "Vodafone IN",
            "network_operator": "40420",
            "network_operator_name": "Vi",
            "phone_prefix": "+917",
        },
        {
            "sim_operator": "40430",
            "sim_operator_name": "Airtel",
            "network_operator": "40430",
            "network_operator_name": "Bharti Airtel",
            "phone_prefix": "+918",
        },
        {
            "sim_operator": "40485",
            "sim_operator_name": "Reliance Jio",
            "network_operator": "40485",
            "network_operator_name": "Reliance Jio",
            "phone_prefix": "+916",
        },
    ]

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)
        logger.info("[DevicePersona] Generator initialised")

    def generate(self, persona_index: Optional[int] = None) -> AndroidPersona:
        """
        Generate a fully-consistent Android device persona.

        Parameters
        ----------
        persona_index : int | None
            Index into PHANTOM_DEVICE_PERSONAS.  None = random selection.

        Returns
        -------
        AndroidPersona
        """
        t0 = time.perf_counter()

        # Select base persona template
        if persona_index is not None and 0 <= persona_index < len(PHANTOM_DEVICE_PERSONAS):
            template = PHANTOM_DEVICE_PERSONAS[persona_index]
        else:
            template = self._rng.choice(PHANTOM_DEVICE_PERSONAS)

        # Select operator
        operator = self._rng.choice(self._INDIAN_OPERATORS)

        # Generate per-session unique identifiers
        imei = self._generate_imei()
        imsi = self._generate_imsi(operator["sim_operator"])
        iccid = self._generate_iccid()
        phone = self._generate_phone(operator["phone_prefix"])
        session_id = self._generate_session_id(imei, iccid)

        persona = AndroidPersona(
            manufacturer=template["manufacturer"],
            model=template["model"],
            brand=template["brand"],
            device=template["device"],
            product=template["product"],
            android_version=template["android_version"],
            sdk_int=template["sdk_int"],
            build_id=template["build_id"],
            fingerprint=template["fingerprint"],
            country_iso=template["country_iso"],
            network_operator=operator["network_operator"],
            network_operator_name=operator["network_operator_name"],
            sim_operator=operator["sim_operator"],
            sim_operator_name=operator["sim_operator_name"],
            imei=imei,
            imsi=imsi,
            iccid=iccid,
            phone_number=phone,
            session_id=session_id,
            created_at=time.time(),
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[DevicePersona] Generated persona: model=%s operator=%s session=%s (%.1f ms)",
            persona.model, persona.sim_operator_name, persona.session_id[:8], elapsed_ms,
        )
        return persona

    def to_frida_context(self, persona: AndroidPersona) -> dict:
        """
        Serialize the persona to a dict suitable for Frida JS script injection.

        Returns
        -------
        dict
            All persona fields that the Frida bypass scripts need to override.
        """
        return {
            "manufacturer": persona.manufacturer,
            "model": persona.model,
            "brand": persona.brand,
            "device": persona.device,
            "product": persona.product,
            "android_version": persona.android_version,
            "sdk_int": persona.sdk_int,
            "build_id": persona.build_id,
            "fingerprint": persona.fingerprint,
            "country_iso": persona.country_iso,
            "network_operator": persona.network_operator,
            "network_operator_name": persona.network_operator_name,
            "sim_operator": persona.sim_operator,
            "sim_operator_name": persona.sim_operator_name,
            "imei": persona.imei,
            "imsi": persona.imsi,
            "phone_number": persona.phone_number,
        }

    def to_llm_context(self, persona: AndroidPersona) -> str:
        """
        Format the persona as a string block for the PHANTOM LLM system prompt.
        """
        return (
            f"DEVICE ENVIRONMENT (do not deviate from these values):\n"
            f"  Manufacturer: {persona.manufacturer}\n"
            f"  Model: {persona.model}\n"
            f"  Android: {persona.android_version} (API {persona.sdk_int})\n"
            f"  Build: {persona.build_id}\n"
            f"  Country ISO: {persona.country_iso.upper()}\n"
            f"  Operator: {persona.sim_operator_name} ({persona.sim_operator})\n"
            f"  IMEI: {persona.imei}\n"
            f"  Phone: {persona.phone_number}\n"
            f"  Session: {persona.session_id}\n"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Identifier generators (internally valid formats)
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_imei(self) -> str:
        """
        Generate a Luhn-valid 15-digit IMEI.

        Real IMEIs have a valid Luhn checksum.  Sophisticated anti-analysis
        checks verify this.  We always generate a valid IMEI.
        """
        # TAC (8 digits): pick a real Qualcomm-based TAC prefix
        tac_prefixes = [
            "35397010",  # Samsung Galaxy
            "35897010",  # Xiaomi Redmi
            "86819205",  # OnePlus
            "35895711",  # Samsung Galaxy S21
        ]
        tac = self._rng.choice(tac_prefixes)
        # SNR (6 random digits)
        snr = "".join(str(self._rng.randint(0, 9)) for _ in range(6))
        base = tac + snr  # 14 digits
        # Compute Luhn check digit
        check = self._luhn_check_digit(base)
        return base + str(check)

    def _generate_imsi(self, mcc_mnc: str) -> str:
        """Generate a realistic 15-digit IMSI."""
        # MSIN: 10 digits completing the 15-digit IMSI
        msin = "".join(str(self._rng.randint(0, 9)) for _ in range(10))
        return mcc_mnc + msin

    def _generate_iccid(self) -> str:
        """Generate a Luhn-valid 20-digit ICCID (SIM card identifier)."""
        # 89: ITU-T prefix for telecommunications
        # 91: India country code for SIM cards
        prefix = "8991"
        suffix = "".join(str(self._rng.randint(0, 9)) for _ in range(15))
        base = prefix + suffix  # 19 digits
        check = self._luhn_check_digit(base)
        return base + str(check)

    def _generate_phone(self, prefix: str) -> str:
        """Generate a realistic Indian phone number."""
        digits = "".join(str(self._rng.randint(0, 9)) for _ in range(9))
        return prefix + digits

    @staticmethod
    def _generate_session_id(imei: str, iccid: str) -> str:
        """Derive a unique session ID from IMEI + ICCID."""
        raw = f"{imei}:{iccid}:{time.time_ns()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _luhn_check_digit(number: str) -> int:
        """
        Compute the Luhn check digit for a numeric string.

        This is the standard algorithm used in IMEI and credit card
        validation.  Malware uses this to detect synthetic IMEIs.
        """
        digits = [int(d) for d in number]
        # Double every second digit from the right
        for i in range(len(digits) - 1, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        total = sum(digits)
        return (10 - (total % 10)) % 10
