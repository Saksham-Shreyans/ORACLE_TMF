from __future__ import annotations
import hashlib
import logging
import random
import string
import time
from dataclasses import dataclass,field
from typing import Optional
from config.stage2_settings import PHANTOM_DEVICE_PERSONAS
logger=logging.getLogger(__name__)
@dataclass
class AndroidPersona:
    manufacturer:str=""
    model:str=""
    brand:str=""
    device:str=""
    product:str=""
    android_version:str=""
    sdk_int:int=33
    build_id:str=""
    fingerprint:str=""
    country_iso:str="in"
    network_operator:str=""
    network_operator_name:str=""
    sim_operator:str=""
    sim_operator_name:str=""
    imei:str=""
    imsi:str=""
    iccid:str=""
    phone_number:str=""
    ou_gyro_mu:float=0.0
    ou_accel_mu:float=9.81
    ou_light_mu:float=250.0
    session_id:str=""
    created_at:float=0.0
class DevicePersonaGenerator:
    _INDIAN_OPERATORS:list[dict]=[
        {
            "sim_operator":"40410",
            "sim_operator_name":"Airtel",
            "network_operator":"40410",
            "network_operator_name":"Bharti Airtel",
            "phone_prefix":"+919",
        },
        {
            "sim_operator":"40420",
            "sim_operator_name":"Vodafone IN",
            "network_operator":"40420",
            "network_operator_name":"Vi",
            "phone_prefix":"+917",
        },
        {
            "sim_operator":"40430",
            "sim_operator_name":"Airtel",
            "network_operator":"40430",
            "network_operator_name":"Bharti Airtel",
            "phone_prefix":"+918",
        },
        {
            "sim_operator":"40485",
            "sim_operator_name":"Reliance Jio",
            "network_operator":"40485",
            "network_operator_name":"Reliance Jio",
            "phone_prefix":"+916",
        },
    ]
    def __init__(self,seed:Optional[int]=None)->None:
        self._rng=random.Random(seed)
        logger.info("[DevicePersona] Generator initialised")
    def generate(self,persona_index:Optional[int]=None)->AndroidPersona:
        t0=time.perf_counter()
        if persona_index is not None and 0<=persona_index<len(PHANTOM_DEVICE_PERSONAS):
            template=PHANTOM_DEVICE_PERSONAS[persona_index]
        else:
            template=self._rng.choice(PHANTOM_DEVICE_PERSONAS)
        operator=self._rng.choice(self._INDIAN_OPERATORS)
        imei=self._generate_imei()
        imsi=self._generate_imsi(operator["sim_operator"])
        iccid=self._generate_iccid()
        phone=self._generate_phone(operator["phone_prefix"])
        session_id=self._generate_session_id(imei,iccid)
        persona=AndroidPersona(
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
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[DevicePersona] Generated persona: model=%s operator=%s session=%s (%.1f ms)",
            persona.model,persona.sim_operator_name,persona.session_id[:8],elapsed_ms,
        )
        return persona
    def to_frida_context(self,persona:AndroidPersona)->dict:
        return{
            "manufacturer":persona.manufacturer,
            "model":persona.model,
            "brand":persona.brand,
            "device":persona.device,
            "product":persona.product,
            "android_version":persona.android_version,
            "sdk_int":persona.sdk_int,
            "build_id":persona.build_id,
            "fingerprint":persona.fingerprint,
            "country_iso":persona.country_iso,
            "network_operator":persona.network_operator,
            "network_operator_name":persona.network_operator_name,
            "sim_operator":persona.sim_operator,
            "sim_operator_name":persona.sim_operator_name,
            "imei":persona.imei,
            "imsi":persona.imsi,
            "phone_number":persona.phone_number,
        }
    def to_llm_context(self,persona:AndroidPersona)->str:
        return(
            f"DEVICE ENVIRONMENT(do not deviate from these values):\n"
            f"  Manufacturer:{persona.manufacturer}\n"
            f"  Model:{persona.model}\n"
            f"  Android:{persona.android_version}(API{persona.sdk_int})\n"
            f"  Build:{persona.build_id}\n"
            f"  Country ISO:{persona.country_iso.upper()}\n"
            f"  Operator:{persona.sim_operator_name}({persona.sim_operator})\n"
            f"  IMEI:{persona.imei}\n"
            f"  Phone:{persona.phone_number}\n"
            f"  Session:{persona.session_id}\n"
        )
    def _generate_imei(self)->str:
        tac_prefixes=[
            "35397010",
            "35897010",
            "86819205",
            "35895711",
        ]
        tac=self._rng.choice(tac_prefixes)
        snr="".join(str(self._rng.randint(0,9))for _ in range(6))
        base=tac+snr
        check=self._luhn_check_digit(base)
        return base+str(check)
    def _generate_imsi(self,mcc_mnc:str)->str:
        msin="".join(str(self._rng.randint(0,9))for _ in range(10))
        return mcc_mnc+msin
    def _generate_iccid(self)->str:
        prefix="8991"
        suffix="".join(str(self._rng.randint(0,9))for _ in range(15))
        base=prefix+suffix
        check=self._luhn_check_digit(base)
        return base+str(check)
    def _generate_phone(self,prefix:str)->str:
        digits="".join(str(self._rng.randint(0,9))for _ in range(9))
        return prefix+digits
    @staticmethod
    def _generate_session_id(imei:str,iccid:str)->str:
        raw=f"{imei}:{iccid}:{time.time_ns()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    @staticmethod
    def _luhn_check_digit(number:str)->int:
        digits=[int(d)for d in number]
        for i in range(len(digits)-1,-1,-2):
            digits[i]*=2
            if digits[i]>9:
                digits[i]-=9
        total=sum(digits)
        return(10-(total%10))%10
