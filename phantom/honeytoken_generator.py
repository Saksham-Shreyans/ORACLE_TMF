from __future__ import annotations
import hashlib
import logging
import math
import random
import string
import time
from dataclasses import dataclass,field
from typing import Optional
from config.stage2_settings import PHANTOM_SMS_TEMPLATES
from phantom.device_persona import AndroidPersona
logger=logging.getLogger(__name__)
_HONEYTOKEN_MARKER="ORACLE_PHA"
@dataclass
class BankAccount:
    bank_name:str=""
    ifsc_code:str=""
    account_number:str=""
    account_holder:str=""
    balance_inr:float=0.0
    upi_vpa:str=""
    upi_mpin:str=""
    net_banking_id:str=""
    net_banking_pass:str=""
    session_token:str=""
@dataclass
class PaymentCard:
    card_number:str=""
    card_holder:str=""
    expiry_month:int=0
    expiry_year:int=0
    cvv:str=""
    card_type:str=""
    bank_name:str=""
    last_four:str=""
@dataclass
class PhantomHoneytokenBundle:
    session_id:str=""
    persona_model:str=""
    created_at:float=0.0
    primary_account:BankAccount=field(default_factory=BankAccount)
    secondary_account:BankAccount=field(default_factory=BankAccount)
    primary_card:PaymentCard=field(default_factory=PaymentCard)
    synthetic_sms:list[dict]=field(default_factory=list)
    active_otp:str=""
    otp_issued_at:float=0.0
    otp_target_bank:str=""
    capture_proxy_url:str="http://127.0.0.1:8899/capture"
class HoneytokenGenerator:
    _HOLDER_NAMES:list[str]=[
        "Vikram Testpal",
        "Ananya Phantom",
        "Rahul Honeysim",
        "Priya Decoynet",
        "Arjun Trapuser",
        "Deepa Testnode",
    ]
    _BANK_IFSC_PREFIXES:dict[str,str]={
        "SBI":"SBIN",
        "HDFC":"HDFC",
        "ICICI":"ICIC",
        "AXIS":"UTIB",
        "KOTAK":"KKBK",
        "PNB":"PUNB",
        "BOI":"BKID",
    }
    _CARD_BINS:dict[str,list[str]]={
        "VISA":["4111","4012","4532"],
        "MASTERCARD":["5100","5200","5454"],
        "RUPAY":["6069","6070","6521"],
    }
    def __init__(self,seed:Optional[int]=None)->None:
        self._rng=random.Random(seed)
        logger.info("[HoneytokenGenerator] Initialised (seed=%s)",seed)
    def generate(self,persona:AndroidPersona)->PhantomHoneytokenBundle:
        t0=time.perf_counter()
        session_id=persona.session_id
        holder=self._rng.choice(self._HOLDER_NAMES)
        bank_names=self._rng.sample(list(self._BANK_IFSC_PREFIXES.keys()),2)
        primary_account=self._generate_account(holder,bank_names[0],session_id)
        secondary_account=self._generate_account(holder,bank_names[1],session_id+"2")
        primary_card=self._generate_card(holder,bank_names[0])
        sms_history=self._generate_sms_history(
            primary_account,secondary_account,n_messages=15
        )
        active_otp=self._generate_otp()
        bundle=PhantomHoneytokenBundle(
            session_id=session_id,
            persona_model=persona.model,
            created_at=time.time(),
            primary_account=primary_account,
            secondary_account=secondary_account,
            primary_card=primary_card,
            synthetic_sms=sms_history,
            active_otp=active_otp,
            otp_issued_at=time.time(),
            otp_target_bank=bank_names[0],
        )
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[HoneytokenGenerator] Bundle generated: session=%s banks=%s "
            "sms_count=%d (%.1f ms)",
            session_id[:8],bank_names,len(sms_history),elapsed_ms,
        )
        return bundle
    def refresh_otp(
        self,
        bundle:PhantomHoneytokenBundle,
        bank:str="",
        amount:float=0.0,
        purpose:str="login",
    )->str:
        otp=self._generate_otp()
        bundle.active_otp=otp
        bundle.otp_issued_at=time.time()
        bundle.otp_target_bank=bank or bundle.otp_target_bank
        sms=self._format_otp_sms(bank or bundle.otp_target_bank,otp,amount,purpose)
        bundle.synthetic_sms.insert(0,sms)
        logger.info("[HoneytokenGenerator] OTP refreshed: %s for %s",otp,bank)
        return otp
    def format_as_android_sms_db(self,bundle:PhantomHoneytokenBundle)->list[dict]:
        rows=[]
        for i,sms in enumerate(bundle.synthetic_sms):
            age_s=(i+1)*self._rng.uniform(300,7200)
            ts_ms=int((time.time()-age_s)*1000)
            rows.append({
                "_id":1000+i,
                "thread_id":self._rng.randint(100,200),
                "address":sms.get("sender","BANK"),
                "date":ts_ms,
                "date_sent":ts_ms-self._rng.randint(50,500),
                "body":sms.get("body",""),
                "read":1,
                "type":1,
                "status":-1,
                "locked":0,
                "error_code":0,
            })
        return rows
    def _generate_account(
        self,
        holder:str,
        bank:str,
        session_salt:str,
    )->BankAccount:
        ifsc_prefix=self._BANK_IFSC_PREFIXES.get(bank,"SBIN")
        branch_code="0"+"".join(str(self._rng.randint(0,9))for _ in range(6))
        ifsc=f"{ifsc_prefix}{branch_code}"
        account_num=(
            str(self._rng.randint(10,99))
            +"".join(str(self._rng.randint(0,9))for _ in range(12))
        )
        upi_vpa=(
            f"{_HONEYTOKEN_MARKER.lower()}"
            f"{self._rng.randint(1000,9999)}"
            f"@{bank.lower()}"
        )
        balance=round(self._rng.uniform(5000.0,150000.0),2)
        mpin="".join(str(self._rng.randint(0,9))for _ in range(6))
        net_id=f"{_HONEYTOKEN_MARKER}{self._rng.randint(10000000,99999999)}"
        net_pass=self._rng.choices(string.ascii_letters+string.digits,k=12)
        net_pass_str="PHA@"+"".join(net_pass)
        return BankAccount(
            bank_name=bank,
            ifsc_code=ifsc,
            account_number=account_num,
            account_holder=holder,
            balance_inr=balance,
            upi_vpa=upi_vpa,
            upi_mpin=mpin,
            net_banking_id=net_id,
            net_banking_pass=net_pass_str,
            session_token=hashlib.sha256(
                f"{session_salt}{account_num}".encode()
            ).hexdigest()[:32],
        )
    def _generate_card(self,holder:str,bank:str)->PaymentCard:
        card_type=self._rng.choice(["VISA","MASTERCARD","RUPAY"])
        bin_prefix=self._rng.choice(self._CARD_BINS[card_type])
        partial=bin_prefix+"".join(
            str(self._rng.randint(0,9))for _ in range(11)
        )
        check=self._luhn_check_digit(partial)
        card_num=partial+str(check)
        expiry_month=self._rng.randint(1,12)
        expiry_year=2026+self._rng.randint(0,4)
        cvv="".join(str(self._rng.randint(0,9))for _ in range(3))
        return PaymentCard(
            card_number=card_num,
            card_holder=holder,
            expiry_month=expiry_month,
            expiry_year=expiry_year,
            cvv=cvv,
            card_type=card_type,
            bank_name=bank,
            last_four=card_num[-4:],
        )
    def _generate_sms_history(
        self,
        primary:BankAccount,
        secondary:BankAccount,
        n_messages:int=15,
    )->list[dict]:
        smses:list[dict]=[]
        banks=[primary.bank_name,secondary.bank_name]
        for i in range(n_messages):
            bank=self._rng.choice(banks)
            account=primary if bank==primary.bank_name else secondary
            templates=PHANTOM_SMS_TEMPLATES.get(bank,PHANTOM_SMS_TEMPLATES["SBI"])
            template=self._rng.choice(templates)
            amount=round(self._rng.uniform(100.0,25000.0),2)
            otp=self._generate_otp()
            body=template.format(
                otp=otp,
                account=account.account_number[-4:],
                account_last4=account.account_number[-4:],
                amount=f"{amount:,.2f}",
                balance=f"{account.balance_inr:,.2f}",
                card_last4=f"XXXX{self._rng.randint(1000,9999)}",
                merchant=self._rng.choice(
                    ["Amazon","BigBasket","Swiggy","Zepto","Flipkart"]
                ),
                date=f"{self._rng.randint(1,28):02d}/{self._rng.randint(1,12):02d}/2026",
                minutes=self._rng.choice([3,5,10,15]),
                purpose=self._rng.choice(["login","transaction","fund transfer","OTP"]),
            )
            smses.append({
                "sender":f"VM-{bank[:3].upper()}BNK",
                "body":body,
                "bank":bank,
            })
        return smses
    def _format_otp_sms(
        self,bank:str,otp:str,amount:float,purpose:str
    )->dict:
        templates=PHANTOM_SMS_TEMPLATES.get(bank,PHANTOM_SMS_TEMPLATES["SBI"])
        template=self._rng.choice(
            [t for t in templates if "{otp}" in t]or templates
        )
        body=template.format(
            otp=otp,
            amount=f"{amount:,.2f}" if amount else "0.00",
            account="XX1234",
            account_last4="1234",
            card_last4="5678",
            merchant="ORACLE_TEST",
            date="27/06/2026",
            minutes=10,
            purpose=purpose,
            balance="50,000.00",
        )
        return{"sender":f"VM-{bank[:3].upper()}BNK","body":body,"bank":bank}
    def _generate_otp(self)->str:
        return "".join(str(self._rng.randint(0,9))for _ in range(6))
    @staticmethod
    def _luhn_check_digit(number:str)->int:
        digits=[int(d)for d in number]
        for i in range(len(digits)-2,-1,-2):
            digits[i]*=2
            if digits[i]>9:
                digits[i]-=9
        total=sum(digits)
        return(10-(total%10))%10
