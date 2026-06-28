from __future__ import annotations
import os
from typing import Final
OU_THETA:Final[float]=0.7
OU_SIGMA:Final[float]=0.15
OU_DT:Final[float]=0.016
OU_GYRO_MU:Final[float]=0.0
OU_ACCEL_MU:Final[float]=9.81
OU_LIGHT_MU:Final[float]=250.0
KEYSTROKE_MEAN_MS:Final[float]=150.0
KEYSTROKE_STD_MS:Final[float]=80.0
KEYSTROKE_MIN_MS:Final[float]=30.0
KEYSTROKE_MAX_MS:Final[float]=2000.0
PHANTOM_DEVICE_PERSONAS:Final[list[dict]]=[
    {
        "manufacturer":"samsung",
        "model":"SM-G991B",
        "brand":"samsung",
        "device":"o1s",
        "product":"o1sxxx",
        "android_version":"14",
        "sdk_int":34,
        "build_id":"UP1A.231005.007",
        "fingerprint":"samsung/o1sxxx/o1s:14/UP1A.231005.007/G991BXXU7EWJB:user/release-keys",
        "country_iso":"in",
    },
    {
        "manufacturer":"xiaomi",
        "model":"2201116TG",
        "brand":"Redmi",
        "device":"topaz",
        "product":"topaz_in",
        "android_version":"13",
        "sdk_int":33,
        "build_id":"TP1A.220624.014",
        "fingerprint":"Redmi/topaz_in/topaz:13/TP1A.220624.014/V14.0.3.0.TMLINXM:user/release-keys",
        "country_iso":"in",
    },
    {
        "manufacturer":"OnePlus",
        "model":"CPH2423",
        "brand":"OnePlus",
        "device":"OP535FL1",
        "product":"CPH2423",
        "android_version":"13",
        "sdk_int":33,
        "build_id":"TP1A.220905.001",
        "fingerprint":"OnePlus/CPH2423/OP535FL1:13/TP1A.220905.001/R.202304281536:user/release-keys",
        "country_iso":"in",
    },
]
PHANTOM_SMS_TEMPLATES:Final[dict[str,list[str]]]={
    "SBI":[
        "SBI: OTP for login is {otp}. Do not share with anyone. Validity: 10 mins.",
        "Dear SBI customer, your account {account} has been credited with Rs.{amount}. "
        "Avl Bal Rs.{balance}.",
        "Your OTP for SBI YONO is {otp}. Valid for {minutes} minutes. "
        "Do not share with anyone.",
    ],
    "HDFC":[
        "HDFC Bank: {otp} is the OTP for transaction of Rs {amount} on card {card_last4}. "
        "Do not share with anyone.",
        "Thank you for using HDFC Bank Card ending {card_last4} for Rs {amount} at "
        "{merchant} on {date}.",
        "HDFC OTP for {purpose} is {otp}. Valid for {minutes} mins. "
        "Don't share with anyone incl bank officials.",
    ],
    "ICICI":[
        "ICICI Bank: Dear Customer, OTP for transaction is {otp}. "
        "DO NOT SHARE with anyone. ICICI Bank never asks for OTP.",
        "ICICI Bk: A/c {account} debited with INR {amount} on {date}. "
        "Avbl Bal: INR {balance}.",
        "Your One Time Password (OTP) for accessing iMobile Pay is {otp}. "
        "Valid for 10 minutes.",
    ],
    "AXIS":[
        "Axis Bank: OTP is {otp} for debit of Rs. {amount} from Acct XX{account_last4}. "
        "Not for sharing.",
        "Your Axis Bank OTP for {purpose} is {otp}. "
        "Valid for {minutes} minutes only. Axis Bank never asks for OTP.",
    ],
    "KOTAK":[
        "Kotak Mahindra Bank: OTP {otp} for transaction Rs {amount}. "
        "DO NOT SHARE. Valid {minutes} mins.",
        "Kotak: OTP for {purpose} is {otp}. Don't share with anyone. Valid for {minutes} mins.",
    ],
}
PHANTOM_MAX_SESSION_TURNS:Final[int]=50
PHANTOM_SESSION_TIMEOUT_S:Final[int]=300
PHANTOM_PCAP_RETAIN_HOURS:Final[int]=24
FRIDA_MAX_BYPASS_RETRIES:Final[int]=5
FRIDA_RETRY_DELAY_S:Final[float]=2.0
FRIDA_TIMEOUT_S:Final[int]=120
FRIDA_SCRIPTS_DIR:Final[str]=os.path.join(
    os.path.dirname(__file__),"..","phantom","frida_bypass","scripts"
)
FRIDA_ADB_PORT:Final[int]=5037
FRIDA_SERVER_PORT:Final[int]=27042
NAV_CONFIDENCE_WEIGHT:Final[float]=0.10
NAV_MIRAGE_MIN_VERSIONS:Final[int]=3
NAV_MIRAGE_VELOCITY_THRESHOLD:Final[float]=0.8
NAV_MIN_DROP_COUNT:Final[int]=2
CABAL_LLM_COMPAT_THRESHOLD:Final[float]=0.75
CABAL_MAX_HOPS:Final[int]=3
CABAL_MAX_APKS:Final[int]=50
KINSHIP_NGRAM_SIZES:Final[list[int]]=[2,3,4]
KINSHIP_SBERT_MODEL:Final[str]="all-MiniLM-L6-v2"
KINSHIP_SIMILARITY_THRESHOLD:Final[float]=0.72
KINSHIP_MAX_DEAD_BLOCKS:Final[int]=500
MIRAGE_INJECTION_COSTS:Final[dict[str,dict]]={
    "unused_permissions":{
        "bytes_min":2,
        "bytes_max":50,
        "bypass_dte":False,
        "bypass_validator":False,
        "hardness":"easy",
    },
    "placeholder_strings":{
        "bytes_min":10,
        "bytes_max":200,
        "bypass_dte":False,
        "bypass_validator":False,
        "hardness":"easy",
    },
    "c2_stubs":{
        "bytes_min":100,
        "bytes_max":2000,
        "bypass_dte":False,
        "bypass_validator":True,
        "hardness":"medium",
    },
    "dead_code_scaffolding":{
        "bytes_min":500,
        "bytes_max":10000,
        "bypass_dte":True,
        "bypass_validator":True,
        "hardness":"hard",
    },
}
MIRAGE_MAX_TECHNIQUE_SHIFT_COST:Final[float]=1.0
OUROBOROS_MAX_CYCLES:Final[int]=10
OUROBOROS_CONVERGENCE_THRESHOLD:Final[float]=0.05
OUROBOROS_CRITIC_MODEL:Final[str]="claude-sonnet-4-6"
OUROBOROS_DEVOLUTION_REMOVAL_RATE:Final[float]=0.30
SYNTHETIC_APKTOOL_PATH:Final[str]=os.getenv("APKTOOL_PATH","apktool")
SYNTHETIC_AIRGAP_REQUIRED:Final[bool]=True
SYNTHETIC_MAX_APK_SIZE_BYTES:Final[int]=50*1024*1024
SYNTHETIC_WORK_DIR:Final[str]=os.path.join(
    os.path.expanduser("~"),".oracle_tmf","synthetic_workspace"
)
DDOS_AMPLIFICATION_FACTORS:Final[dict[str,dict]]={
    "syn_flood":{
        "vector":"SYN Flood",
        "signature":["socket(PF_INET, SOCK_RAW, IPPROTO_TCP)"],
        "amplification":1.0,
        "threat_level":"HIGH",
    },
    "dns_amplification":{
        "vector":"DNS Amplification",
        "signature":["DNS ANY","DNS TXT","spoofed source IP"],
        "amplification":50.0,
        "threat_level":"CRITICAL",
    },
    "ntp_amplification":{
        "vector":"NTP Amplification",
        "signature":["NTP monlist","\\x16\\x03\\x01","0x2a"],
        "amplification":206.0,
        "threat_level":"CRITICAL",
    },
    "snmp_amplification":{
        "vector":"SNMP Amplification",
        "signature":["GetBulkRequest","community string","'public'"],
        "amplification":650.0,
        "threat_level":"CRITICAL",
    },
    "http_flood_slowloris":{
        "vector":"HTTP Flood (Slowloris)",
        "signature":["OkHttpClient","randomized User-Agent","1-byte send loop"],
        "amplification":1.0,
        "threat_level":"HIGH",
    },
    "dga_c2_migration":{
        "vector":"DGA C2 Migration",
        "signature":["java.util.Random","Date().getTime()","TLD array"],
        "amplification":0.0,
        "threat_level":"HIGH",
    },
}
ANC_RAW_SOCKET_SIGNATURES:Final[tuple[str,...]]=(
    "socket(PF_INET, SOCK_RAW, IPPROTO_TCP)",
    "Ljava/net/DatagramSocket;",
    "IPPROTO_TCP",
    "SOCK_RAW",
    "JNI_OnLoad",
)
DGA_SEED_SIGNATURES:Final[tuple[str,...]]=(
    "java/util/Random",
    "java/util/Date",
    "getTime()",
    ".com",".net",".org",".info",".biz",
)
