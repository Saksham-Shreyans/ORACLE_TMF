"""
ORACLE-TMF  ·  config/stage2_settings.py
==========================================
Stage 2 configuration — ALL tunable constants for:
  • PHANTOM Active Deception Engine
  • Frida Dynamic Bypass Framework
  • NAV (Negative Artifact Vectors)
  • CABAL Cross-App Collusion Forecasting
  • KINSHIP Builder DNA Fingerprinting
  • MIRAGE Adversarial Robustness
  • OUROBOROS-TMF Co-Evolution
  • Synthetic V(N+1) Generation
  • Network Attack Layer (DDoS / ANC)

Rule: No magic numbers anywhere else in the Stage 2 codebase.
      Import these alongside Stage 1 settings where needed.
"""
from __future__ import annotations

import os
from typing import Final

# ─────────────────────────────────────────────────────────────────────────────
# PHANTOM — Active Deception Engine
# ─────────────────────────────────────────────────────────────────────────────

# Ornstein-Uhlenbeck sensor simulation parameters (hand-holding physics)
OU_THETA: Final[float] = 0.7       # Mean-reversion speed
OU_SIGMA: Final[float] = 0.15      # Noise amplitude
OU_DT: Final[float] = 0.016        # Timestep (60 Hz sensor update rate)
OU_GYRO_MU: Final[float] = 0.0     # Gyroscope mean (device at rest)
OU_ACCEL_MU: Final[float] = 9.81   # Accelerometer mean (gravity component)
OU_LIGHT_MU: Final[float] = 250.0  # Ambient light mean (indoor office lux)

# Behavioral biometric keystroke timing (defeats anti-detection timing checks)
KEYSTROKE_MEAN_MS: Final[float] = 150.0  # Mean inter-keystroke delay
KEYSTROKE_STD_MS: Final[float] = 80.0   # Standard deviation
KEYSTROKE_MIN_MS: Final[float] = 30.0   # Hard minimum (physical constraint)
KEYSTROKE_MAX_MS: Final[float] = 2000.0  # Hard maximum (typing pause)

# Phantom device personas (realistic Android build fingerprints)
PHANTOM_DEVICE_PERSONAS: Final[list[dict]] = [
    {
        "manufacturer": "samsung",
        "model": "SM-G991B",
        "brand": "samsung",
        "device": "o1s",
        "product": "o1sxxx",
        "android_version": "14",
        "sdk_int": 34,
        "build_id": "UP1A.231005.007",
        "fingerprint": "samsung/o1sxxx/o1s:14/UP1A.231005.007/G991BXXU7EWJB:user/release-keys",
        "country_iso": "in",  # India — primary target market
    },
    {
        "manufacturer": "xiaomi",
        "model": "2201116TG",
        "brand": "Redmi",
        "device": "topaz",
        "product": "topaz_in",
        "android_version": "13",
        "sdk_int": 33,
        "build_id": "TP1A.220624.014",
        "fingerprint": "Redmi/topaz_in/topaz:13/TP1A.220624.014/V14.0.3.0.TMLINXM:user/release-keys",
        "country_iso": "in",
    },
    {
        "manufacturer": "OnePlus",
        "model": "CPH2423",
        "brand": "OnePlus",
        "device": "OP535FL1",
        "product": "CPH2423",
        "android_version": "13",
        "sdk_int": 33,
        "build_id": "TP1A.220905.001",
        "fingerprint": "OnePlus/CPH2423/OP535FL1:13/TP1A.220905.001/R.202304281536:user/release-keys",
        "country_iso": "in",
    },
]

# Phantom banking SMS templates (format-accurate for SBI, HDFC, ICICI)
PHANTOM_SMS_TEMPLATES: Final[dict[str, list[str]]] = {
    "SBI": [
        "SBI: OTP for login is {otp}. Do not share with anyone. Validity: 10 mins.",
        "Dear SBI customer, your account {account} has been credited with Rs.{amount}. "
        "Avl Bal Rs.{balance}.",
        "Your OTP for SBI YONO is {otp}. Valid for {minutes} minutes. "
        "Do not share with anyone.",
    ],
    "HDFC": [
        "HDFC Bank: {otp} is the OTP for transaction of Rs {amount} on card {card_last4}. "
        "Do not share with anyone.",
        "Thank you for using HDFC Bank Card ending {card_last4} for Rs {amount} at "
        "{merchant} on {date}.",
        "HDFC OTP for {purpose} is {otp}. Valid for {minutes} mins. "
        "Don't share with anyone incl bank officials.",
    ],
    "ICICI": [
        "ICICI Bank: Dear Customer, OTP for transaction is {otp}. "
        "DO NOT SHARE with anyone. ICICI Bank never asks for OTP.",
        "ICICI Bk: A/c {account} debited with INR {amount} on {date}. "
        "Avbl Bal: INR {balance}.",
        "Your One Time Password (OTP) for accessing iMobile Pay is {otp}. "
        "Valid for 10 minutes.",
    ],
    "AXIS": [
        "Axis Bank: OTP is {otp} for debit of Rs. {amount} from Acct XX{account_last4}. "
        "Not for sharing.",
        "Your Axis Bank OTP for {purpose} is {otp}. "
        "Valid for {minutes} minutes only. Axis Bank never asks for OTP.",
    ],
    "KOTAK": [
        "Kotak Mahindra Bank: OTP {otp} for transaction Rs {amount}. "
        "DO NOT SHARE. Valid {minutes} mins.",
        "Kotak: OTP for {purpose} is {otp}. Don't share with anyone. Valid for {minutes} mins.",
    ],
}

# Phantom detonation session limits
PHANTOM_MAX_SESSION_TURNS: Final[int] = 50
PHANTOM_SESSION_TIMEOUT_S: Final[int] = 300  # 5 minutes per detonation session
PHANTOM_PCAP_RETAIN_HOURS: Final[int] = 24   # PCAP retention for validation only

# ─────────────────────────────────────────────────────────────────────────────
# FRIDA BYPASS FRAMEWORK
# ─────────────────────────────────────────────────────────────────────────────

FRIDA_MAX_BYPASS_RETRIES: Final[int] = 5       # Escalating retry limit
FRIDA_RETRY_DELAY_S: Final[float] = 2.0        # Delay between retry attempts
FRIDA_TIMEOUT_S: Final[int] = 120              # Per-bypass timeout
FRIDA_SCRIPTS_DIR: Final[str] = os.path.join(
    os.path.dirname(__file__), "..", "phantom", "frida_bypass", "scripts"
)

# ADB port for Frida connection
FRIDA_ADB_PORT: Final[int] = 5037
FRIDA_SERVER_PORT: Final[int] = 27042

# ─────────────────────────────────────────────────────────────────────────────
# NAV — Negative Artifact Vectors
# ─────────────────────────────────────────────────────────────────────────────

# NAV confidence weight in Stage K formula (additive adjustment)
NAV_CONFIDENCE_WEIGHT: Final[float] = 0.10

# Minimum versions for a rapid-appearance-then-disappearance pattern (MIRAGE detector)
NAV_MIRAGE_MIN_VERSIONS: Final[int] = 3

# Threshold for flagging as NAV-MIRAGE (adversarial poisoning attempt)
NAV_MIRAGE_VELOCITY_THRESHOLD: Final[float] = 0.8

# Minimum artifact count drop to register as a NAV event
NAV_MIN_DROP_COUNT: Final[int] = 2

# ─────────────────────────────────────────────────────────────────────────────
# CABAL — Cross-App Collusion Forecasting
# ─────────────────────────────────────────────────────────────────────────────

CABAL_LLM_COMPAT_THRESHOLD: Final[float] = 0.75  # Collusion compatibility score
CABAL_MAX_HOPS: Final[int] = 3                    # Maximum collusion chain depth
CABAL_MAX_APKS: Final[int] = 50                   # Max APKs for O(n²) tractability

# ─────────────────────────────────────────────────────────────────────────────
# KINSHIP — Builder DNA Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

KINSHIP_NGRAM_SIZES: Final[list[int]] = [2, 3, 4]  # Character n-gram sizes
KINSHIP_SBERT_MODEL: Final[str] = "all-MiniLM-L6-v2"
KINSHIP_SIMILARITY_THRESHOLD: Final[float] = 0.72
KINSHIP_MAX_DEAD_BLOCKS: Final[int] = 500  # Cap for tractable fingerprinting

# ─────────────────────────────────────────────────────────────────────────────
# MIRAGE — Adversarial Robustness Framework
# ─────────────────────────────────────────────────────────────────────────────

# Injection cost estimates per artifact class (relative difficulty)
MIRAGE_INJECTION_COSTS: Final[dict[str, dict]] = {
    "unused_permissions": {
        "bytes_min": 2,
        "bytes_max": 50,
        "bypass_dte": False,
        "bypass_validator": False,
        "hardness": "easy",
    },
    "placeholder_strings": {
        "bytes_min": 10,
        "bytes_max": 200,
        "bypass_dte": False,
        "bypass_validator": False,
        "hardness": "easy",
    },
    "c2_stubs": {
        "bytes_min": 100,
        "bytes_max": 2000,
        "bypass_dte": False,
        "bypass_validator": True,   # Must pass topology validation
        "hardness": "medium",
    },
    "dead_code_scaffolding": {
        "bytes_min": 500,
        "bytes_max": 10000,
        "bypass_dte": True,          # Must pass DTE SCAFFOLDING classification
        "bypass_validator": True,
        "hardness": "hard",
    },
}

# MIRAGE optimization target: minimum-cost poisoning that shifts predicted technique
MIRAGE_MAX_TECHNIQUE_SHIFT_COST: Final[float] = 1.0  # Normalized cost bound

# ─────────────────────────────────────────────────────────────────────────────
# OUROBOROS-TMF — Closed-Loop Adversarial Co-Evolution
# ─────────────────────────────────────────────────────────────────────────────

OUROBOROS_MAX_CYCLES: Final[int] = 10
OUROBOROS_CONVERGENCE_THRESHOLD: Final[float] = 0.05  # Δ accuracy between cycles
OUROBOROS_CRITIC_MODEL: Final[str] = "claude-sonnet-4-6"
OUROBOROS_DEVOLUTION_REMOVAL_RATE: Final[float] = 0.30  # Fraction of artifacts to remove

# ─────────────────────────────────────────────────────────────────────────────
# SYNTHETIC V(N+1) GENERATION
# ─────────────────────────────────────────────────────────────────────────────

SYNTHETIC_APKTOOL_PATH: Final[str] = os.getenv("APKTOOL_PATH", "apktool")
SYNTHETIC_AIRGAP_REQUIRED: Final[bool] = True   # Safety: never outbound in detonation
SYNTHETIC_MAX_APK_SIZE_BYTES: Final[int] = 50 * 1024 * 1024
SYNTHETIC_WORK_DIR: Final[str] = os.path.join(
    os.path.expanduser("~"), ".oracle_tmf", "synthetic_workspace"
)

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK ATTACK LAYER — DDoS / ANC
# ─────────────────────────────────────────────────────────────────────────────

# Amplification factors per attack vector (from research literature)
DDOS_AMPLIFICATION_FACTORS: Final[dict[str, dict]] = {
    "syn_flood": {
        "vector": "SYN Flood",
        "signature": ["socket(PF_INET, SOCK_RAW, IPPROTO_TCP)"],
        "amplification": 1.0,     # Volumetric (no amplification — direct)
        "threat_level": "HIGH",
    },
    "dns_amplification": {
        "vector": "DNS Amplification",
        "signature": ["DNS ANY", "DNS TXT", "spoofed source IP"],
        "amplification": 50.0,    # 28x–73x (midpoint)
        "threat_level": "CRITICAL",
    },
    "ntp_amplification": {
        "vector": "NTP Amplification",
        "signature": ["NTP monlist", "\\x16\\x03\\x01", "0x2a"],
        "amplification": 206.0,   # ~206x
        "threat_level": "CRITICAL",
    },
    "snmp_amplification": {
        "vector": "SNMP Amplification",
        "signature": ["GetBulkRequest", "community string", "'public'"],
        "amplification": 650.0,   # ~650x
        "threat_level": "CRITICAL",
    },
    "http_flood_slowloris": {
        "vector": "HTTP Flood (Slowloris)",
        "signature": ["OkHttpClient", "randomized User-Agent", "1-byte send loop"],
        "amplification": 1.0,
        "threat_level": "HIGH",
    },
    "dga_c2_migration": {
        "vector": "DGA C2 Migration",
        "signature": ["java.util.Random", "Date().getTime()", "TLD array"],
        "amplification": 0.0,     # Evasion — no amplification
        "threat_level": "HIGH",
    },
}

# Raw socket Smali signatures indicating SYN flood capability
ANC_RAW_SOCKET_SIGNATURES: Final[tuple[str, ...]] = (
    "socket(PF_INET, SOCK_RAW, IPPROTO_TCP)",
    "Ljava/net/DatagramSocket;",
    "IPPROTO_TCP",
    "SOCK_RAW",
    "JNI_OnLoad",  # JNI binding indicating native socket
)

# DGA detection: Random seeded from timestamp + TLD arrays
DGA_SEED_SIGNATURES: Final[tuple[str, ...]] = (
    "java/util/Random",
    "java/util/Date",
    "getTime()",
    ".com", ".net", ".org", ".info", ".biz",  # Truncated TLD array indicators
)
