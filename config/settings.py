"""
ORACLE-TMF  ·  config/settings.py
===================================
Single source of truth for every tunable constant in the pipeline.

Rule: No magic numbers anywhere else in the codebase.
      Every threshold, weight, and API key is defined here.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Final


# ─────────────────────────────────────────────────────────────
#  1. API CREDENTIALS
#     Set via environment variables — never hard-code keys.
# ─────────────────────────────────────────────────────────────

ANTHROPIC_API_KEY: Final[str] = os.getenv("ANTHROPIC_API_KEY", "")

# Primary model for all three LLM agents (Decompiler, Hypothesizer, Validator)
LLM_MODEL: Final[str] = "claude-sonnet-4-6"
LLM_TEMPERATURE: Final[float] = 0.2   # Low temp → deterministic reasoning
LLM_MAX_TOKENS: Final[int] = 4096


# ─────────────────────────────────────────────────────────────
#  2. STAGE A  —  APK INGESTION
# ─────────────────────────────────────────────────────────────

APK_MAX_SIZE_BYTES: Final[int] = 100 * 1024 * 1024   # 100 MB hard limit
APK_MIN_SIZE_BYTES: Final[int] = 1 * 1024            # 1 KB (reject empty/stub)

# Known packer stub class names (triggers dynamic Frida extraction path)
PACKER_STUB_CLASSES: Final[list[str]] = [
    "StubApp",
    "Wrapper",
    "com.stub.stub",
    "com.secshell",
    "com.jiagu",
    "com.qihoo",
    "com.bangcle",
    "com.kinggame",
    "com.tencent.mobileqq.pb",
]

# Anti-analysis file size anomalies (classes.dex > threshold = likely packed)
DEX_PACKED_SIZE_THRESHOLD: Final[int] = 5 * 1024 * 1024  # 5 MB

WORK_DIR: Final[str] = "/tmp/oracle_tmf_workspace"


# ─────────────────────────────────────────────────────────────
#  3. STAGE B  —  DEX DISASSEMBLY
# ─────────────────────────────────────────────────────────────

# Cache Androguard analysis objects to disk to avoid redundant processing
ANDROGUARD_CACHE_ENABLED: Final[bool] = True
ANDROGUARD_CACHE_DIR: Final[str] = os.path.join(WORK_DIR, ".androguard_cache")


# ─────────────────────────────────────────────────────────────
#  4. STAGE D  —  DEAD CODE DETECTION
# ─────────────────────────────────────────────────────────────

# Methods with fewer opcodes than this are trivial (getters/setters) — skip
DEAD_CODE_MIN_OPCODE_COUNT: Final[int] = 15

# Standard Android lifecycle method prefixes to exclude from dead code analysis
ANDROID_LIFECYCLE_PREFIXES: Final[tuple[str, ...]] = (
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onCreateView", "onActivityCreated", "onAttach", "onDetach",
    "onReceive", "onBind", "onUnbind", "onServiceConnected",
    "onDraw", "onMeasure", "onLayout", "onTouchEvent", "onKeyDown",
    "onClick", "onItemClick", "onOptionsItemSelected",
    "<init>", "<clinit>",   # Constructors always reachable
)

# Reflection invocation signatures that create synthetic CFG edges
REFLECTION_INVOKE_SIGNATURES: Final[tuple[str, ...]] = (
    "java/lang/reflect/Method;->invoke(",
    "java/lang/Class;->forName(",
    "dalvik/system/DexClassLoader;->loadClass(",
    "java/lang/ClassLoader;->loadClass(",
)


# ─────────────────────────────────────────────────────────────
#  5. STAGE E  —  UNUSED PERMISSION ANALYSIS
# ─────────────────────────────────────────────────────────────

# Axplorer-inspired permission → required API mapping
# Maps android.permission.X to the API class signatures that need it.
# A permission is "unused" if it's declared but none of its APIs appear
# in the reachable CFG.
PERMISSION_TO_API_MAP: Final[dict[str, list[str]]] = {
    "android.permission.SEND_SMS":
        ["android/telephony/SmsManager;->sendTextMessage(",
         "android/telephony/SmsManager;->sendMultipartTextMessage("],
    "android.permission.RECEIVE_SMS":
        ["android/content/BroadcastReceiver;->onReceive(",
         "android.provider.Telephony.SMS_RECEIVED"],
    "android.permission.READ_CONTACTS":
        ["android/provider/ContactsContract",
         "android/database/Cursor;->getString("],
    "android.permission.CAMERA":
        ["android/hardware/Camera;->open(",
         "android/hardware/camera2/CameraManager;->openCamera("],
    "android.permission.RECORD_AUDIO":
        ["android/media/MediaRecorder;->setAudioSource(",
         "android/media/AudioRecord;->startRecording("],
    "android.permission.ACCESS_FINE_LOCATION":
        ["android/location/LocationManager;->requestLocationUpdates(",
         "android/location/LocationManager;->getLastKnownLocation("],
    "android.permission.READ_CALL_LOG":
        ["android/provider/CallLog$Calls",
         "android/database/Cursor"],
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        ["android/accessibilityservice/AccessibilityService",
         "android/view/accessibility/AccessibilityEvent"],
    "android.permission.BIND_DEVICE_ADMIN":
        ["android/app/admin/DevicePolicyManager",
         "android/app/admin/DeviceAdminReceiver"],
    "android.permission.SYSTEM_ALERT_WINDOW":
        ["android/view/WindowManager$LayoutParams",
         "android/view/WindowManager;->addView("],
    "android.permission.READ_PHONE_STATE":
        ["android/telephony/TelephonyManager;->getDeviceId(",
         "android/telephony/TelephonyManager;->getImei("],
    "android.permission.PROCESS_OUTGOING_CALLS":
        ["android.intent.action.NEW_OUTGOING_CALL",
         "android/telephony/TelephonyManager"],
}


# ─────────────────────────────────────────────────────────────
#  6. STAGE F  —  STRING MINING
# ─────────────────────────────────────────────────────────────

# Shannon entropy threshold — strings above this are high-entropy (suspicious)
STRING_HIGH_ENTROPY_THRESHOLD: Final[float] = 4.5

# Minimum string length to analyse (skip single chars and very short tokens)
STRING_MIN_LENGTH: Final[int] = 6

# Regex patterns for developmental/staging markers
PLACEHOLDER_PATTERNS: Final[dict[str, str]] = {
    "todo_marker":          r"(?i)(TODO|FIXME|HACK|XXX|PLACEHOLDER|stub)",
    "test_marker":          r"(?i)(test|debug|dev|staging|sandbox)",
    "staging_url":          r"https?://(dev|test|staging|local|localhost|192\.168|10\.|172\.)",
    "empty_json_schema":    r'\{["\']?\w+["\']?\s*:\s*["\']["\']',
    "hardcoded_ipv4":       r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b",
    "hardcoded_ipv6":       r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "c2_path_pattern":      r"/(?:api|v\d+|drop|upload|exfil|collect|cmd|bot|panel)/",
    "onion_address":        r"[a-z2-7]{16,56}\.onion",
    "crypto_address":       r"\b(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}\b",
}


# ─────────────────────────────────────────────────────────────
#  7. STAGE G  —  C2 STUB DETECTION
# ─────────────────────────────────────────────────────────────

# HTTP client classes indicating network scaffolding
NETWORK_CLIENT_CLASSES: Final[tuple[str, ...]] = (
    "okhttp3/OkHttpClient",
    "retrofit2/Retrofit",
    "java/net/HttpURLConnection",
    "java/net/URL",
    "org/apache/http/client/HttpClient",
    "com/android/volley/Request",
)

# Terminal execution methods — if these are absent in the call chain,
# the network client is a C2 stub (not yet executed)
NETWORK_TERMINAL_METHODS: Final[tuple[str, ...]] = (
    ".execute(",
    ".enqueue(",
    ".getOutputStream(",
    ".connect(",
    ".getInputStream(",
)


# ─────────────────────────────────────────────────────────────
#  8. STAGE H  —  PARTIAL API DETECTION
# ─────────────────────────────────────────────────────────────

# Sensitive Android framework interfaces — subclassing these is high-risk
SENSITIVE_FRAMEWORK_CLASSES: Final[tuple[str, ...]] = (
    "android/accessibilityservice/AccessibilityService",
    "android/app/admin/DeviceAdminReceiver",
    "android/telephony/PhoneStateListener",
    "android/content/BroadcastReceiver",
    "android/inputmethodservice/InputMethodService",
    "android/app/NotificationListenerService",
)

# An overriding method with fewer opcodes than this is a "partial scaffold"
PARTIAL_API_OPCODE_THRESHOLD: Final[int] = 10

# Malicious API signatures — if these appear, the method is NOT partial (it's active)
MALICIOUS_API_SIGNATURES: Final[tuple[str, ...]] = (
    "performGlobalAction(",
    "findAccessibilityNodeInfosByViewId(",
    "dispatchGesture(",
    "lockNow(",
    "wipeData(",
    "setPasswordQuality(",
)


# ─────────────────────────────────────────────────────────────
#  9. STAGE I  —  VERSION DIFF ENGINE
# ─────────────────────────────────────────────────────────────

# MVV (Mutation Velocity Vector) normalization clip range
MVV_CLIP_LOW: Final[float] = 0.5
MVV_CLIP_HIGH: Final[float] = 1.5


# ─────────────────────────────────────────────────────────────
# 10. STAGE J  —  LLM REASONING ENGINE
# ─────────────────────────────────────────────────────────────

# Context window hard limits per agent call
LLM_MAG_CONTEXT_CHARS: Final[int] = 16_000   # MAG JSON sent to agents
LLM_RAG_CONTEXT_CHARS: Final[int] = 8_000    # RAG retrieval context

# ChromaDB collection names for RAG knowledge base
CHROMA_MITRE_COLLECTION: Final[str] = "mitre_attck_mobile"
CHROMA_MALNET_COLLECTION: Final[str] = "malnet_phylogenetics"

# Path to the persisted ChromaDB vector store
CHROMA_PERSIST_DIR: Final[str] = os.path.join(
    os.path.dirname(__file__), "..", "data", "knowledge_base", "chroma_db"
)

# Number of RAG documents to retrieve per agent query
RAG_TOP_K: Final[int] = 5

# Sentence-BERT model for semantic similarity & TMF-REFLECT RDG resolution
SBERT_MODEL: Final[str] = "all-MiniLM-L6-v2"


# ─────────────────────────────────────────────────────────────
# 11. STAGE K  —  BAYESIAN CONFIDENCE SCORING
# ─────────────────────────────────────────────────────────────

# Bayesian ensemble weights  (must sum to 1.0)
BAYESIAN_WEIGHT_P_LLM: Final[float] = 0.45      # LLM Skeptical Validator output
BAYESIAN_WEIGHT_D_ARTIFACT: Final[float] = 0.35  # Artifact density × MVV
BAYESIAN_WEIGHT_H_PRIOR: Final[float] = 0.20     # Historical family prior

# Artifact density scoring: convergence of multiple artifact types on same capability
ARTIFACT_DENSITY_SCORES: Final[dict[int, float]] = {
    1: 0.33,   # Single artifact type pointing to a capability
    2: 0.66,   # Two independent artifact types converge
    3: 1.00,   # Three or more types converge → maximum density
}

# Gating threshold: forecasts are suppressed if confidence ≤ this value
CONFIDENCE_GATE_THRESHOLD: Final[float] = 0.72


# ─────────────────────────────────────────────────────────────
# 12. STAGE L  —  REPORT SYNTHESIZER
# ─────────────────────────────────────────────────────────────

REPORT_OUTPUT_DIR: Final[str] = os.path.join(WORK_DIR, "reports")

# STIX 2.1 identity for ORACLE-TMF threat actor bundle
STIX_IDENTITY_NAME: Final[str] = "ORACLE-TMF Automated Intelligence Engine"
STIX_IDENTITY_CLASS: Final[str] = "system"


# ─────────────────────────────────────────────────────────────
# 13. DTE ENGINE  —  DORMANCY TAXONOMY
# ─────────────────────────────────────────────────────────────

DTE_N_ESTIMATORS: Final[int] = 300          # XGBoost n_estimators
DTE_MAX_DEPTH: Final[int] = 6               # XGBoost max_depth
DTE_LEARNING_RATE: Final[float] = 0.1       # XGBoost learning_rate

# DTE class labels
DTE_CLASS_REMNANT: Final[str] = "REMNANT"             # Benign SDK boilerplate
DTE_CLASS_SCAFFOLDING: Final[str] = "SCAFFOLDING"     # Future capability stub → Stage J
DTE_CLASS_LOGIC_BOMB: Final[str] = "LOGIC_BOMB"       # Conditional dormant payload
DTE_CLASS_ENC_DROPPER: Final[str] = "ENCRYPTED_DROPPER"  # Dynamic loader → Frida

# Feature vector indices in DTE input
DTE_FEATURE_TRIGGER_DEPTH: Final[int] = 0
DTE_FEATURE_GUARD_ENTROPY: Final[int] = 1
DTE_FEATURE_API_SENSITIVITY: Final[int] = 2
DTE_FEATURE_GUARD_INDEGREE: Final[int] = 3


# ─────────────────────────────────────────────────────────────
# 14. TMF-REFLECT  —  REFLECTION-AWARE CFG
# ─────────────────────────────────────────────────────────────

# Candidate RDG edge thresholds to evaluate during ablation
REFLECT_THRESHOLD_CANDIDATES: Final[list[float]] = [0.2, 0.3, 0.4, 0.5, 0.6]
REFLECT_DEFAULT_THRESHOLD: Final[float] = 0.4   # Best performing threshold

# Maximum reflection chain resolution depth (prevents infinite loops)
REFLECT_MAX_CHAIN_DEPTH: Final[int] = 5


# ─────────────────────────────────────────────────────────────
# 15. TARGETING INTELLIGENCE MODULE
# ─────────────────────────────────────────────────────────────

# Path to the bank package taxonomy JSON (200+ entries, curated manually)
BANK_TAXONOMY_PATH: Final[str] = os.path.join(
    os.path.dirname(__file__), "..", "data", "knowledge_base", "bank_package_taxonomy.json"
)

# Minimum logo colour distance for branding identification (overlay asset analysis)
BRANDING_COLOR_DISTANCE_THRESHOLD: Final[float] = 30.0


# ─────────────────────────────────────────────────────────────
# 16. LOGGING
# ─────────────────────────────────────────────────────────────

LOG_LEVEL: Final[str] = os.getenv("ORACLE_TMF_LOG_LEVEL", "INFO")
LOG_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s"
)
