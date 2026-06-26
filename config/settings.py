"""
ORACLE-TMF  Â·  config/settings.py
===================================
Single source of truth for every tunable constant in the pipeline.
Rule: No magic numbers anywhere else in the codebase.
      Every threshold, weight, and API key is defined here.
"""
from __future__ import annotations
import os
from dataclasses import dataclass,field
from typing import Final




ANTHROPIC_API_KEY:Final[str]=os.getenv("ANTHROPIC_API_KEY","")

LLM_MODEL:Final[str]="claude-sonnet-4-6"
LLM_TEMPERATURE:Final[float]=0.2
LLM_MAX_TOKENS:Final[int]=4096



APK_MAX_SIZE_BYTES:Final[int]=100*1024*1024
APK_MIN_SIZE_BYTES:Final[int]=1*1024
UPLOAD_READ_CHUNK_BYTES:Final[int]=1024*1024
ZIP_MAX_FILE_COUNT:Final[int]=4096
ZIP_MAX_ENTRY_BYTES:Final[int]=64*1024*1024
ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES:Final[int]=250*1024*1024
ZIP_MAX_COMPRESSION_RATIO:Final[int]=100
XML_MAX_BYTES:Final[int]=2*1024*1024
API_KEY_ENV:Final[str]="ORACLE_TMF_API_KEY"
API_RATE_LIMIT_REQUESTS:Final[int]=5
API_RATE_LIMIT_WINDOW_SECONDS:Final[int]=60
RESULT_CACHE_MAX_ENTRIES:Final[int]=64
RESULT_CACHE_TTL_SECONDS:Final[int]=3600

PACKER_STUB_CLASSES:Final[list[str]]=[
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

DEX_PACKED_SIZE_THRESHOLD:Final[int]=5*1024*1024
WORK_DIR:Final[str]=os.getenv("ORACLE_TMF_WORK_DIR",os.path.join(os.path.expanduser("~"),".oracle_tmf","workspace"))




ANDROGUARD_CACHE_ENABLED:Final[bool]=os.getenv("ORACLE_TMF_ENABLE_ANDROGUARD_CACHE","0")=="1"
ANDROGUARD_CACHE_DIR:Final[str]=os.path.join(WORK_DIR,".androguard_cache")




DEAD_CODE_MIN_OPCODE_COUNT:Final[int]=15

ANDROID_LIFECYCLE_PREFIXES:Final[tuple[str,...]]=(
    "onCreate","onStart","onResume","onPause","onStop","onDestroy",
    "onCreateView","onActivityCreated","onAttach","onDetach",
    "onReceive","onBind","onUnbind","onServiceConnected",
    "onDraw","onMeasure","onLayout","onTouchEvent","onKeyDown",
    "onClick","onItemClick","onOptionsItemSelected",
    "<init>","<clinit>",
)

REFLECTION_INVOKE_SIGNATURES:Final[tuple[str,...]]=(
    "java/lang/reflect/Method;->invoke(",
    "java/lang/Class;->forName(",
    "dalvik/system/DexClassLoader;->loadClass(",
    "java/lang/ClassLoader;->loadClass(",
)







PERMISSION_TO_API_MAP:Final[dict[str,list[str]]]={
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




STRING_HIGH_ENTROPY_THRESHOLD:Final[float]=4.5

STRING_MIN_LENGTH:Final[int]=6

PLACEHOLDER_PATTERNS:Final[dict[str,str]]={
    "todo_marker":r"(?i)(TODO|FIXME|HACK|XXX|PLACEHOLDER|stub)",
    "test_marker":r"(?i)(test|debug|dev|staging|sandbox)",
    "staging_url":r"https?://(dev|test|staging|local|localhost|192\.168|10\.|172\.)",
    "empty_json_schema":r'\{["\']?\w+["\']?\s*:\s*["\']["\']',
    "hardcoded_ipv4":r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b",
    "hardcoded_ipv6":r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "c2_path_pattern":r"/(?:api|v\d+|drop|upload|exfil|collect|cmd|bot|panel)/",
    "onion_address":r"[a-z2-7]{16,56}\.onion",
    "crypto_address":r"\b(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}\b",
}




NETWORK_CLIENT_CLASSES:Final[tuple[str,...]]=(
    "okhttp3/OkHttpClient",
    "retrofit2/Retrofit",
    "java/net/HttpURLConnection",
    "java/net/URL",
    "org/apache/http/client/HttpClient",
    "com/android/volley/Request",
)


NETWORK_TERMINAL_METHODS:Final[tuple[str,...]]=(
    ".execute(",
    ".enqueue(",
    ".getOutputStream(",
    ".connect(",
    ".getInputStream(",
)




SENSITIVE_FRAMEWORK_CLASSES:Final[tuple[str,...]]=(
    "android/accessibilityservice/AccessibilityService",
    "android/app/admin/DeviceAdminReceiver",
    "android/telephony/PhoneStateListener",
    "android/content/BroadcastReceiver",
    "android/inputmethodservice/InputMethodService",
    "android/app/NotificationListenerService",
)

PARTIAL_API_OPCODE_THRESHOLD:Final[int]=10

MALICIOUS_API_SIGNATURES:Final[tuple[str,...]]=(
    "performGlobalAction(",
    "findAccessibilityNodeInfosByViewId(",
    "dispatchGesture(",
    "lockNow(",
    "wipeData(",
    "setPasswordQuality(",
)




MVV_CLIP_LOW:Final[float]=0.5
MVV_CLIP_HIGH:Final[float]=1.5




LLM_MAG_CONTEXT_CHARS:Final[int]=16_000
LLM_RAG_CONTEXT_CHARS:Final[int]=8_000

CHROMA_MITRE_COLLECTION:Final[str]="mitre_attck_mobile"
CHROMA_MALNET_COLLECTION:Final[str]="malnet_phylogenetics"

CHROMA_PERSIST_DIR:Final[str]=os.path.join(
    os.path.dirname(__file__),"..","data","knowledge_base","chroma_db"
)

RAG_TOP_K:Final[int]=5

SBERT_MODEL:Final[str]="all-MiniLM-L6-v2"




BAYESIAN_WEIGHT_P_LLM:Final[float]=0.45
BAYESIAN_WEIGHT_D_ARTIFACT:Final[float]=0.35
BAYESIAN_WEIGHT_H_PRIOR:Final[float]=0.20

ARTIFACT_DENSITY_SCORES:Final[dict[int,float]]={
    1:0.33,
    2:0.66,
    3:1.00,
}

CONFIDENCE_GATE_THRESHOLD:Final[float]=0.72



REPORT_OUTPUT_DIR:Final[str]=os.path.join(WORK_DIR,"reports")

STIX_IDENTITY_NAME:Final[str]="ORACLE-TMF Automated Intelligence Engine"
STIX_IDENTITY_CLASS:Final[str]="system"



DTE_N_ESTIMATORS:Final[int]=300
DTE_MAX_DEPTH:Final[int]=6
DTE_LEARNING_RATE:Final[float]=0.1

DTE_CLASS_REMNANT:Final[str]="REMNANT"
DTE_CLASS_SCAFFOLDING:Final[str]="SCAFFOLDING"
DTE_CLASS_LOGIC_BOMB:Final[str]="LOGIC_BOMB"
DTE_CLASS_ENC_DROPPER:Final[str]="ENCRYPTED_DROPPER"

DTE_FEATURE_TRIGGER_DEPTH:Final[int]=0
DTE_FEATURE_GUARD_ENTROPY:Final[int]=1
DTE_FEATURE_API_SENSITIVITY:Final[int]=2
DTE_FEATURE_GUARD_INDEGREE:Final[int]=3




REFLECT_THRESHOLD_CANDIDATES:Final[list[float]]=[0.2,0.3,0.4,0.5,0.6]
REFLECT_DEFAULT_THRESHOLD:Final[float]=0.4

REFLECT_MAX_CHAIN_DEPTH:Final[int]=5




BANK_TAXONOMY_PATH:Final[str]=os.path.join(
    os.path.dirname(__file__),"..","data","knowledge_base","bank_package_taxonomy.json"
)

BRANDING_COLOR_DISTANCE_THRESHOLD:Final[float]=30.0



LOG_LEVEL:Final[str]=os.getenv("ORACLE_TMF_LOG_LEVEL","INFO")
LOG_FORMAT:Final[str]=(
    "%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s"
)


