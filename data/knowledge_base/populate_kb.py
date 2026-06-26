"""
ORACLE-TMF  ·  data/knowledge_base/populate_kb.py
====================================================
Automated RAG Knowledge Base Population Script
Populates the ChromaDB vector store with:
    1. MITRE ATT&CK for Mobile technique descriptions
    2. Curated malware family phylogenetic evolution histories
    Usage:
        python -m data.knowledge_base.populate_kb
        # or
        python data/knowledge_base/populate_kb.py
        This script is idempotent — safe to re-run. Existing entries are upserted.
        """
from __future__ import annotations
import json
import logging
import os
import sys
from pathlib import Path
PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
logger = logging.getLogger(__name__)
from config.settings import (
    CHROMA_MALNET_COLLECTION,
    CHROMA_MITRE_COLLECTION,
    CHROMA_PERSIST_DIR,
)
FAMILIES_JSON = Path(__file__).parent/"malware_families.json"


def populate_knowledge_base() -> dict:
    """
    Populate the ChromaDB vector store with MITRE + MalNet knowledge.
    Returns a dict with counts:
        {"mitre_techniques": int, "malnet_families": int, "errors": list}
        """
    try:
        import chromadb
        from sentence_transformers import SentenceTransformer
    except ImportError as e:
        logger.error(
            "Required packages not installed. Run:\n"
            "  pip install chromadb sentence-transformers\n"
            "Error: %s", e,
        )
        return {"mitre_techniques": 0, "malnet_families": 0, "errors": [str(e)]}
    results = {"mitre_techniques": 0, "malnet_families": 0, "errors": []}

    logger.info(
        "[KB] Loading sentence-transformer model (all-MiniLM-L6-v2)...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    logger.info(
        "[KB] Populating MITRE ATT&CK Mobile collection...")
    mitre_collection = client.get_or_create_collection(
        CHROMA_MITRE_COLLECTION)
    mitre_count = _populate_mitre(mitre_collection, model)
    results["mitre_techniques"] = mitre_count
    logger.info(
        "[KB] MITRE collection: %d techniques ingested", mitre_count)
    logger.info(
        "[KB] Populating MalNet phylogenetics collection...")
    malnet_collection = client.get_or_create_collection(
        CHROMA_MALNET_COLLECTION)
    malnet_count = _populate_malnet(malnet_collection, model)
    results["malnet_families"] = malnet_count
    logger.info(
        "[KB] MalNet collection: %d families ingested", malnet_count)
    logger.info(
        "[KB] Knowledge base population complete: "
        "%d MITRE techniques, %d malware families",
        mitre_count, malnet_count,
    )
    return results

    def _populate_mitre(collection, model) -> int:
        """
        Populate the MITRE ATT&CK for Mobile technique collection.
        Uses the curated technique descriptions from malware_families.json
        plus extended descriptions for comprehensive coverage.
        """
        families_data = _load_families_json()
        technique_descs = families_data.get("mitre_technique_descriptions", {})
        extended_techniques = {
            "T1660": {
                "name": "Phishing",
                "tactic": "Initial Access",
                "description": (
                    "Adversaries may send phishing messages via SMS (smishing) to "
                    "gain access to victim mobile devices. Messages typically contain "
                    "links to malicious APK downloads disguised as legitimate apps."
                ),
            },
            "T1474": {
                "name": "Supply Chain Compromise",
                "tactic": "Initial Access",
                "description": (
                    "Compromise of the mobile supply chain through backdoored apps "
                    "on official stores, modified SDKs, or compromised build systems."
                ),
            },
            "T1575": {
                "name": "Native API",
                "tactic": "Execution",
                "description": (
                    "Use of native Android APIs through JNI/NDK to execute code, "
                    "often to bypass Java-level security monitoring."
                ),
            },
            "T1398": {
                "name": "Boot or Logon Initialization Scripts",
                "tactic": "Persistence",
                "description": (
                    "Register broadcast receivers for BOOT_COMPLETED to automatically "
                    "restart malware after device reboot. Common in banking trojans "
                    "to maintain persistent overlay monitoring."
                ),
            },
            "T1624.001": {
                "name": "Event Triggered Execution: Broadcast Receivers",
                "tactic": "Persistence",
                "description": (
                    "Register for system broadcasts (PACKAGE_ADDED, SMS_RECEIVED, "
                    "CONNECTIVITY_CHANGE) to trigger malicious code execution on "
                    "specific system events without user interaction."
                ),
            },
            "T1406": {
                "name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "description": (
                    "Employ code obfuscation, string encryption, packing, or native "
                    "code to hinder static analysis of malicious functionality."
                ),
            },
            "T1418.001": {
                "name": "Software Discovery: Security Software Discovery",
                "tactic": "Defense Evasion",
                "description": (
                    "Enumerate installed security apps to determine if AV, banking "
                    "protection, or anti-fraud software is present before activating "
                    "malicious payloads."
                ),
            },
            "T1417.002": {
                "name": "Input Capture: GUI Input Capture",
                "tactic": "Credential Access",
                "description": (
                    "Display overlay windows that mimic legitimate banking app login "
                    "screens to capture user credentials. The overlay is triggered "
                    "when the target banking app is detected in the foreground via "
                    "accessibility service monitoring."
                ),
            },
            "T1411": {
                "name": "Input Injection",
                "tactic": "Credential Access",
                "description": (
                    "Use accessibility service APIs to programmatically inject taps, "
                    "swipes, and text input into other applications. Enables automated "
                    "fund transfer (ATS) without user awareness."
                ),
            },
            "T1429": {
                "name": "Audio Capture",
                "tactic": "Collection",
                "description": (
                    "Record ambient audio via device microphone. Used for surveillance "
                    "and capturing voice-based authentication."
                ),
            },
            "T1512": {
                "name": "Video Capture",
                "tactic": "Collection",
                "description": (
                    "Access camera or capture screen contents. Screen recording "
                    "enables real-time observation of banking app sessions."
                ),
            },
            "T1517": {
                "name": "Access Notifications",
                "tactic": "Collection",
                "description": (
                    "Read, intercept, or dismiss notifications from banking apps, "
                    "SMS, and 2FA apps. Used to steal OTP codes and suppress fraud "
                    "alerts from financial institutions."
                ),
            },
            "T1636.003": {
                "name": "Protected User Data: Contact List",
                "tactic": "Collection",
                "description": (
                    "Exfiltrate the device contact list for SMS worm propagation "
                    "or targeted phishing campaigns."
                ),
            },
            "T1636.004": {
                "name": "Protected User Data: SMS Messages",
                "tactic": "Collection",
                "description": (
                    "Intercept, read, or forward SMS messages. Primary technique "
                    "for stealing SMS-based 2FA codes from banking services."
                ),
            },
            "T1418": {
                "name": "Software Discovery",
                "tactic": "Discovery",
                "description": (
                    "Enumerate installed applications to identify target banking "
                    "apps and determine which overlay screens to deploy."
                ),
            },
            "T1521": {
                "name": "Encrypted Channel",
                "tactic": "Command and Control",
                "description": (
                    "Encrypt C2 communications using TLS, AES, or custom protocols "
                    "to evade network-level detection."
                ),
            },
            "T1568.002": {
                "name": "Dynamic Resolution: Domain Generation Algorithms",
                "tactic": "Command and Control",
                "description": (
                    "Use algorithmic domain generation to produce a large number "
                    "of potential C2 domains, making infrastructure takedown difficult. "
                    "The malware and C2 server share the same DGA seed."
                ),
            },
            "T1646": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": (
                    "Exfiltrate stolen credentials, SMS messages, and contact lists "
                    "over the established C2 channel."
                ),
            },
            "T1644": {
                "name": "Out of Band Data",
                "tactic": "Exfiltration",
                "description": (
                    "Exfiltrate data through channels other than the primary C2, "
                    "such as SMS, Telegram bots, or email."
                ),
            },
            "T1471": {
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": (
                    "Encrypt device files and demand ransom. Mobile ransomware "
                    "typically targets external storage and media files."
                ),
            },
        }
        ids = []
        documents = []
        embeddings_list = []
        metadatas = []
        for tech_id, tech_data in extended_techniques.items():
            text = (
                f"{tech_id} - {tech_data['name']} ({tech_data['tactic']}): "
                f"{tech_data['description']}"
            )
            embedding = model.encode(text).tolist()
            ids.append(tech_id)
            documents.append(text)
            embeddings_list.append(embedding)
            metadatas.append({
                "source": "MITRE ATT&CK Mobile v15",
                "technique_id": tech_id,
                "tactic": tech_data["tactic"],
                "name": tech_data["name"],
            })
        if ids:
            collection.upsert(
                ids=ids,
                documents=documents,
                embeddings=embeddings_list,
                metadatas=metadatas,
            )
        return len(ids)


    def _populate_malnet(collection, model) -> int:
        """
        Populate the MalNet phylogenetics collection with malware family
        evolution summaries.
        """
        families_data = _load_families_json()
        families = families_data.get("families", [])
        ids = []
        documents = []
        embeddings_list = []
        metadatas = []
        for family in families:
            family_name = family["family_name"]
            text_parts = [
                f"Malware Family: {family_name}",
                f"Aliases: {', '.join(family.get('aliases', []))}",
                f"First Seen: {family.get('first_seen', 'Unknown')}",
                f"Primary Targets: {', '.join(family.get('primary_targets', []))}",
                f"Target Institutions: {', '.join(family.get('target_institutions', []))}",
            ]
            for version_info in family.get("evolution", []):
                text_parts.append(
                    f"Version {version_info['version']} ({version_info['date']}): "
                    f"Techniques: {', '.join(version_info.get('techniques', []))}. "
                    f"{version_info.get('description', '')}"
                )
            
            text_parts.append(
                f"Evolution Summary: {family.get('evolution_summary', '')}")
            
            predicted = family.get("predicted_next_techniques", [])
            if predicted:
                text_parts.append(
                    f"Predicted Next Techniques: {', '.join(predicted)}"
                )
            
            text = "\n".join(text_parts)
            embedding = model.encode(text).tolist()
            ids.append(family_name)
            documents.append(text[:5000])
            embeddings_list.append(embedding)
            metadatas.append({
                "family_name": family_name,
                "source": "MalNet"
            })

        if ids:
            collection.upsert(
                ids=ids,
                documents=documents,
                embeddings=embeddings_list,
                metadatas=metadatas,
            )
        return len(ids)

    def _load_families_json() -> dict:
        if not FAMILIES_JSON.exists():
            logger.warning(
                "[KB] Families JSON not found: %s", FAMILIES_JSON)
            return {}
        with open(FAMILIES_JSON, "r", encoding="utf-8") as fh:
            return json.load(fh)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    result = populate_knowledge_base()
    print(
        f"\n✓ Knowledge base populated successfully.\n"
        f"   MITRE Techniques : {result['mitre_techniques']}\n"
        f"   Malware Families : {result['malnet_families']}\n"
    )
    if result.get("errors"):
        print(
            f"  Errors: {result['errors']}")
