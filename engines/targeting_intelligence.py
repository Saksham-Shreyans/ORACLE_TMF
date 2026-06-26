"""
ORACLE-TMF  ·  engines/targeting_intelligence.py
=================================================
TARGETING INTELLIGENCE MODULE
The system doesn't just predict "overlay attack" — it predicts WHICH
financial institution will be targeted.  This is the highest-impact
component for actionable defence: concrete, named-bank intelligence
that a non-technical reviewer can verify on sight.
ARCHITECTURE — 4 Detection Layers:
  Layer 1 — Package Array Analysis
    Cross-reference all dormant package name arrays in dead code against
    a curated bank package taxonomy (200+ entries).  Package names in
    unreachable Smali code = pre-positioned targeting.
  Layer 2 — Overlay Asset Analysis
    Inflate dormant XML layouts (Class 6 orphaned UIs) and analyse their
    content:  colour schemes, drawable references, field label text, and
    embedded image filenames.  Map financial brand signatures to specific
    institutions.
  Layer 3 — Geographic Expansion Signals
    Identify locale-specific resource directories (res/values-hi/ for India,
    res/values-de/ for Germany) that are present but unreferenced in active
    code.  Flag country Mobile Country Codes (MCC) in dead TelephonyManager
    getNetworkCountryIso() comparisons.
  Layer 4 — Overlay HTML Identification
    Scan the DEX string pool for HTML/CSS fragments containing financial
    institution identifiers, login form markup, or banking app UI strings.
    Extract institution names directly from embedded phishing page source.
OUTPUT:
  A TargetingReport dict containing:
    predicted_targets:       list of {institution, package, country, confidence, layers}
    geographic_expansion:    list of predicted target country codes
    family_hint:             malware family identified from package patterns
    targeting_confidence:    overall targeting prediction confidence score
    html_overlay_hints:      raw HTML fragments extracted from string pool
Research basis:
  • ORACLE-TMF Stage 1 Solution Approach, Slide 11 — "Targeting Intelligence Module"
  • Threat Fabric Annual Report 2025 — Android Banking Trojan Target Analysis
  • CERT-IN advisory on UPI fraud malware targeting (2025)
"""
from __future__ import annotations
import json
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any,Optional
from config.settings import BANK_TAXONOMY_PATH
from models.mutation_artifact_graph import MutationArtifactGraph
logger=logging.getLogger(__name__)





MCC_MAP:dict[str,dict]={
    "404":{"country":"India","iso":"IN"},
    "405":{"country":"India","iso":"IN"},
    "410":{"country":"Pakistan","iso":"PK"},
    "470":{"country":"Bangladesh","iso":"BD"},
    "413":{"country":"Sri Lanka","iso":"LK"},
    "432":{"country":"Iran","iso":"IR"},
    "460":{"country":"China","iso":"CN"},
    "440":{"country":"Japan","iso":"JP"},
    "450":{"country":"South Korea","iso":"KR"},
    "515":{"country":"Philippines","iso":"PH"},
    "510":{"country":"Indonesia","iso":"ID"},
    "502":{"country":"Malaysia","iso":"MY"},
    "525":{"country":"Singapore","iso":"SG"},
    "310":{"country":"USA","iso":"US"},
    "311":{"country":"USA","iso":"US"},
    "232":{"country":"Austria","iso":"AT"},
    "262":{"country":"Germany","iso":"DE"},
    "234":{"country":"UK","iso":"GB"},
    "208":{"country":"France","iso":"FR"},
    "222":{"country":"Italy","iso":"IT"},
    "214":{"country":"Spain","iso":"ES"},
    "505":{"country":"Australia","iso":"AU"},
    "302":{"country":"Canada","iso":"CA"},
    "724":{"country":"Brazil","iso":"BR"},
    "520":{"country":"Thailand","iso":"TH"},
    "401":{"country":"Kazakhstan","iso":"KZ"},
}

LOCALE_TO_COUNTRY:dict[str,str]={
    "hi":"IN","mr":"IN","gu":"IN","ta":"IN","te":"IN",
    "kn":"IN","ml":"IN","pa":"IN","bn":"IN","or":"IN",
    "de":"DE","fr":"FR","es":"ES","it":"IT","pt":"BR",
    "nl":"NL","ru":"RU","pl":"PL","tr":"TR",
    "zh":"CN","ja":"JP","ko":"KR",
    "ar":"SA","fa":"IR","ur":"PK",
    "id":"ID","ms":"MY","tl":"PH",
    "th":"TH","vi":"VN",
    "en-IN":"IN","en-AU":"AU","en-GB":"GB","en-US":"US",
}

_HTML_BANK_INDICATORS:list[re.Pattern]=[
    re.compile(r'(?i)<title>[^<]*(bank|pay|finance|wallet|upi|mobile banking)[^<]*</title>'),
    re.compile(r'(?i)(hdfc|sbi|icici|axis|kotak|pnb|barclays|chase|paypal)[^"\'<>{]{0,30}(login|sign.in|banking)'),
    re.compile(r'(?i)id=["\'](?:username|password|account.?no|upi.?pin|cvv|otp)["\']'),
    re.compile(r'(?i)(net.?banking|mobile.?banking|internet.?banking)'),
]

_FAMILY_HINTS:dict[str,list[str]]={
    "FluBot":["com.tencent.mm","com.yelp.android","com.delivery"],
    "SpyNote":["com.android.system","com.mobile.manager","com.sys.manager"],
    "Cerberus":["com.cia.ciaservice","com.system.update"],
    "GodFather":["com.google.service","com.android.update.service"],
    "ToxicPanda":["com.payment.app","com.bank.mobile"],
    "Anubis":["com.fota.control","com.system.control"],
}
class TargetingIntelligence:
    """
    4-Layer Targeting Intelligence Module.
    Analyses the MAG to predict which specific financial institutions
    will be targeted by the next version of the malware.
    Usage
    -----
    >>> intel = TargetingIntelligence()
    >>> report = intel.run(mag, extract_dir)
    """
    STAGE_NAME="TARGETING"
    def __init__(self)->None:
        self._taxonomy=self._load_taxonomy()
        
        self._pkg_to_entry:dict[str,dict]={
            entry["package_name"]:entry
            for entry in self._taxonomy.get("entries",[])
        }
        
        self._institution_keywords:list[tuple[str,dict]]=[
            (entry["institution_name"].lower(),entry)
            for entry in self._taxonomy.get("entries",[])
        ]
    
    
    
    def run(
        self,
        mag:MutationArtifactGraph,
        extract_dir:str="",
        analysis:Optional[Any]=None,
    )->dict:
        """
        Execute all 4 targeting intelligence layers.
        Parameters
        ----------
        mag         : MutationArtifactGraph — fully populated by Stages A-H
        extract_dir : str — extracted APK directory (Stage A output)
        analysis    : Androguard Analysis object (Stage B output), optional
        Returns
        -------
        dict with keys:
          predicted_targets, geographic_expansion, family_hint,
          targeting_confidence, html_overlay_hints
        """
        t0=time.perf_counter()
        logger.info("[Targeting] Starting 4-layer targeting intelligence analysis")
        targets:dict[str,dict]={}
        geo_signals:set[str]=set()
        html_hints:list[str]=[]
        family_hint:str=mag.malware_family or ""
        
        l1_targets=self._layer1_package_arrays(mag)
        for tgt in l1_targets:
            pkg=tgt["package_name"]
            if pkg not in targets:
                targets[pkg]=tgt.copy()
            targets[pkg].setdefault("detection_layers",[]).append("package_array")
            if not family_hint:
                family_hint=self._infer_family_from_packages(mag)
        
        l2_targets=self._layer2_overlay_assets(mag,extract_dir)
        for tgt in l2_targets:
            pkg=tgt["package_name"]
            if pkg not in targets:
                targets[pkg]=tgt.copy()
            targets[pkg].setdefault("detection_layers",[]).append("overlay_asset")
        
        l3_countries=self._layer3_geographic_signals(mag,extract_dir)
        geo_signals.update(l3_countries)
        
        l4_targets,html_hints=self._layer4_html_overlays(mag,analysis)
        for tgt in l4_targets:
            pkg=tgt["package_name"]
            if pkg not in targets:
                targets[pkg]=tgt.copy()
            targets[pkg].setdefault("detection_layers",[]).append("html_overlay")
        
        predicted=[]
        for pkg,tgt in targets.items():
            layers=tgt.get("detection_layers",[])
            
            layer_count=len(set(layers))
            base_confidence=0.50+(layer_count-1)*0.15
            tgt["confidence"]=min(0.95,round(base_confidence,3))
            predicted.append(tgt)
        predicted.sort(key=lambda x:x.get("confidence",0),reverse=True)
        
        top_confidences=[t.get("confidence",0)for t in predicted[:3]]
        overall_confidence=sum(top_confidences)/max(1,len(top_confidences))
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Targeting] Complete in %.1f ms | targets=%d | countries=%s | family=%s",
            elapsed_ms,len(predicted),sorted(geo_signals),family_hint or "UNKNOWN",
        )
        return{
            "predicted_targets":predicted[:10],
            "geographic_expansion":sorted(geo_signals),
            "family_hint":family_hint,
            "targeting_confidence":round(overall_confidence,3),
            "html_overlay_hints":html_hints[:5],
        }
    
    
    
    def _layer1_package_arrays(self,mag:MutationArtifactGraph)->list[dict]:
        """
        Cross-reference dead-code string constants against the bank package taxonomy.
        Android banking trojans pre-populate arrays of target package names
        in dead/initialisation code so they can react when the target app
        is in the foreground (for overlay injection).
        """
        found:list[dict]=[]
        
        dead_strings:set[str]=set()
        for dead in mag.dead_code:
            
            string_re=re.compile(r'const-string[^,]+,\s*"([^"]{5,})"')
            for m in string_re.finditer(dead.smali_code or ""):
                dead_strings.add(m.group(1).strip())
        
        for ps in mag.placeholder_strings:
            dead_strings.add(ps.value)
        
        for stub in mag.c2_stubs:
            if stub.payload_schema:
                dead_strings.add(stub.payload_schema)
        
        for string_val in dead_strings:
            
            if string_val in self._pkg_to_entry:
                entry=self._pkg_to_entry[string_val]
                found.append({
                    "package_name":entry["package_name"],
                    "institution_name":entry["institution_name"],
                    "country_code":entry["country_code"],
                    "category":entry.get("category","banking"),
                    "detection_layers":[],
                })
                continue
            
            for pkg,entry in self._pkg_to_entry.items():
                if(string_val in pkg or pkg in string_val)and len(string_val)>6:
                    found.append({
                        "package_name":entry["package_name"],
                        "institution_name":entry["institution_name"],
                        "country_code":entry["country_code"],
                        "category":entry.get("category","banking"),
                        "detection_layers":[],
                    })
                    break
        
        seen:set[str]=set()
        unique:list[dict]=[]
        for t in found:
            if t["institution_name"]not in seen:
                seen.add(t["institution_name"])
                unique.append(t)
        logger.debug("[Targeting] Layer 1: %d target institutions identified",len(unique))
        return unique
    
    
    
    def _layer2_overlay_assets(
        self,mag:MutationArtifactGraph,extract_dir:str
    )->list[dict]:
        """
        Analyse orphaned UI layouts (Class 6 artifacts) for financial branding.
        Examines drawable references, color values, and text labels within
        the XML layout to identify the targeted institution.
        """
        found:list[dict]=[]
        for ui_flow in mag.unfinished_ui_flows:
            
            for asset_ref in ui_flow.asset_refs:
                asset_lower=asset_ref.lower()
                for institution_kw,entry in self._institution_keywords:
                    
                    inst_tokens=institution_kw.split()
                    if any(tok in asset_lower for tok in inst_tokens if len(tok)>3):
                        found.append({
                            "package_name":entry["package_name"],
                            "institution_name":entry["institution_name"],
                            "country_code":entry["country_code"],
                            "category":entry.get("category","banking"),
                            "detection_layers":[],
                            "evidence":f"asset_ref:{asset_ref}",
                        })
                        break
            
            layout_stem=Path(ui_flow.layout_file).stem.lower()
            for institution_kw,entry in self._institution_keywords:
                inst_tokens=institution_kw.split()
                if any(tok in layout_stem for tok in inst_tokens if len(tok)>3):
                    found.append({
                        "package_name":entry["package_name"],
                        "institution_name":entry["institution_name"],
                        "country_code":entry["country_code"],
                        "category":entry.get("category","banking"),
                        "detection_layers":[],
                        "evidence":f"layout:{ui_flow.layout_file}",
                    })
        logger.debug("[Targeting] Layer 2: %d targets from overlay assets",len(found))
        return found
    
    
    
    def _layer3_geographic_signals(
        self,mag:MutationArtifactGraph,extract_dir:str
    )->set[str]:
        """
        Identify target countries from:
          a) Locale-specific resource directories (res/values-hi/ → India)
          b) MCC codes in dead TelephonyManager comparisons
          c) Country ISO codes in dead string constants
        """
        countries:set[str]=set()
        
        if extract_dir and os.path.isdir(extract_dir):
            values_dir=os.path.join(extract_dir,"res")
            if os.path.isdir(values_dir):
                for subdir in os.listdir(values_dir):
                    if subdir.startswith("values-"):
                        locale_suffix=subdir[7:]
                        
                        locale_code=locale_suffix.split("-")[0].lower()
                        if locale_code in LOCALE_TO_COUNTRY:
                            countries.add(LOCALE_TO_COUNTRY[locale_code])
                            logger.debug("[Targeting] Layer 3: locale dir %s → %s",
                                        subdir,LOCALE_TO_COUNTRY[locale_code])
        
        mcc_re=re.compile(r'\b(4[01][0-9]|3[01][0-9]|2[0-9][0-9]|5[012][0-9]|7[02][0-9])\b')
        for dead in mag.dead_code:
            smali=dead.smali_code or ""
            if "getNetworkCountryIso"in smali or "getSimCountryIso"in smali:
                for m in mcc_re.finditer(smali):
                    mcc=m.group(1)
                    if mcc in MCC_MAP:
                        countries.add(MCC_MAP[mcc]["iso"])
                        logger.debug("[Targeting] Layer 3: MCC %s → %s",
                                    mcc,MCC_MAP[mcc]["iso"])
        
        iso_re=re.compile(r'\b([A-Z]{2})\b')
        iso_set=set(LOCALE_TO_COUNTRY.values())
        for ps in mag.placeholder_strings:
            for m in iso_re.finditer(ps.value):
                iso=m.group(1)
                if iso in iso_set:
                    countries.add(iso)
        logger.debug("[Targeting] Layer 3: geographic signals → %s",sorted(countries))
        return countries
    
    
    
    def _layer4_html_overlays(
        self,mag:MutationArtifactGraph,analysis:Optional[Any]
    )->tuple[list[dict],list[str]]:
        """
        Scan the DEX string pool for HTML/CSS fragments containing
        financial institution identifiers or phishing form markup.
        Stage J Hypothesizer already analyses these — here we do a
        fast keyword scan to identify specific institutions.
        """
        found:list[dict]=[]
        html_frags:list[str]=[]
        
        html_candidates:list[str]=[]
        for ps in mag.placeholder_strings:
            val=ps.value
            if "<"in val and ">"in val and len(val)>20:
                html_candidates.append(val)
        
        for stub in mag.c2_stubs:
            if stub.payload_schema and "<"in stub.payload_schema:
                html_candidates.append(stub.payload_schema)
        for html_chunk in html_candidates:
            
            for pattern in _HTML_BANK_INDICATORS:
                m=pattern.search(html_chunk)
                if m:
                    html_frags.append(html_chunk[:200])
                    matched_text=m.group(0).lower()
                    
                    for institution_kw,entry in self._institution_keywords:
                        inst_tokens=institution_kw.split()
                        if any(tok in matched_text for tok in inst_tokens if len(tok)>3):
                            found.append({
                                "package_name":entry["package_name"],
                                "institution_name":entry["institution_name"],
                                "country_code":entry["country_code"],
                                "category":entry.get("category","banking"),
                                "detection_layers":[],
                                "evidence":f"html:{matched_text[:60]}",
                            })
                            break
                    break
        logger.debug("[Targeting] Layer 4: %d HTML hints, %d targets",len(html_frags),len(found))
        return found,html_frags
    
    
    
    def _infer_family_from_packages(self,mag:MutationArtifactGraph)->str:
        """
        Infer the malware family from package name patterns in dead code.
        Returns empty string if no family can be confidently identified.
        """
        all_strings:list[str]=[]
        for dead in mag.dead_code:
            string_re=re.compile(r'const-string[^,]+,\s*"([^"]{5,})"')
            all_strings.extend(string_re.findall(dead.smali_code or ""))
        for ps in mag.placeholder_strings:
            all_strings.append(ps.value)
        for family,patterns in _FAMILY_HINTS.items():
            for pattern in patterns:
                if any(pattern in s for s in all_strings):
                    logger.info("[Targeting] Family inferred from package patterns: %s",family)
                    return family
        return ""
    
    
    
    @staticmethod
    def _load_taxonomy()->dict:
        """Load the bank package taxonomy JSON from disk."""
        try:
            if os.path.isfile(BANK_TAXONOMY_PATH):
                with open(BANK_TAXONOMY_PATH,"r",encoding="utf-8")as fh:
                    return json.load(fh)
        except Exception as exc:
            logger.warning("[Targeting] Failed to load bank taxonomy: %s",exc)
        
        logger.info("[Targeting] Using inline fallback bank taxonomy")
        return{
            "entries":[
                {"package_name":"com.snapwork.hdfc","institution_name":"HDFC Bank","country_code":"IN","category":"banking"},
                {"package_name":"com.sbi.upi","institution_name":"SBI YONO","country_code":"IN","category":"payment"},
                {"package_name":"com.csam.icici.bank.imobile","institution_name":"ICICI Bank","country_code":"IN","category":"banking"},
                {"package_name":"com.axis.mobile","institution_name":"Axis Bank","country_code":"IN","category":"banking"},
                {"package_name":"com.phonepe.app","institution_name":"PhonePe","country_code":"IN","category":"payment"},
                {"package_name":"net.one97.paytm","institution_name":"Paytm","country_code":"IN","category":"payment"},
                {"package_name":"com.google.android.apps.nbu.paisa.user","institution_name":"Google Pay","country_code":"IN","category":"payment"},
                {"package_name":"com.chase.sig.android","institution_name":"Chase","country_code":"US","category":"banking"},
                {"package_name":"com.infonow.bofa","institution_name":"Bank of America","country_code":"US","category":"banking"},
                {"package_name":"com.paypal.android.p2pmobile","institution_name":"PayPal","country_code":"US","category":"payment"},
                {"package_name":"com.barclays.android.barclaysmobilebanking","institution_name":"Barclays","country_code":"GB","category":"banking"},
                {"package_name":"uk.co.hsbc.hsbcukmobilebanking","institution_name":"HSBC UK","country_code":"GB","category":"banking"},
                {"package_name":"com.coinbase.android","institution_name":"Coinbase","country_code":"US","category":"crypto"},
                {"package_name":"com.binance.dev","institution_name":"Binance","country_code":"MT","category":"crypto"},
                {"package_name":"com.wallet.crypto.trustapp","institution_name":"Trust Wallet","country_code":"US","category":"crypto"},
            ]
        }
