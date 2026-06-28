from __future__ import annotations
import logging
import math
import re
import time
from typing import Any,Optional
from config.settings import(
    REFLECT_DEFAULT_THRESHOLD,
    REFLECT_MAX_CHAIN_DEPTH,
    REFLECT_THRESHOLD_CANDIDATES,
    SBERT_MODEL,
)
logger=logging.getLogger(__name__)
_REFLECTION_SIGS:tuple[str,...]=(
    "Ljava/lang/Class;->forName(",
    "Ljava/lang/reflect/Method;->invoke(",
    "Ljava/lang/ClassLoader;->loadClass(",
    "Ldalvik/system/DexClassLoader;-><init>(",
    "Ldalvik/system/PathClassLoader;->loadClass(",
    "Ljava/lang/Class;->getDeclaredMethod(",
    "Ljava/lang/Class;->getMethod(",
)
_SMALI_CLASS_RE=re.compile(r"^L[a-zA-Z][a-zA-Z0-9/$_]{2,};$")
_CONST_STRING_RE=re.compile(
    r"const-string(?:/jumbo)?\s+[vp]\d+,\s*\"([^\"]{4,})\"",
    re.MULTILINE,
)
_MALWARE_CLASS_CORPUS:list[str]=[
    "com.example.config.Settings",
    "com.android.service.SystemService",
    "com.update.service.UpdateManager",
    "com.manager.app.ApplicationManager",
    "com.sms.interceptor.SmsReceiver",
    "com.contact.stealer.ContactManager",
    "com.location.tracker.GpsService",
    "com.audio.recorder.MicCapture",
    "com.screen.capture.ScreenService",
    "com.keylogger.input.KeyCapture",
    "com.overlay.attack.PhishingActivity",
    "com.banking.overlay.LoginActivity",
    "com.crypto.wallet.WalletStealer",
    "com.c2.network.CommandService",
    "com.dropper.payload.PayloadLoader",
    "com.bot.controller.BotManager",
    "com.device.admin.AdminReceiver",
    "com.accessibility.service.AccessService",
    "com.notification.listener.NotifListener",
]
class TMFReflect:
    def __init__(self,threshold:float=REFLECT_DEFAULT_THRESHOLD)->None:
        self.threshold=threshold
        self._sbert_model:Optional[Any]=None
        self._sbert_available=True
    def augment_cfg(
        self,
        analysis:Any,
        cfg:Any,
        threshold:Optional[float]=None,
    )->Any:
        if cfg is None:
            logger.warning("[TMF-REFLECT] No CFG provided — skipping augmentation")
            return cfg
        t=threshold if threshold is not None else self.threshold
        t0=time.perf_counter()
        logger.info("[TMF-REFLECT] Augmenting CFG (threshold=%.2f)",t)
        rdg=self._build_rdg(analysis)
        logger.debug("[TMF-REFLECT] RDG nodes: %d",len(rdg))
        edges_injected=self._resolve_and_inject(rdg,analysis,cfg,t)
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[TMF-REFLECT] Complete in %.1f ms | "
            "reflection_calls_found=%d | edges_injected=%d",
            elapsed_ms,len(rdg),edges_injected,
        )
        return cfg
    def _build_rdg(self,analysis:Any)->list[dict]:
        rdg:list[dict]=[]
        try:
            for method_analysis in analysis.get_methods():
                if method_analysis.is_android_api()or method_analysis.is_external():
                    continue
                smali_code=self._get_smali(method_analysis)
                if not smali_code:
                    continue
                has_reflection=any(sig in smali_code for sig in _REFLECTION_SIGS)
                if not has_reflection:
                    continue
                caller_desc=self._method_descriptor(method_analysis.method)
                chain_depth=self._count_reflection_depth(smali_code)
                for match in _CONST_STRING_RE.finditer(smali_code):
                    string_value=match.group(1)
                    entropy=self._shannon_entropy(string_value)
                    weight=1.0/(1.0+entropy)
                    rdg.append({
                        "caller_desc":caller_desc,
                        "string_value":string_value,
                        "entropy":round(entropy,4),
                        "weight":round(weight,4),
                        "chain_depth":chain_depth,
                    })
        except Exception as exc:
            logger.warning("[TMF-REFLECT] RDG build error: %s",exc)
        return rdg
    def _resolve_and_inject(
        self,
        rdg:list[dict],
        analysis:Any,
        cfg:Any,
        threshold:float,
    )->int:
        injected=0
        class_cache:dict[str,Any]={}
        try:
            for class_analysis in analysis.get_classes():
                class_cache[class_analysis.name]=class_analysis
        except Exception:
            pass
        for entry in rdg:
            string_val=entry["string_value"]
            weight=entry["weight"]
            caller_desc=entry["caller_desc"]
            if weight<threshold*0.5:
                continue
            smali_candidate=self._to_smali_class(string_val)
            if weight>=threshold:
                count=self._inject_direct(
                    caller_desc,smali_candidate,class_cache,cfg
                )
                injected+=count
            elif weight>=threshold*0.5:
                count=self._inject_semantic(
                    caller_desc,string_val,weight,class_cache,cfg
                )
                injected+=count
        return injected
    def _inject_direct(
        self,
        caller_desc:str,
        smali_class:str,
        class_cache:dict,
        cfg:Any,
    )->int:
        if not _SMALI_CLASS_RE.match(smali_class):
            return 0
        if smali_class not in class_cache:
            return 0
        class_analysis=class_cache[smali_class]
        count=0
        for method_analysis in class_analysis.get_methods():
            callee_desc=self._method_descriptor(method_analysis.method)
            if callee_desc not in cfg:
                cfg.add_node(callee_desc)
            cfg.add_edge(caller_desc,callee_desc,weight="reflect_direct")
            count+=1
        if count>0:
            logger.debug(
                "[TMF-REFLECT] Direct inject: %s → %s (%d methods)",
                caller_desc[-40:],smali_class,count
            )
        return count
    def _inject_semantic(
        self,
        caller_desc:str,
        string_val:str,
        weight:float,
        class_cache:dict,
        cfg:Any,
    )->int:
        sbert=self._get_sbert()
        if sbert is None:
            return 0
        try:
            import numpy as np
            query_emb=sbert.encode(string_val,normalize_embeddings=True)
            corpus_embs=sbert.encode(_MALWARE_CLASS_CORPUS,normalize_embeddings=True)
            similarities=np.dot(corpus_embs,query_emb)
            best_idx=int(np.argmax(similarities))
            best_sim=float(similarities[best_idx])
            if best_sim<0.75:
                return 0
            best_match=_MALWARE_CLASS_CORPUS[best_idx]
            smali_match=self._to_smali_class(best_match)
            logger.debug(
                "[TMF-REFLECT] Semantic resolve: '%s' → '%s' (sim=%.3f)",
                string_val[:40],best_match,best_sim,
            )
            return self._inject_direct(caller_desc,smali_match,class_cache,cfg)
        except Exception as exc:
            logger.debug("[TMF-REFLECT] SBERT resolution failed: %s",exc)
            return 0
    def _get_sbert(self)->Optional[Any]:
        if not self._sbert_available:
            return None
        if self._sbert_model is not None:
            return self._sbert_model
        try:
            from sentence_transformers import SentenceTransformer
            local_only=os.getenv("ORACLE_TMF_SBERT_LOCAL_ONLY","0")=="1"
            if local_only:
                self._sbert_model=SentenceTransformer(
                    SBERT_MODEL,
                    local_files_only=True,
                )
            else:
                self._sbert_model=SentenceTransformer(SBERT_MODEL)
            logger.debug("[TMF-REFLECT] SBERT model loaded: %s (local_only=%s)",SBERT_MODEL,local_only)
        except ImportError:
            logger.warning(
                "[TMF-REFLECT] sentence-transformers not installed — "
                "semantic resolution disabled.  Run: pip install sentence-transformers"
            )
            self._sbert_available=False
            return None
        except Exception as exc:
            logger.warning("[TMF-REFLECT] SBERT load failed: %s",exc)
            self._sbert_available=False
            return None
        return self._sbert_model
    @staticmethod
    def _to_smali_class(java_name:str)->str:
        name=java_name.strip()
        if name.startswith("L")and name.endswith(";"):
            return name
        name=name.replace(".","/")
        if not name.startswith("L"):
            name="L"+name
        if not name.endswith(";"):
            name=name+";"
        return name
    @staticmethod
    def _shannon_entropy(text:str)->float:
        if not text:
            return 0.0
        freq:dict[str,int]={}
        for c in text:
            freq[c]=freq.get(c,0)+1
        total=len(text)
        return-sum((v/total)*math.log2(v/total)for v in freq.values())
    @staticmethod
    def _count_reflection_depth(smali_code:str)->int:
        return sum(1 for sig in _REFLECTION_SIGS if sig in smali_code)
    @staticmethod
    def _get_smali(method_analysis:Any)->str:
        try:
            src=method_analysis.method.get_source()
            return src if src else ""
        except Exception:
            return ""
    @staticmethod
    def _method_descriptor(method_obj:Any)->str:
        try:
            return(
                f"{method_obj.get_class_name()}"
                f"->{method_obj.get_name()}"
                f"{method_obj.get_descriptor()}"
            )
        except Exception:
            return str(method_obj)
