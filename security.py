"""Shared security hardening helpers for ORACLE-TMF."""
from __future__ import annotations
import html
import hmac
import os
import re
import tempfile
import time
from collections import OrderedDict,defaultdict,deque
from pathlib import Path
from typing import Any,Iterable
from fastapi import HTTPException,UploadFile
from fastapi.security import APIKeyHeader
from config.settings import(
    API_KEY_ENV,
    APK_MAX_SIZE_BYTES,
    APK_MIN_SIZE_BYTES,
    RESULT_CACHE_MAX_ENTRIES,
    RESULT_CACHE_TTL_SECONDS,
    UPLOAD_READ_CHUNK_BYTES,
)
try:
    from defusedxml import ElementTree as SafeET
except ImportError:
    import xml.etree.ElementTree as SafeET
CONTROL_CHARS_RE=re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
SECRET_RE=re.compile(
    r"(?i)(sk-ant-[a-z0-9_-]+|sk-[a-z0-9_-]{16,}|api[_-]?key\s*[:=]\s*['\"]?[^'\"\s,}]+|"
    r"token\s*[:=]\s*['\"]?[^'\"\s,}]+|password\s*[:=]\s*['\"]?[^'\"\s,}]+)"
)
APK_REQUIRED_NAMES=("AndroidManifest.xml","classes.dex")
api_key_header=APIKeyHeader(name="X-API-Key",auto_error=False)
def private_runtime_dir(app_name:str="oracle_tmf")->Path:
    configured=os.getenv("ORACLE_TMF_WORK_DIR")
    root=Path(configured)if configured else Path(tempfile.gettempdir())/app_name
    root.mkdir(parents=True,exist_ok=True)
    try:
        os.chmod(root,0o700)
    except OSError:
        pass
    return root
def clean_text(value:Any,max_len:int=2000)->str:
    text="" if value is None else str(value)
    text=CONTROL_CHARS_RE.sub("",text)
    return text[:max_len]
def escaped(value:Any,max_len:int=2000)->str:
    return html.escape(clean_text(value,max_len),quote=True)
def redact_secrets(value:Any,max_len:int=16000)->str:
    return SECRET_RE.sub("[REDACTED]",clean_text(value,max_len))
def safe_xml_parse(path:str|os.PathLike[str]):
    return SafeET.parse(path)
def safe_xml_fromstring(text:str):
    return SafeET.fromstring(text)
def validate_apk_zip_names(names:Iterable[str])->None:
    present=set(names)
    if APK_REQUIRED_NAMES[0]not in present:
        raise ValueError("APK is missing AndroidManifest.xml")
    if not any(name.endswith(".dex")and "/" not in name for name in present):
        raise ValueError("APK is missing top-level DEX bytecode")
async def read_upload_limited(upload:UploadFile,field_name:str,max_bytes:int=APK_MAX_SIZE_BYTES)->bytes:
    filename=upload.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400,detail=f"{field_name}must be an.apk file")
    data=bytearray()
    while True:
        chunk=await upload.read(UPLOAD_READ_CHUNK_BYTES)
        if not chunk:
            break
        data.extend(chunk)
        if len(data)>max_bytes:
            raise HTTPException(status_code=413,detail=f"{field_name}exceeds{max_bytes//1024//1024}MB limit")
    if len(data)<APK_MIN_SIZE_BYTES:
        raise HTTPException(status_code=400,detail=f"{field_name}is too small")
    if bytes(data[:4])!=b"PK\x03\x04":
        raise HTTPException(status_code=400,detail=f"{field_name}is not a ZIP/APK")
    import zipfile,io
    try:
        with zipfile.ZipFile(io.BytesIO(bytes(data)),"r")as zf:
            validate_apk_zip_names(zf.namelist())
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=f"{field_name}is not a valid APK:{exc}")from exc
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400,detail=f"{field_name}ZIP is corrupt")from exc
    return bytes(data)
def require_api_key(provided_key:str|None)->str:
    expected=os.getenv(API_KEY_ENV,"")
    if not expected:
        raise HTTPException(status_code=503,detail=f"API disabled until{API_KEY_ENV}is configured")
    if not provided_key or not hmac.compare_digest(provided_key,expected):
        raise HTTPException(status_code=401,detail="Invalid or missing API key")
    return provided_key
class TTLResultStore:
    def __init__(self,max_entries:int=RESULT_CACHE_MAX_ENTRIES,ttl_seconds:int=RESULT_CACHE_TTL_SECONDS)->None:
        self._max_entries=max_entries
        self._ttl_seconds=ttl_seconds
        self._items:OrderedDict[str,tuple[float,str,dict]]=OrderedDict()
    def set(self,analysis_id:str,owner:str,value:dict)->None:
        self._purge_expired()
        self._items[analysis_id]=(time.time(),owner,value)
        self._items.move_to_end(analysis_id)
        while len(self._items)>self._max_entries:
            self._items.popitem(last=False)
    def get(self,analysis_id:str,owner:str)->dict|None:
        self._purge_expired()
        item=self._items.get(analysis_id)
        if not item:
            return None
        _,item_owner,value=item
        if item_owner!=owner:
            raise HTTPException(status_code=403,detail="Result belongs to a different API key")
        self._items.move_to_end(analysis_id)
        return value
    def delete(self,analysis_id:str,owner:str)->bool:
        self._purge_expired()
        item=self._items.get(analysis_id)
        if not item:
            return False
        if item[1]!=owner:
            raise HTTPException(status_code=403,detail="Result belongs to a different API key")
        del self._items[analysis_id]
        return True
    def _purge_expired(self)->None:
        now=time.time()
        expired=[key for key,(created,_,_)in self._items.items()if now-created>self._ttl_seconds]
        for key in expired:
            del self._items[key]
class SlidingWindowRateLimiter:
    def __init__(self,max_requests:int,window_seconds:int)->None:
        self._max_requests=max_requests
        self._window_seconds=window_seconds
        self._hits:defaultdict[str,deque[float]]=defaultdict(deque)
    def check(self,key:str)->None:
        now=time.time()
        hits=self._hits[key]
        while hits and now-hits[0]>self._window_seconds:
            hits.popleft()
        if len(hits)>=self._max_requests:
            raise HTTPException(status_code=429,detail="Rate limit exceeded")
        hits.append(now)
def request_identity(client_host:str,api_key:str)->str:
    return f"{client_host}:{api_key[:12]}"
