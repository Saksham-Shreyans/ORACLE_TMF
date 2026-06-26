"""
ORACLE-TMF API layer with production-safe defaults.

The API is disabled until ORACLE_TMF_API_KEY is configured. Results are
owner-bound to the API key, bounded by TTL, and summaries are returned by
default so full MAG data is not exposed accidentally.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import tempfile
import uuid
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel

from config.settings import (
    API_RATE_LIMIT_REQUESTS,
    API_RATE_LIMIT_WINDOW_SECONDS,
    APK_MAX_SIZE_BYTES,
)
from security import (
    TTLResultStore,
    SlidingWindowRateLimiter,
    api_key_header,
    clean_text,
    read_upload_limited,
    require_api_key,
    request_identity,
)

logger = logging.getLogger(__name__)

_DOCS_ENABLED = os.getenv("ORACLE_TMF_ENABLE_DOCS", "0") == "1"
_ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("ORACLE_TMF_CORS_ORIGINS", "").split(",") if origin.strip()]
_ALLOWED_HOSTS = [host.strip() for host in os.getenv("ORACLE_TMF_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if host.strip()]
_ANALYSIS_TIMEOUT_SECONDS = int(os.getenv("ORACLE_TMF_ANALYSIS_TIMEOUT_SECONDS", "900"))
_ANALYSIS_SEMAPHORE = asyncio.Semaphore(int(os.getenv("ORACLE_TMF_MAX_CONCURRENT_ANALYSES", "1")))

app = FastAPI(
    title="ORACLE-TMF API",
    description="Authenticated Android malware mutation analysis API.",
    version="2.0.0",
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=_ALLOWED_HOSTS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type"],
)

_results_cache = TTLResultStore()
_rate_limiter = SlidingWindowRateLimiter(API_RATE_LIMIT_REQUESTS, API_RATE_LIMIT_WINDOW_SECONDS)


@app.middleware("http")
async def security_headers_and_size_guard(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > (APK_MAX_SIZE_BYTES * 2 + 1024 * 1024):
        raise HTTPException(status_code=413, detail="Request body too large")
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


def _authorized_owner(request: Request, api_key: str | None = Depends(api_key_header)) -> str:
    valid_key = require_api_key(api_key)
    client_host = request.client.host if request.client else "unknown"
    owner = request_identity(client_host, hashlib.sha256(valid_key.encode()).hexdigest())
    _rate_limiter.check(owner)
    return owner


class HealthResponse(BaseModel):
    status: str = "healthy"
    timestamp: str = ""


class ReadinessResponse(BaseModel):
    status: str = "ready"
    version: str = "2.0.0"
    timestamp: str = ""


class AnalysisSubmission(BaseModel):
    analysis_id: str
    status: str
    message: str
    submitted_at: str


class ForecastSummary(BaseModel):
    predicted_tactic: str = ""
    predicted_technique: str = ""
    technique_name: str = ""
    confidence_score: float = 0.0
    confidence_ci_low: float = 0.0
    confidence_ci_high: float = 0.0
    passes_gate: bool = False
    target_institutions: list[str] = []
    target_countries: list[str] = []


class AnalysisResponse(BaseModel):
    analysis_id: str
    status: str
    apk_sha256: str = ""
    package_name: str = ""
    malware_family: str = ""
    total_artifacts: int = 0
    artifact_counts: dict = {}
    forecasts: list[ForecastSummary] = []
    high_confidence_count: int = 0
    analysis_time_ms: float = 0.0
    stage_errors: dict = {}
    full_mag: dict = {}


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    return HealthResponse(status="healthy", timestamp=datetime.utcnow().isoformat() + "Z")


@app.get("/ready", response_model=ReadinessResponse, tags=["System"])
async def readiness_check(owner: str = Depends(_authorized_owner)):
    return ReadinessResponse(status="ready", timestamp=datetime.utcnow().isoformat() + "Z")


@app.post("/analyze", response_model=AnalysisSubmission, tags=["Analysis"])
async def analyze_apk(
    request: Request,
    apk_file: UploadFile = File(..., description="Android APK file to analyze"),
    prev_apk_file: Optional[UploadFile] = File(None, description="Previous version APK (optional)"),
    skip_llm: bool = Query(True, description="Skip external LLM agents unless explicitly enabled"),
    owner: str = Depends(_authorized_owner),
):
    apk_bytes = await read_upload_limited(apk_file, "Target APK")
    prev_bytes = await read_upload_limited(prev_apk_file, "Previous APK") if prev_apk_file else None

    sha256 = hashlib.sha256(apk_bytes).hexdigest()
    analysis_id = f"{uuid.uuid4().hex[:12]}"

    async with _ANALYSIS_SEMAPHORE:
        try:
            result_dict = await asyncio.wait_for(
                asyncio.to_thread(_run_analysis, analysis_id, apk_bytes, prev_bytes, skip_llm),
                timeout=_ANALYSIS_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            logger.warning("[API] Analysis timed out for %s", sha256[:12])
            raise HTTPException(status_code=504, detail="Analysis timed out") from exc
        except Exception as exc:
            logger.exception("[API] Analysis failed for %s", sha256[:12])
            raise HTTPException(status_code=500, detail="Analysis failed") from exc

    _results_cache.set(analysis_id, owner, result_dict)
    return AnalysisSubmission(
        analysis_id=analysis_id,
        status="completed",
        message=f"Analysis complete. Retrieve the summary at GET /results/{analysis_id}",
        submitted_at=datetime.utcnow().isoformat() + "Z",
    )


@app.get("/results/{analysis_id}", response_model=AnalysisResponse, tags=["Analysis"])
async def get_results(
    analysis_id: str,
    include_full: bool = Query(False, description="Return full MAG for privileged callers"),
    owner: str = Depends(_authorized_owner),
):
    result = _results_cache.get(analysis_id, owner)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found or expired")
    response = dict(result)
    if not include_full:
        response["full_mag"] = {}
        response["stage_errors"] = {}
    return AnalysisResponse(**response)


@app.delete("/results/{analysis_id}", tags=["Analysis"])
async def delete_result(analysis_id: str, owner: str = Depends(_authorized_owner)):
    deleted = _results_cache.delete(analysis_id, owner)
    return {"deleted": deleted}


def _run_analysis(analysis_id: str, apk_bytes: bytes, prev_bytes: Optional[bytes], skip_llm: bool) -> dict:
    from orchestrator import ORACLETMFOrchestrator

    with tempfile.TemporaryDirectory(prefix="oracle_tmf_job_") as tmp:
        apk_path = os.path.join(tmp, "target.apk")
        with open(apk_path, "wb") as fh:
            fh.write(apk_bytes)
        prev_path = None
        if prev_bytes:
            prev_path = os.path.join(tmp, "prev.apk")
            with open(prev_path, "wb") as fh:
                fh.write(prev_bytes)
        orch = ORACLETMFOrchestrator()
        result = orch.analyze(apk_path, prev_apk_path=prev_path, skip_llm=skip_llm, skip_report=True)

    mag = result.mag
    meta = mag.apk_metadata
    forecast_summaries = []
    for forecast in mag.forecasts:
        forecast_summaries.append({
            "predicted_tactic": clean_text(forecast.predicted_tactic, 200),
            "predicted_technique": clean_text(forecast.predicted_technique, 200),
            "technique_name": clean_text(forecast.technique_name, 200),
            "confidence_score": forecast.confidence_score,
            "confidence_ci_low": getattr(forecast, "confidence_ci_low", 0.0),
            "confidence_ci_high": getattr(forecast, "confidence_ci_high", 0.0),
            "passes_gate": forecast.passes_gate,
            "target_institutions": [clean_text(item, 120) for item in forecast.predicted_target_institutions],
            "target_countries": [clean_text(item, 8) for item in forecast.predicted_target_countries],
        })
    return {
        "analysis_id": analysis_id,
        "status": "completed" if result.success else "failed",
        "apk_sha256": meta.sha256,
        "package_name": clean_text(meta.package_name, 240),
        "malware_family": clean_text(mag.malware_family, 120),
        "total_artifacts": mag.total_artifact_count(),
        "artifact_counts": mag.artifact_class_counts(),
        "forecasts": forecast_summaries,
        "high_confidence_count": len(mag.high_confidence_forecasts()),
        "analysis_time_ms": result.total_time_ms,
        "stage_errors": {clean_text(k, 100): clean_text(v, 500) for k, v in mag.stage_errors.items()},
        "full_mag": mag.to_dict(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host=os.getenv("ORACLE_TMF_BIND_HOST", "127.0.0.1"), port=8000, reload=False)
