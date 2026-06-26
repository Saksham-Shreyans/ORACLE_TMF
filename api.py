"""
ORACLE-TMF  ·  api.py
=======================
FastAPI REST API Layer (v2.0)
Transforms ORACLE-TMF from a single-user Streamlit app into an
enterprise-deployable service that SOC teams can integrate programmatically.
Novel Contribution:
  "RESTful API for programmatic malware mutation analysis,
   enabling CI/CD pipeline integration."
Endpoints:
  POST /analyze       — Upload APK, returns analysis result JSON
  GET  /health        — System health check
  GET  /results/{id}  — Retrieve cached results by analysis ID
  GET  /docs          — OpenAPI/Swagger auto-documentation
Usage:
  uvicorn api:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations
import hashlib
import logging
import os
import tempfile
import time
import uuid
from datetime import datetime
from typing import Optional
from fastapi import FastAPI,File,UploadFile,HTTPException,BackgroundTasks,Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel,Field
logger=logging.getLogger(__name__)



app=FastAPI(
    title="ORACLE-TMF API",
    description=(
        "**Observational Reasoning and Coercive Analysis for Latent Evolution — "
        "Temporal Mutation Forecaster**\n\n"
        "RESTful API for programmatic Android malware mutation analysis. "
        "Upload APKs and receive predictive mutation intelligence, "
        "Bayesian confidence scores, and MITRE ATT&CK technique forecasts."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name":"Saksham Shreyans",
        "url":"https://github.com/Saksham-Shreyans/ORACLE_TMF",
    },
    license_info={
        "name":"MIT License",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



_results_cache:dict[str,dict]={}
_orchestrator=None
def _get_orchestrator():
    """Lazy-load the orchestrator (expensive — trains XGBoost on first init)."""
    global _orchestrator
    if _orchestrator is None:
        from orchestrator import ORACLETMFOrchestrator
        _orchestrator=ORACLETMFOrchestrator()
    return _orchestrator



class HealthResponse(BaseModel):
    """System health check response."""
    status:str="healthy"
    version:str="2.0.0"
    timestamp:str=""
    components:dict={}
class AnalysisSubmission(BaseModel):
    """Response when an analysis is submitted."""
    analysis_id:str
    status:str
    message:str
    submitted_at:str
class ForecastSummary(BaseModel):
    """Compact forecast representation for API responses."""
    predicted_tactic:str=""
    predicted_technique:str=""
    technique_name:str=""
    confidence_score:float=0.0
    confidence_ci_low:float=0.0
    confidence_ci_high:float=0.0
    passes_gate:bool=False
    target_institutions:list[str]=[]
    target_countries:list[str]=[]
class AnalysisResponse(BaseModel):
    """Full analysis result response."""
    analysis_id:str
    status:str
    apk_sha256:str=""
    package_name:str=""
    malware_family:str=""
    total_artifacts:int=0
    artifact_counts:dict={}
    forecasts:list[ForecastSummary]=[]
    high_confidence_count:int=0
    robustness_summary:str=""
    analysis_time_ms:float=0.0
    stage_errors:dict={}
    full_mag:dict={}



@app.get("/health",response_model=HealthResponse,tags=["System"])
async def health_check():
    """
    System health check.
    Returns the system status, version, and component availability.
    """
    components={
        "orchestrator":_orchestrator is not None,
        "anthropic_key_set":bool(os.getenv("ANTHROPIC_API_KEY","")),
    }
    
    try:
        import xgboost
        components["xgboost"]=True
    except ImportError:
        components["xgboost"]=False
    try:
        import shap
        components["shap"]=True
    except ImportError:
        components["shap"]=False
    try:
        import chromadb
        components["chromadb"]=True
    except ImportError:
        components["chromadb"]=False
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        timestamp=datetime.utcnow().isoformat()+"Z",
        components=components,
    )
@app.post("/analyze",response_model=AnalysisSubmission,tags=["Analysis"])
async def analyze_apk(
    background_tasks:BackgroundTasks,
    apk_file:UploadFile=File(...,description="Android APK file to analyze"),
    prev_apk_file:Optional[UploadFile]=File(None,description="Previous version APK (optional)"),
    skip_llm:bool=Query(False,description="Skip LLM agents (static-only analysis)"),
    run_robustness:bool=Query(True,description="Run adversarial robustness test"),
):
    """
    Submit an APK for mutation analysis.
    The analysis runs synchronously and returns a full result.
    For large APKs (>50MB), consider using async mode.
    **Required**: APK file (max 100 MB)
    **Optional**: Previous version APK for version diff (MVV computation)
    """
    
    if not apk_file.filename or not apk_file.filename.endswith(".apk"):
        raise HTTPException(status_code=400,detail="File must be an .apk file")
    
    apk_bytes=await apk_file.read()
    if len(apk_bytes)>100*1024*1024:
        raise HTTPException(status_code=413,detail="APK exceeds 100 MB limit")
    if len(apk_bytes)<1024:
        raise HTTPException(status_code=400,detail="APK too small (< 1 KB)")
    
    sha256=hashlib.sha256(apk_bytes).hexdigest()
    analysis_id=f"{sha256[:12]}_{uuid.uuid4().hex[:8]}"
    
    prev_bytes=None
    if prev_apk_file:
        prev_bytes=await prev_apk_file.read()
    
    try:
        result_dict=_run_analysis(
            analysis_id,apk_bytes,prev_bytes,skip_llm,run_robustness
        )
        _results_cache[analysis_id]=result_dict
        return AnalysisSubmission(
            analysis_id=analysis_id,
            status="completed",
            message=f"Analysis complete. Retrieve results at GET /results/{analysis_id}",
            submitted_at=datetime.utcnow().isoformat()+"Z",
        )
    except Exception as exc:
        raise HTTPException(status_code=500,detail=f"Analysis failed: {str(exc)}")
@app.get("/results/{analysis_id}",response_model=AnalysisResponse,tags=["Analysis"])
async def get_results(analysis_id:str):
    """
    Retrieve analysis results by ID.
    Returns the full analysis result including:
    - APK metadata
    - Artifact counts across all 7 classes
    - Mutation forecasts with Bayesian confidence scores and Monte Carlo CIs
    - Adversarial robustness summary
    - Full MAG (Mutation Artifact Graph)
    """
    if analysis_id not in _results_cache:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis '{analysis_id}' not found. Submit an APK via POST /analyze first.",
        )
    return AnalysisResponse(**_results_cache[analysis_id])
@app.get("/results",tags=["Analysis"])
async def list_results():
    """List all cached analysis result IDs."""
    return{
        "count":len(_results_cache),
        "analysis_ids":list(_results_cache.keys()),
    }



def _run_analysis(
    analysis_id:str,
    apk_bytes:bytes,
    prev_bytes:Optional[bytes],
    skip_llm:bool,
    run_robustness:bool,
)->dict:
    """Run the ORACLE-TMF pipeline and return a structured result dict."""
    orch=_get_orchestrator()
    with tempfile.TemporaryDirectory()as tmp:
        apk_path=os.path.join(tmp,"target.apk")
        with open(apk_path,"wb")as fh:
            fh.write(apk_bytes)
        prev_path=None
        if prev_bytes:
            prev_path=os.path.join(tmp,"prev.apk")
            with open(prev_path,"wb")as fh:
                fh.write(prev_bytes)
        result=orch.analyze(
            apk_path,
            prev_apk_path=prev_path,
            skip_llm=skip_llm,
            skip_report=True,
            run_robustness_test=run_robustness,
        )
    mag=result.mag
    meta=mag.apk_metadata
    
    forecast_summaries=[]
    for f in mag.forecasts:
        forecast_summaries.append({
            "predicted_tactic":f.predicted_tactic,
            "predicted_technique":f.predicted_technique,
            "technique_name":f.technique_name,
            "confidence_score":f.confidence_score,
            "confidence_ci_low":f.confidence_ci_low,
            "confidence_ci_high":f.confidence_ci_high,
            "passes_gate":f.passes_gate,
            "target_institutions":f.predicted_target_institutions,
            "target_countries":f.predicted_target_countries,
        })
    robustness_summary=""
    if mag.robustness_metrics and isinstance(mag.robustness_metrics,dict):
        robustness_summary=mag.robustness_metrics.get("summary","")
    return{
        "analysis_id":analysis_id,
        "status":"completed"if result.success else "failed",
        "apk_sha256":meta.sha256,
        "package_name":meta.package_name,
        "malware_family":mag.malware_family,
        "total_artifacts":mag.total_artifact_count(),
        "artifact_counts":mag.artifact_class_counts(),
        "forecasts":forecast_summaries,
        "high_confidence_count":len(mag.high_confidence_forecasts()),
        "robustness_summary":robustness_summary,
        "analysis_time_ms":result.total_time_ms,
        "stage_errors":mag.stage_errors,
        "full_mag":mag.to_dict(),
    }



@app.on_event("startup")
async def startup_event():
    """Pre-warm the orchestrator on startup."""
    logger.info("[API] ORACLE-TMF API v2.0 starting...")
    
if __name__=="__main__":
    import uvicorn
    uvicorn.run("api:app",host="0.0.0.0",port=8000,reload=True)
