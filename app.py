"""
ORACLE-TMF  ·  app.py
=======================
Streamlit Frontend Dashboard
Provides the visual interface for ORACLE-TMF analysts:
  Left Sidebar  : APK file uploader, previous version uploader,
                  deobfuscation level selector, analysis trigger button
  Tab 1 (Overview)   : APK metadata card, 7-class artifact gauges,
                        forecast confidence summary
  Tab 2 (Artifacts)  : Expandable sections for all 7 artifact classes.
                        Dead Code shows Smali + Agent 1 pseudo-Java side by side.
                        DTE labels colour-coded (SCAFFOLDING=blue, LOGIC_BOMB=red)
  Tab 3 (Forecasts)  : "Evolutionary Mutation Timeline" — the wow factor.
                        v_n-1 (Past) → v_n (Present) → v_n+1 (Predicted).
                        Per-forecast confidence breakdown + MITRE mapping.
  Tab 4 (Export)     : Download buttons for JSON, YARA, STIX 2.1, PDF brief
Run:
  streamlit run app.py
"""
from __future__ import annotations
import json
import os
import sys
import tempfile
import time
from pathlib import Path
import streamlit as st

st.set_page_config(
    page_title="ORACLE-TMF",
    page_icon="🔮",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    /* Core dark palette */
    .stApp { background-color: #0d0d1a; color: #e8e8f0; }
    .stSidebar { background-color: #111128; border-right: 1px solid #1e1e3a; }
    .stTabs [data-baseweb="tab-list"] { background-color: #111128; border-bottom: 2px solid #00f5ff33; }
    .stTabs [data-baseweb="tab"] { color: #8888aa; font-weight: 600; padding: 10px 20px; }
    .stTabs [aria-selected="true"] { color: #00f5ff !important; border-bottom: 2px solid #00f5ff; }
    .stButton > button { background-color: #003366; color: #00f5ff; border: 1px solid #00f5ff;
                         border-radius: 6px; font-weight: 700; letter-spacing: 0.05em; }
    .stButton > button:hover { background-color: #00f5ff; color: #0d0d1a; }
    .stExpander { background-color: #111128; border: 1px solid #1e1e3a; border-radius: 8px; }
    .stMetric { background-color: #111128; border-radius: 8px; padding: 12px;
                border: 1px solid #1e1e3a; }
    div[data-testid="stMetricValue"] { color: #00f5ff; font-size: 2rem; }
    div[data-testid="stMetricLabel"] { color: #8888aa; }
    /* Artifact class colour chips */
    .chip-scaffolding { background: #003380; color: #5588ff; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
    .chip-logic_bomb  { background: #400000; color: #ff5555; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
    .chip-dropper     { background: #402000; color: #ff9933; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
    .chip-remnant     { background: #1a1a2e; color: #666688; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
    /* Forecast card */
    .forecast-card { background: #0d1a0d; border: 1px solid #00ff6444; border-radius: 10px;
                     padding: 16px; margin-bottom: 12px; }
    .confidence-label { color: #00ff64; font-size: 24px; font-weight: 800; }
    code { background-color: #1a1a2e; color: #00f5ff; padding: 2px 6px; border-radius: 4px; }
    /* Headers */
    h1 { color: #00f5ff; letter-spacing: -0.02em; }
    h2 { color: #ccddff; }
    h3 { color: #aabbdd; }
</style>
""",unsafe_allow_html=True)

try:
    import plotly.graph_objects as go
    _PLOTLY_OK=True
except ImportError:
    _PLOTLY_OK=False
try:
    from orchestrator import ORACLETMFOrchestrator,AnalysisResult
    _ORCH_OK=True
except ImportError:
    _ORCH_OK=False



@st.cache_resource(show_spinner="Initialising ORACLE-TMF pipeline…")
def get_orchestrator():
    """Single orchestrator instance shared across Streamlit sessions."""
    if not _ORCH_OK:
        return None
    return ORACLETMFOrchestrator()
@st.cache_data(show_spinner=False,max_entries=10)
def run_analysis_cached(apk_bytes:bytes,prev_bytes:bytes|None,skip_llm:bool):
    """
    Run the pipeline and cache the result by APK content hash.
    Returns (AnalysisResult, error_str).
    """
    orch=get_orchestrator()
    if orch is None:
        return None,"Orchestrator could not be initialised (check dependencies)"
    with tempfile.TemporaryDirectory()as tmp:
        apk_path=os.path.join(tmp,"target.apk")
        with open(apk_path,"wb")as fh:
            fh.write(apk_bytes)
        prev_path=None
        if prev_bytes:
            prev_path=os.path.join(tmp,"prev.apk")
            with open(prev_path,"wb")as fh:
                fh.write(prev_bytes)
        try:
            result=orch.analyze(
                apk_path,
                prev_apk_path=prev_path,
                skip_llm=skip_llm,
                skip_report=False,
            )
            return result,""
        except Exception as exc:
            return None,str(exc)



def render_sidebar()->tuple:
    """Render the sidebar and return (uploaded_apk, prev_apk, deobf, skip_llm, run_pressed)."""
    with st.sidebar:
        st.markdown("## 🔮 ORACLE-TMF")
        st.markdown(
            "<small style='color:#8888aa'>Temporal Mutation Forecaster<br>"
            "PSB CyberShield 2026</small>",
            unsafe_allow_html=True,
        )
        st.divider()
        uploaded=st.file_uploader(
            "📦 Upload Target APK",
            type=["apk"],
            help="Android APK file (max 100 MB)",
        )
        prev_uploaded=st.file_uploader(
            "📦 Previous Version (optional)",
            type=["apk"],
            help="Upload v_n-1 to enable Stage I version diff and MVV",
        )
        st.divider()
        deobf=st.select_slider(
            "🔓 Deobfuscation Level",
            options=["None","Fast","Deep"],
            value="Fast",
            help="None=raw Smali, Fast=TMF-REFLECT only, Deep=TMF-REFLECT+Frida hooks",
        )
        skip_llm=st.checkbox(
            "⚡ Static Only (skip LLM agents)",
            value=False,
            help="Run stages A-H only. Much faster, no API costs, no forecasts.",
        )
        st.divider()
        run_btn=st.button(
            "🔍  ANALYZE APK",
            type="primary",
            use_container_width=True,
            disabled=(uploaded is None),
        )
        st.divider()
        st.markdown(
            "<small style='color:#555577'>"
            "ORACLE-TMF v1.0.0<br>"
            "© 2026 Saksham Shreyans et al.<br>"
            "RGIPT · PSB CyberShield</small>",
            unsafe_allow_html=True,
        )
    return uploaded,prev_uploaded,deobf,skip_llm,run_btn



def render_overview(result):
    mag=result.mag
    
    st.markdown("### 📋 APK Intelligence Card")
    m=mag.apk_metadata
    col_a,col_b,col_c=st.columns(3)
    with col_a:
        st.metric("Package Name",m.package_name or "—")
        st.metric("Version",f"{m.version_name} (code {m.version_code})"if m.version_name else "—")
        st.metric("Family",mag.malware_family or "UNKNOWN")
    with col_b:
        st.metric("SHA-256 (first 16)",m.sha256[:16]+"…"if m.sha256 else "—")
        st.metric("File Size",f"{m.file_size_bytes/1024:.1f} KB"if m.file_size_bytes else "—")
        st.metric("Packed?","⚠️ YES — "+m.packer_hint if m.is_packed else "No")
    with col_c:
        st.metric("Min SDK",str(m.min_sdk)if m.min_sdk else "—")
        st.metric("Target SDK",str(m.target_sdk)if m.target_sdk else "—")
        st.metric("Analysis Time",f"{result.total_time_ms/1000:.1f} s")
    st.divider()
    
    st.markdown("### 🔬 Mutation Artifact Inventory — 7-Class Taxonomy")
    counts=mag.artifact_class_counts()
    labels=[
        ("CLASS 1\nDead Code","dead_code","#5588ff"),
        ("CLASS 2\nUnused Perms","unused_permissions","#ff9933"),
        ("CLASS 3\nPlaceholders","placeholder_strings","#ffcc00"),
        ("CLASS 4\nC2 Stubs","c2_stubs","#ff4444"),
        ("CLASS 5\nPartial APIs","partial_apis","#aa44ff"),
        ("CLASS 6\nUnfinished UI","unfinished_ui_flows","#44ddaa"),
        ("CLASS 7\nGenAI Scaffolds","genai_scaffolds","#ff66cc"),
    ]
    gauge_cols=st.columns(7)
    for col,(label,cls_key,color)in zip(gauge_cols,labels):
        
        mapping={
            "dead_code":len(mag.dead_code),
            "unused_permissions":len(mag.unused_permissions),
            "placeholder_strings":len(mag.placeholder_strings),
            "c2_stubs":len(mag.c2_stubs),
            "partial_apis":len(mag.partial_apis),
            "unfinished_ui_flows":len(mag.unfinished_ui_flows),
            "genai_scaffolds":len(mag.genai_scaffolds),
        }
        val=mapping.get(cls_key,0)
        with col:
            if _PLOTLY_OK:
                fig=_make_gauge(val,max(val+5,20),label,color)
                st.plotly_chart(fig,use_container_width=True,config={"displayModeBar":False})
            else:
                st.metric(label.replace("\n"," "),val)
    
    passed=mag.high_confidence_forecasts()
    st.divider()
    if passed:
        best=passed[0]
        st.success(
            f"🎯 **{len(passed)} High-Confidence Forecast(s) Generated**  |  "
            f"Top prediction: **{best.predicted_technique}** ({best.technique_name})  |  "
            f"Confidence: **{best.confidence_score:.3f}**"
        )
    elif mag.forecasts:
        st.warning(
            f"⚠️ {len(mag.forecasts)} forecast(s) generated but confidence < "
            f"{0.72} gate threshold. Consider enriching the RAG knowledge base."
        )
    else:
        st.info("ℹ️ No LLM forecasts generated. Run with LLM enabled for predictions.")
    
    if mag.stage_errors:
        with st.expander(f"⚠️ {len(mag.stage_errors)} Stage Error(s)",expanded=False):
            for stage,err in mag.stage_errors.items():
                st.error(f"**{stage}**: {err}")



def render_artifacts(result):
    mag=result.mag
    st.markdown("### 🔬 Detected Mutation Artifacts")
    
    with st.expander(f"🔵 CLASS 1 — Dead Code / Unreachable Methods  ({len(mag.dead_code)})",expanded=bool(mag.dead_code)):
        if not mag.dead_code:
            st.info("No dead code artifacts detected.")
        else:
            for i,a in enumerate(mag.dead_code[:20],1):
                dte_chip=_dte_chip(a.dte_label.value if hasattr(a.dte_label,"value")else str(a.dte_label))
                st.markdown(
                    f"**#{i}** `{a.class_name}` → `{a.method_name[:60]}`  "
                    f"{dte_chip}  conf={a.dte_confidence:.2f}  opcodes={a.opcode_count}",
                    unsafe_allow_html=True,
                )
                col_smali,col_java=st.columns(2)
                with col_smali:
                    st.markdown("**Smali (raw)**")
                    st.code(a.smali_code[:800]if a.smali_code else "(not available)",language="text")
                with col_java:
                    st.markdown("**Pseudo-Java (Agent 1)**")
                    st.code(a.pseudo_java[:800]if a.pseudo_java else "(run with LLM enabled)",language="java")
                st.divider()
    
    with st.expander(f"🟠 CLASS 2 — Unused Permission Intents  ({len(mag.unused_permissions)})",expanded=bool(mag.unused_permissions)):
        if not mag.unused_permissions:
            st.info("No unused permission artifacts detected.")
        else:
            data=[{"Permission":a.permission_name,"Group":a.android_permission_group,"Context":a.context_note[:80]}
                    for a in mag.unused_permissions]
            st.table(data)
    
    with st.expander(f"🟡 CLASS 3 — Placeholder Strings & Resources  ({len(mag.placeholder_strings)})",expanded=False):
        if not mag.placeholder_strings:
            st.info("No placeholder string artifacts detected.")
        else:
            for a in mag.placeholder_strings[:15]:
                st.code(f'[{a.matched_pattern or "high-entropy"}] entropy={a.entropy:.2f}  "{a.value[:100]}"',language="text")
    
    with st.expander(f"🔴 CLASS 4 — C2 Endpoint Stubs  ({len(mag.c2_stubs)})",expanded=bool(mag.c2_stubs)):
        if not mag.c2_stubs:
            st.info("No C2 stub artifacts detected.")
        else:
            for a in mag.c2_stubs[:10]:
                st.markdown(f"**Class**: `{a.class_name}`  **Framework**: `{a.framework}`")
                if a.extracted_url:
                    st.markdown(f"🌐 **URL**: `{a.extracted_url}`")
                if a.http_method:
                    st.markdown(f"📡 **Method**: `{a.http_method}`")
                st.divider()
    
    with st.expander(f"🟣 CLASS 5 — Partial API Implementations  ({len(mag.partial_apis)})",expanded=False):
        if not mag.partial_apis:
            st.info("No partial API artifacts detected.")
        else:
            for a in mag.partial_apis:
                st.markdown(
                    f"**Class**: `{a.class_name}`  "
                    f"**Extends**: `{a.interface_extended.split('/')[-1]}`  "
                    f"**Stubs**: `{'`, `'.join(a.method_stubs)}`"
                )
    
    with st.expander(f"🟢 CLASS 6 — Unfinished UI Flows  ({len(mag.unfinished_ui_flows)})",expanded=bool(mag.unfinished_ui_flows)):
        if not mag.unfinished_ui_flows:
            st.info("No orphaned UI layout artifacts detected.")
        else:
            for a in mag.unfinished_ui_flows:
                color="🔴"if "phishing"in a.suspected_type or "credential"in a.suspected_type else "🟡"
                st.markdown(
                    f"{color} `{a.layout_file}`  **Type**: `{a.suspected_type}`  "
                    f"**Assets**: `{', '.join(a.asset_refs[:3])}`"
                )
    
    with st.expander(f"🌸 CLASS 7 — GenAI API Scaffolds (TMF-Psi)  ({len(mag.genai_scaffolds)})",expanded=bool(mag.genai_scaffolds)):
        if not mag.genai_scaffolds:
            st.info("No GenAI API scaffold artifacts detected.")
        else:
            for a in mag.genai_scaffolds:
                st.warning(
                    f"⚠️ **AI-Augmented Malware Scaffold Detected!**  "
                    f"Provider: **{a.provider}**  |  Model: `{a.model_hint or 'unknown'}`  "
                    f"|  Endpoint: `{a.api_endpoint[:60]}`"
                )
                st.markdown(f"**Class**: `{a.class_name}` → `{a.method_name[:60]}`")
                st.divider()



def render_forecasts(result):
    mag=result.mag
    st.markdown("### 🎯 Evolutionary Mutation Forecasts")
    
    st.markdown("#### 🌌 Evolutionary Mutation Timeline")
    if _PLOTLY_OK:
        fig=_make_evolutionary_timeline(mag)
        st.plotly_chart(fig,use_container_width=True,config={"displayModeBar":False})
    else:
        st.info("Install plotly for the interactive evolutionary timeline.")
    
    passed=mag.high_confidence_forecasts()
    if not passed:
        if mag.forecasts:
            st.warning(
                "All forecasts scored below the 0.72 confidence gate. "
                "Showing top prediction regardless:"
            )
            passed=mag.forecasts[:1]
        else:
            st.info(
                "No forecasts available. Ensure:\n"
                "• ANTHROPIC_API_KEY is set\n"
                "• 'Static Only' checkbox is unchecked\n"
                "• Artifacts were detected in Stages D/E/G/H"
            )
            return
    for i,f in enumerate(passed,1):
        with st.container():
            st.markdown(
                f"<div class='forecast-card'>",
                unsafe_allow_html=True,
            )
            col_score,col_detail=st.columns([1,3])
            with col_score:
                st.markdown(
                    f"<div class='confidence-label'>C = {f.confidence_score:.3f}</div>",
                    unsafe_allow_html=True,
                )
                color="#00ff64"if f.confidence_score>0.80 else "#ffcc00"if f.confidence_score>0.65 else "#ff4444"
                if _PLOTLY_OK:
                    fig_c=_make_confidence_breakdown(f)
                    st.plotly_chart(fig_c,use_container_width=True,config={"displayModeBar":False})
            with col_detail:
                st.markdown(f"**#{i} Prediction: {f.predicted_technique}**")
                st.markdown(f"🎯 **Tactic**: `{f.predicted_tactic}`  |  **Technique**: `{f.predicted_technique}` — *{f.technique_name}*")
                if f.predicted_target_institutions:
                    st.markdown(f"🏦 **Target Institutions**: {', '.join(f.predicted_target_institutions[:3])}")
                if f.predicted_target_countries:
                    st.markdown(f"🌍 **Target Countries**: {', '.join(f.predicted_target_countries[:5])}")
                if f.rationale:
                    with st.expander("📖 LLM Chain-of-Thought Rationale"):
                        st.markdown(f.rationale[:800])
                st.markdown(
                    f"**Bayesian Decomposition**:  "
                    f"P_LLM={f.p_llm:.3f} × 0.45  +  "
                    f"D={f.artifact_density:.3f} × MVV={f.mvv_normalized:.3f} × 0.35  +  "
                    f"H_prior={f.h_prior:.3f} × 0.20"
                )
            st.markdown("</div>",unsafe_allow_html=True)



def render_export(result):
    mag=result.mag
    bundle=result.report_bundle
    st.markdown("### 📤 Export Intelligence Products")
    col_j,col_y,col_s,col_p=st.columns(4)
    with col_j:
        st.markdown("#### 📄 JSON Report")
        st.markdown("Full MAG + executive summary (SIEM-ready)")
        if bundle and bundle.json_path and os.path.isfile(bundle.json_path):
            with open(bundle.json_path,"rb")as f:
                st.download_button("⬇️ Download JSON",f.read(),"oracle_tmf_report.json","application/json")
        else:
            
            json_data=mag.to_json().encode()
            st.download_button("⬇️ Download MAG JSON",json_data,"oracle_tmf_mag.json","application/json")
    with col_y:
        st.markdown("#### 📋 YARA Rules")
        st.markdown("Proactive detection signatures for v_{n+1}")
        if bundle and bundle.yara_path and os.path.isfile(bundle.yara_path):
            with open(bundle.yara_path,"rb")as f:
                st.download_button("⬇️ Download YARA",f.read(),"oracle_tmf_forecast.yar","text/plain")
        else:
            st.info("YARA file not generated (check Stage L errors)")
    with col_s:
        st.markdown("#### 🌐 STIX 2.1 Bundle")
        st.markdown("TAXII-compatible threat intelligence feed")
        if bundle and bundle.stix_path and os.path.isfile(bundle.stix_path):
            with open(bundle.stix_path,"rb")as f:
                st.download_button("⬇️ Download STIX",f.read(),"oracle_tmf_stix.json","application/json")
        else:
            st.info("STIX file not generated (install stix2: pip install stix2)")
    with col_p:
        st.markdown("#### 📰 PDF Intelligence Brief")
        st.markdown("Human-readable SOC analyst report")
        if bundle and bundle.pdf_path and os.path.isfile(bundle.pdf_path):
            with open(bundle.pdf_path,"rb")as f:
                st.download_button("⬇️ Download PDF",f.read(),"oracle_tmf_brief.pdf","application/pdf")
        else:
            st.info("PDF not generated (install fpdf2: pip install fpdf2)")
    st.divider()
    st.markdown("#### 📊 Pipeline Timing Breakdown")
    if mag.stage_timings_ms:
        if _PLOTLY_OK:
            stages=list(mag.stage_timings_ms.keys())
            times=[mag.stage_timings_ms[s]for s in stages]
            fig=go.Figure(go.Bar(
                x=times,y=stages,orientation="h",
                marker_color=[
                    "#ff4444"if s in mag.stage_errors else "#00f5ff"
                    for s in stages
                ],
            ))
            fig.update_layout(
                title="Stage Wall-Clock Times (ms)",
                paper_bgcolor="#0d0d1a",plot_bgcolor="#111128",
                font={"color":"#e8e8f0"},
                xaxis_title="Milliseconds",
                height=max(300,len(stages)*28),
                margin=dict(l=10,r=10,t=40,b=40),
            )
            st.plotly_chart(fig,use_container_width=True)
        else:
            for s,t in mag.stage_timings_ms.items():
                st.text(f"{s:<25} {t:>8.1f} ms {'❌'if s in mag.stage_errors else '✓'}")



def _make_gauge(value:int,max_val:int,title:str,color:str):
    """Compact gauge chart for a single artifact class."""
    fig=go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text":title,"font":{"color":"#aabbdd","size":9}},
        gauge={
            "axis":{"range":[0,max_val],"tickcolor":"#444466"},
            "bar":{"color":color},
            "bgcolor":"#111128",
            "bordercolor":"#1e1e3a",
            "steps":[{"range":[0,max_val],"color":"#1a1a2e"}],
        },
        number={"font":{"color":color,"size":22}},
    ))
    fig.update_layout(
        height=130,
        margin=dict(l=8,r=8,t=35,b=8),
        paper_bgcolor="#0d0d1a",
        font={"color":"#e8e8f0"},
    )
    return fig
def _make_evolutionary_timeline(mag):
    """
    The Wow Factor — Evolutionary Mutation Timeline.
    Three nodes connected by a dotted arrow:
      v_n-1 (Historical/dim)  →  v_n (Current/bright)  →  v_n+1 (Predicted/glowing)
    """
    fig=go.Figure()
    
    fig.update_layout(
        paper_bgcolor="#0d0d1a",
        plot_bgcolor="#0d0d1a",
        height=320,
        margin=dict(l=30,r=30,t=60,b=40),
        title=dict(text="⟨ Evolutionary Mutation Timeline ⟩",font=dict(color="#00f5ff",size=14),x=0.5),
        showlegend=False,
        xaxis=dict(range=[-0.7,2.7],showgrid=False,zeroline=False,showticklabels=False),
        yaxis=dict(range=[-1.2,1.8],showgrid=False,zeroline=False,showticklabels=False),
    )
    
    for x0,x1 in[(0.15,0.85),(1.15,1.85)]:
        fig.add_shape(type="line",x0=x0,y0=0,x1=x1,y1=0,
                      line=dict(color="#00f5ff55",width=2,dash="dot"))
        fig.add_annotation(x=x1,y=0,xref="x",yref="y",
                           showarrow=True,arrowhead=2,arrowcolor="#00f5ff88",
                           arrowsize=1.5,arrowwidth=2,ax=-20,ay=0)
    
    fig.add_trace(go.Scatter(
        x=[0],y=[0],mode="markers",
        marker=dict(size=90,color="rgba(40,40,80,0.6)",line=dict(color="#33336688",width=3)),
        hovertemplate="<b>v_n-1</b><br>Historical baseline<extra></extra>",
    ))
    fig.add_annotation(x=0,y=0,text="<b>v_n-1</b><br><span style='font-size:10px;color:#666688'>Historical</span>",
                       showarrow=False,font=dict(color="#8888bb",size=12),yshift=0)
    fig.add_annotation(x=0,y=-0.85,text="<span style='font-size:9px;color:#555577'>Previous Version</span>",
                       showarrow=False,font=dict(color="#555577",size=9))
    
    total_arts=mag.total_artifact_count()
    family=mag.malware_family or "UNKNOWN"
    fig.add_trace(go.Scatter(
        x=[1],y=[0],mode="markers",
        marker=dict(size=115,color="rgba(0,40,100,0.8)",line=dict(color="#00f5ff",width=5)),
        hovertemplate=(
            f"<b>v_n — {family}</b><br>"
            f"Total artifacts: {total_arts}<br>"
            f"Dead code: {len(mag.dead_code)}<br>"
            f"Unused perms: {len(mag.unused_permissions)}<br>"
            f"C2 stubs: {len(mag.c2_stubs)}<extra></extra>"
        ),
    ))
    fig.add_annotation(x=1,y=0,text=f"<b>v_n</b><br><span style='font-size:10px'>{family}</span>",
                       showarrow=False,font=dict(color="#00f5ff",size=13))
    fig.add_annotation(x=1,y=-0.85,
                       text=f"<span style='font-size:9px;color:#00f5ff88'>{total_arts} artifacts</span>",
                       showarrow=False,font=dict(color="#00f5ff88",size=9))
    
    passed=mag.high_confidence_forecasts()
    if passed:
        fc=passed[0]
        tech_short=fc.predicted_technique
        conf_txt=f"C={fc.confidence_score:.2f}"
        hover_txt=(
            f"<b>v_n+1 — PREDICTED</b><br>"
            f"Technique: {tech_short}<br>"
            f"{fc.technique_name}<br>"
            f"Confidence: {fc.confidence_score:.3f}<br>"
            f"Tactic: {fc.predicted_tactic}<extra></extra>"
        )
        node_text=f"<b>v_n+1</b><br><span style='font-size:10px'>{tech_short}</span>"
        node_color="rgba(0,80,20,0.5)"
        line_color="#00ff64"
        anno_color="#00ff64"
        sub_text=f"<span style='font-size:9px;color:#00ff6488'>{conf_txt} ✓ FORECAST</span>"
    else:
        hover_txt="<b>v_n+1</b><br>No high-confidence forecast<extra></extra>"
        node_text="<b>v_n+1</b><br><span style='font-size:10px;color:#555577'>Pending</span>"
        node_color="rgba(30,30,50,0.5)"
        line_color="#444466"
        anno_color="#666688"
        sub_text="<span style='font-size:9px;color:#444466'>Run LLM for forecast</span>"
    fig.add_trace(go.Scatter(
        x=[2],y=[0],mode="markers",
        marker=dict(size=115,color=node_color,line=dict(color=line_color,width=5)),
        hovertemplate=hover_txt,
    ))
    fig.add_annotation(x=2,y=0,text=node_text,showarrow=False,
                       font=dict(color=anno_color,size=13))
    fig.add_annotation(x=2,y=-0.85,text=sub_text,showarrow=False,
                       font=dict(color=anno_color,size=9))
    
    for x_pos,label in[(0,"v_n-1"),(1,"v_n ← You Are Here"),(2,"v_n+1 ← PREDICTED")]:
        fig.add_annotation(x=x_pos,y=1.35,text=f"<span style='font-size:8px'>{label}</span>",
                           showarrow=False,font=dict(color="#555577",size=8))
    return fig
def _make_confidence_breakdown(fc):
    """Horizontal bar chart showing Bayesian confidence components."""
    components=["P_LLM × 0.45","D × MVV × 0.35","H_prior × 0.20"]
    values=[
        fc.p_llm*0.45,
        fc.artifact_density*fc.mvv_normalized*0.35,
        fc.h_prior*0.20,
    ]
    colors=["#5588ff","#ff9933","#44ddaa"]
    fig=go.Figure(go.Bar(
        x=values,y=components,orientation="h",
        marker_color=colors,text=[f"{v:.3f}"for v in values],
        textposition="outside",textfont=dict(color="#e8e8f0",size=10),
    ))
    fig.update_layout(
        paper_bgcolor="#0d0d1a",plot_bgcolor="#111128",
        height=140,margin=dict(l=5,r=50,t=10,b=5),
        xaxis=dict(range=[0,0.55],showgrid=False,color="#666688"),
        yaxis=dict(color="#8888aa"),
        font=dict(color="#e8e8f0",size=9),
    )
    return fig



def _dte_chip(label:str)->str:
    """Return coloured HTML chip for a DTE classification label."""
    cls_map={
        "SCAFFOLDING":"chip-scaffolding",
        "LOGIC_BOMB":"chip-logic_bomb",
        "ENCRYPTED_DROPPER":"chip-dropper",
        "REMNANT":"chip-remnant",
    }
    css=cls_map.get(label,"chip-remnant")
    return f'<span class="{css}">{label}</span>'



def main()->None:
    
    st.markdown(
        "<h1 style='text-align:center;letter-spacing:-0.03em;'>🔮 ORACLE-TMF</h1>"
        "<p style='text-align:center;color:#8888aa;margin-top:-12px;'>"
        "Observational Reasoning and Coercive Analysis for Latent Evolution — "
        "Temporal Mutation Forecaster</p>",
        unsafe_allow_html=True,
    )
    
    uploaded,prev_uploaded,deobf,skip_llm,run_btn=render_sidebar()
    
    if "analysis_result"not in st.session_state:
        st.session_state.analysis_result=None
    if "analysis_error"not in st.session_state:
        st.session_state.analysis_error=""
    
    if run_btn and uploaded:
        apk_bytes=uploaded.read()
        prev_bytes=prev_uploaded.read()if prev_uploaded else None
        with st.spinner(f"⚙️ Running ORACLE-TMF 12-stage pipeline…  (deobf={deobf})"):
            result,err=run_analysis_cached(apk_bytes,prev_bytes,skip_llm)
        st.session_state.analysis_result=result
        st.session_state.analysis_error=err
        if err:
            st.error(f"Analysis failed: {err}")
        elif result and result.success:
            st.success(f"✅ Analysis complete in {result.total_time_ms/1000:.1f}s")
    
    result=st.session_state.analysis_result
    if result is None:
        st.markdown(
            "<div style='text-align:center;padding:80px;color:#444466;'>"
            "<h2>Upload an APK and click Analyze to begin</h2>"
            "<p>ORACLE-TMF will extract mutation artifacts and forecast the next malware version</p>"
            "</div>",
            unsafe_allow_html=True,
        )
        return
    
    tab_overview,tab_artifacts,tab_forecasts,tab_export=st.tabs([
        "📊 Overview","🔬 Artifacts","🎯 Forecasts","📤 Export",
    ])
    with tab_overview:
        render_overview(result)
    with tab_artifacts:
        render_artifacts(result)
    with tab_forecasts:
        render_forecasts(result)
    with tab_export:
        render_export(result)
if __name__=="__main__":
    main()
