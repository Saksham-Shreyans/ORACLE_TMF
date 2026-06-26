# 🔮 ORACLE-TMF (Temporal Mutation Forecaster)

Observational Reasoning and Coercive Analysis for Latent Evolution.

**ORACLE-TMF** is an advanced malware analysis pipeline and forecasting engine designed to extract mutation artifacts from Android APKs and predict their next evolutionary steps.

## Features

### 🔬 Mutation Artifact Extraction
ORACLE-TMF employs a 12-stage pipeline to dissect Android applications and extract subtle artifacts across a 7-Class Taxonomy:
1. **Dead Code / Unreachable Methods**: Detects unexecuted Smali paths and classifies them via the Dormancy Taxonomy Classification (DTE) engine (e.g., Scaffolding vs. Logic Bomb).
2. **Unused Permission Intents**: Identifies permissions that are requested but never utilized by the application's components.
3. **Placeholder Strings & Resources**: Highlights high-entropy or anomalous placeholder strings often left behind during malware development.
4. **C2 Endpoint Stubs**: Extracts orphaned or inactive Command & Control endpoints.
5. **Partial API Implementations**: Detects incomplete API interfaces that hint at future capabilities.
6. **Unfinished UI Flows**: Spots orphaned UI layouts (e.g., hidden phishing screens).
7. **GenAI API Scaffolds (TMF-Psi)**: Detects AI-augmented malware scaffolds, indicating the use of Generative AI tools by the malware authors.

### 🧠 LLM Multi-Agent Reasoning
The LLM Reasoning Engine analyzes the gathered artifacts to produce chain-of-thought rationales about the malware's evolution, pinpointing techniques, tactics, and targeted institutions/geographies.

### 🎯 Evolutionary Mutation Forecasts
- **Evolutionary Timeline**: Visualizes the historical (v_n-1), current (v_n), and predicted next version (v_n+1) of the malware.
- **Bayesian Confidence Scoring**: Computes a confidence score for each prediction based on LLM probability, artifact density, and prior probabilities, filtering out low-confidence guesses.

### 📤 Export & Integration
Seamlessly export the intelligence products for further analysis or SOC integration:
- **JSON Report**: Comprehensive Mutation Artifact Graph (MAG) and executive summary.
- **YARA Rules**: Proactive detection signatures generated for the predicted v_n+1.
- **STIX 2.1 Bundle**: TAXII-compatible threat intelligence feed.
- **PDF Intelligence Brief**: Human-readable report for SOC analysts.

## Setup and Usage

1. **Install dependencies**:
   Ensure you have all the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Streamlit Dashboard**:
   ```bash
   streamlit run app.py
   ```

3. **Analysis Workflow**:
   - Open the web interface.
   - Upload the **Target APK** (v_n).
   - *(Optional)* Upload the **Previous Version APK** (v_n-1) to enable version diffing.
   - Choose the deobfuscation level.
   - Run the analysis.

## Pipeline Architecture
The ORACLE-TMF architecture runs through the following sequences:
`A (Ingestion) → B (Disassembly) → TMF-REFLECT → C (Manifest) → D (Dead Code) → DTE → E (Perms) → F (Strings) → G (C2) → H (Partial APIs) → GenAI → UI → Targeting → I (Version Diff) → J (LLM Reasoning) → K (Bayesian) → L (Report)`

Each stage is completely isolated, ensuring that a failure in one specific analysis task (e.g., missing dependencies) allows the rest of the pipeline to continue running safely.
