# ORACLE-TMF Stage 2 — Integration Guide

## Overview

Stage 2 extends the Stage 1 static-analysis pipeline (Stages A–L) with six
new analytical layers drawn from the project PowerPoint Tiers 2 and 3.
Every Stage 2 component is **additive and optional** — Stage 1 continues
to operate independently, and Stage 2 engine failures are isolated so they
never block the core pipeline.

---

## File Layout

```
oracle_stage2/                         ← Drop into ORACLE_TMF root
├── config/
│   └── stage2_settings.py             ← All Stage 2 constants (no magic numbers elsewhere)
├── models/
│   └── nav_models.py                  ← NAV data structures
├── engines/
│   └── nav/
│       └── nav_engine.py              ← Negative Artifact Vector engine
├── phantom/                           ← PHANTOM Active Deception Engine
│   ├── deception_engine.py
│   ├── device_persona.py
│   ├── honeytoken_generator.py
│   ├── sensory_emulation.py
│   ├── behavioral_biometrics.py
│   └── frida_bypass/
│       ├── bypass_controller.py
│       └── scripts/                   ← Frida JS hook templates
│           ├── manufacturer_hook.js
│           ├── adb_hook.js
│           ├── sensor_hook.js
│           └── country_hook.js
├── research/
│   ├── cabal/
│   │   └── collusion_engine.py        ← Cross-App Collusion Forecasting
│   ├── kinship/
│   │   └── builder_dna.py             ← Builder DNA Fingerprinting
│   ├── mirage/
│   │   └── adversarial_optimizer.py   ← Adversarial Robustness Analysis
│   ├── ouroboros/
│   │   └── coevolution_loop.py        ← Closed-Loop Co-Evolution
│   ├── synthetic_variant/
│   │   └── variant_generator.py       ← Synthetic V(N+1) Test Fixtures
│   └── network_attack/
│       └── ddos_analyzer.py           ← DDoS/ANC Signature Detection
├── pipeline/
│   └── stage2/
│       ├── stage_m_phantom_detonation.py
│       ├── stage_n_nav_analysis.py
│       ├── stage_o_cabal_analysis.py
│       ├── stage_p_kinship_fingerprint.py
│       ├── stage_q_mirage_robustness.py
│       └── stage_r_ouroboros_coevolution.py
├── orchestrator_stage2.py             ← Main entry point
├── requirements_stage2.txt
└── tests/stage2/
    ├── test_nav_engine.py
    ├── test_phantom_components.py
    ├── test_research_engines.py
    └── test_orchestrator_stage2.py
```

---

## Quick Start

### 1. Install Stage 2 dependencies

```bash
pip install -r requirements_stage2.txt
```

### 2. Run Stage 2 after Stage 1

```python
from orchestrator import run_stage1          # Existing Stage 1 orchestrator
from orchestrator_stage2 import Stage2Orchestrator, Stage2Config

# --- Stage 1 (existing pipeline) ---
mag, forecasts = run_stage1("malware.apk")

# --- Stage 2 (new) ---
cfg = Stage2Config(
    nav_enabled=True,          # Always recommended
    kinship_enabled=True,      # Builder attribution
    mirage_enabled=True,       # Pipeline robustness
    network_attack_enabled=True,   # DDoS detection
    phantom_enabled=False,     # Requires controlled lab environment
    cabal_enabled=False,       # Enable when analysing multi-APK sets
    ouroboros_enabled=False,   # Research/training mode only
    save_json_reports=True,    # Write Stage 2 JSON to stage2_output/
)

orch = Stage2Orchestrator(cfg)
report = orch.run(
    mag=mag,
    forecasts=forecasts,
    mag_prev=mag_previous_version,  # Optional: enables NAV analysis
)

print(report.to_dict())
```

### 3. Multi-APK collusion analysis (CABAL)

```python
cfg = Stage2Config(cabal_enabled=True, nav_enabled=True)
orch = Stage2Orchestrator(cfg)

mag_list = [mag_apk_a, mag_apk_b, mag_apk_c]
report = orch.run(
    mag=mag_apk_a,
    mag_list=mag_list,     # Pass all APKs for CABAL
    forecasts=forecasts,
)
print(f"Collusion paths found: {report.collusion_paths_found}")
```

### 4. Builder attribution (KINSHIP)

```python
# With a corpus of known-attributed MAGs:
report = orch.run(
    mag=unknown_mag,
    corpus_mags=known_attributed_mag_list,
)
if report.builder_cluster_id >= 0:
    print(f"Attributed to builder cluster {report.builder_cluster_id}")
```

---

## Stage-by-Stage Reference

### Stage N — Negative Artifact Vectors (NAV)

**Runs when**: `nav_enabled=True` AND `mag_prev` is provided.

**What it does**: Detects artifact *disappearance* between consecutive versions.
When `dead_code` count drops from 8 to 0 between v_n-1 and v_n, the developer
abandoned that development path and the forecast redirects to the alternative.

**Integration with Stage K**: The `nav_adjustment` value (±0.10 max) is added
to every Stage K forecast `confidence_score`. A genuine NAV event boosts the
redirected technique's confidence; a NAV-MIRAGE suspect reduces all confidence.

**Output keys in report**:
```python
report.stage_n.nav_result.nav_events          # List of detected drops
report.stage_n.nav_result.primary_redirection # NAVRedirectionHypothesis
report.stage_n.nav_result.nav_adjustment      # Float added to Stage K scores
report.nav_redirection                        # String representation
```

---

### Stage O — CABAL Cross-App Collusion

**Runs when**: `cabal_enabled=True` AND `len(mag_list) >= 2`.

**What it does**: Builds a Cross-App Artifact Bridge Graph (CAABG) between
dormant Intent stubs (in dead code) and exported IntentFilters, predicts
multi-hop collusion chains up to `CABAL_MAX_HOPS=3`.

**LLM usage**: Set `use_llm_for_cabal=False` for fast pattern-matching only.
LLM semantic scoring requires `ANTHROPIC_API_KEY` in the environment.

**Output keys**:
```python
report.stage_o.cabal_result.high_confidence_paths  # List[CollusionPath]
report.collusion_paths_found                       # int
```

---

### Stage P — KINSHIP Builder DNA Fingerprinting

**Runs when**: `kinship_enabled=True`.

**What it does**: Extracts a Builder DNA Vector (BDV) — character n-gram
frequencies, opcode patterns, entropy statistics — and clusters against a
corpus of known-attributed APKs to identify the developer/team.

**SBERT**: Requires `sentence-transformers` for semantic embedding. Falls back
to TF-IDF cosine similarity if not installed.

**Output keys**:
```python
report.stage_p.primary_bdv                    # BuilderDNAVector
report.builder_cluster_id                     # int (-1 = no match)
report.stage_p.similar_apk_hashes             # List[str]
```

---

### Stage Q — MIRAGE Adversarial Robustness

**Runs when**: `mirage_enabled=True`.

**What it does**: Quantifies the effort required to fool the ORACLE-TMF
pipeline for this APK. Produces per-class injection cost scores and
hardening recommendations. Higher `robustness_score` = harder to poison.

**Output keys**:
```python
report.stage_q.robustness_score               # float [0.0, 1.0]
report.stage_q.most_vulnerable_class          # str
report.stage_q.recommendations               # List[str]
```

---

### Stage R — OUROBOROS-TMF Co-Evolution

**Runs when**: `ouroboros_enabled=True` (research/training mode).

**What it does**: Iteratively generates mature variants, compares predicted vs
actual MITRE technique, and refines Stage J prompts. Also generates
`(v_staging, v_mature)` devolution pairs for supervised fine-tuning.

**Requires**: `ANTHROPIC_API_KEY` for critic LLM calls.

---

### Network Attack Analyzer

**Runs when**: `network_attack_enabled=True`.

**What it does**: Scans the MAG's dead code for DDoS/ANC capability
signatures (SYN flood, DNS amplification, NTP amplification, HTTP flood,
SNMP amplification, DGA C2 migration). Generates Suricata detection rules
and STIX 2.1 indicators for the network operations team.

**Output keys**:
```python
report.network_attack.detected_threats        # List[DDoSThreat]
report.network_attack.suricata_rules          # List[str] — ready to deploy
report.network_attack.stix_indicators         # List[dict] — STIX 2.1
report.highest_ddos_threat                    # "CRITICAL"/"HIGH"/"NONE"
```

---

## PHANTOM — Usage Requirements

PHANTOM (Stage M) requires a **controlled, air-gapped lab environment**.
It must **never** be used on production infrastructure or real user devices.

```
MANDATORY PREREQUISITES:
  ✓ Air-gapped Android device or emulator (no outbound internet)
  ✓ Frida server installed on the device (requires root)
  ✓ frida Python package installed on the host
  ✓ All honeytoken data is synthetic — never inject real credentials
  ✓ PCAP logs retained only for PHANTOM_PCAP_RETAIN_HOURS (default: 24h)
  ✓ Sessions terminated immediately after analysis completion
```

**Enabling PHANTOM**:
```python
cfg = Stage2Config(phantom_enabled=True)
orch = Stage2Orchestrator(cfg)
report = orch.run(mag, forecasts=forecasts, apk_path="/path/to/malware.apk")

# Access session data:
session = report.stage_m.session
print(session.behaviors_captured)
print(session.to_dict())
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Required for Stage J LLM calls and CABAL semantic scoring |
| `APKTOOL_PATH` | `apktool` | Path to apktool binary for synthetic APK building |
| `ORACLE_NAV_HISTORY_PATH` | `~/.oracle_tmf/nav_history.json` | Persistent NAV history storage |

---

## Running the Test Suite

```bash
# All Stage 2 tests (no API key, no Frida, no real device needed):
python -m pytest tests/stage2/ -v

# With coverage:
python -m pytest tests/stage2/ --cov=engines --cov=phantom \
  --cov=research --cov=pipeline/stage2 --cov-report=html

# Single test module:
python -m pytest tests/stage2/test_nav_engine.py -v
```

All Stage 2 tests are designed to run without external services.
LLM calls fall back to deterministic stubs when `ANTHROPIC_API_KEY` is unset.
Frida calls are skipped when the `frida` package is not installed.

---

## Architecture Decisions

**Strict stage isolation**: Each stage is a separate Python file. A crash in
Stage P (KINSHIP) never prevents Stage Q (MIRAGE) from running. The
orchestrator wraps each stage call in try/except and logs the error.

**Additive design**: Stage 2 never modifies Stage 1 source files. All
integration happens through the `Stage2Orchestrator`, which receives Stage 1
output (`MutationArtifactGraph`, `List[MutationForecast]`) and returns an
enriched `Stage2Report`.

**Configuration-first**: All tunable constants live in `config/stage2_settings.py`.
No magic numbers anywhere else in the Stage 2 codebase.

**Opt-in engines**: Only `nav_enabled=True` is on by default (it's the only
engine that modifies Stage K output). PHANTOM and OUROBOROS require explicit
enablement because they change the runtime context significantly.
