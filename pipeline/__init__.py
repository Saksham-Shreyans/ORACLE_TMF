"""
ORACLE-TMF  ·  pipeline/
==========================
The 12-stage analysis pipeline (Stages A through L).
ISOLATION CONTRACT:
  Each stage is an independent Python module.  Do NOT import stages
  from this __init__.py — doing so would cause a single import failure
  (e.g. missing Androguard) to cascade across unrelated stages.
  Import stages DIRECTLY in the orchestrator:
      from pipeline.stage_a_ingestion       import APKIngestion
      from pipeline.stage_b_dex_disassembly import DEXDisassembler
      ...
Stage index
-----------
  stage_a_ingestion.py        APK Ingestion & Preprocessing
  stage_b_dex_disassembly.py  DEX Bytecode Disassembly & Smali Extraction
  stage_c_manifest_parser.py  AndroidManifest.xml Deep Parsing
  stage_d_dead_code.py        Dead Code Detection via CFG Reachability
  stage_e_unused_perms.py     Unused Permission Intent Analysis
  stage_f_string_mining.py    String Resource & Placeholder Mining
  stage_g_c2_stubs.py         C2 Endpoint Stub Detection
  stage_h_partial_apis.py     Partial API Implementation Detection
  stage_i_version_diff.py     Version Diff Engine (MVV Computation)
  stage_j_llm_reasoning.py    Multi-Agent LLM Reasoning Engine
  stage_k_bayesian_scorer.py  Bayesian Confidence Scoring
  stage_l_report_synthesizer  Forecast Report Synthesizer
"""
__version__="1.0.0"
