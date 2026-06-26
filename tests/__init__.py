"""
ORACLE-TMF  ·  tests/
=======================
Unit and integration test suite.
Run all tests:
    python -m pytest tests/ -v
Run a single module:
    python -m pytest tests/test_stage_a.py -v
Test modules
------------
  test_mag.py           MutationArtifactGraph schema, serialisation, helpers
  test_stage_a.py       APK Ingestion: validation, hashing, Zip Slip protection
  test_stage_d.py       Dead Code Detector: BFS reachability, opcode counting
  test_stage_f.py       String Miner: Shannon entropy, placeholder patterns
  test_dte_engine.py    DTE XGBoost: synthetic data, classification, caching
  test_bayesian.py      Bayesian scorer: formula, gating, weight assertions
  test_stage_i.py       Version Diff Engine: delta computation, MVV formula
  test_targeting.py     Targeting intelligence: package lookup, taxonomy load
"""
