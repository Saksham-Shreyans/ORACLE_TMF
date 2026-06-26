"""
ORACLE-TMF  ·  engines/
=========================
Specialised analytical engines that support the 12-stage pipeline.
ISOLATION CONTRACT:  Same as pipeline/ — import engines directly,
never via this __init__.py, to prevent cascade import failures.
Engine index
------------
  dte_engine.py               Dormancy Taxonomy Engine (XGBoost 4-class classifier)
                              Classifies dead code: REMNANT / SCAFFOLDING /
                              LOGIC_BOMB / ENCRYPTED_DROPPER
  tmf_reflect.py              TMF-REFLECT: Reflection-Aware CFG Augmentation
                              Resolves Java reflection chains using Sentence-BERT
                              and injects synthetic edges into the primary CFG
  genai_scaffold_detector.py  Class 7 (TMF-Psi) GenAI API Scaffold Detection
                              Detects dormant LLM API stubs (Gemini, GPT-4,
                              Claude, Ollama) in Android APKs
  unfinished_ui_detector.py   Class 6 Unfinished UI Flow Detection
                              Identifies orphaned XML layouts never inflated
                              by any Java/Kotlin code
  targeting_intelligence.py   4-Layer Targeting Intelligence Module
                              Predicts which specific financial institutions
                              will be targeted in v_{n+1}
"""
__version__="1.0.0"
