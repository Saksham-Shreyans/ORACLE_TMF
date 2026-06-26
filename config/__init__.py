"""
ORACLE-TMF  ·  config/
========================
Configuration package.
All tunable constants live in settings.py.
No stage imports this package at load time — each stage
imports settings.py directly, ensuring isolated startup.
    from config.settings import CONFIDENCE_GATE_THRESHOLD
"""
__version__="1.0.0"
