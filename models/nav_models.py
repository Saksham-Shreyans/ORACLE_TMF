from __future__ import annotations
from dataclasses import dataclass,field
from enum import Enum
from typing import Optional
class NAVEventType(str,Enum):
    ABANDONED_PATH="ABANDONED_PATH"
    """Scaffolding appeared across N versions then dropped to zero.
    Interpretation: developer redirected development effort."""
    CAPABILITY_REGRESSION="CAPABILITY_REGRESSION"
    """Partial API or C2 stub present in v_n-1, absent in v_n.
    Interpretation: feature reverted — possibly delayed to future version."""
    PERMISSION_REMOVAL="PERMISSION_REMOVAL"
    """Unused permission removed — may indicate stealth improvement."""
    NAV_MIRAGE_SUSPECT="NAV_MIRAGE_SUSPECT"
    """Rapid appear/disappear pattern — potential adversarial poisoning
    attempt to manipulate the ORACLE-TMF forecast output."""
class NAVRedirectionHypothesis(str,Enum):
    OVERLAY_TO_ACCESSIBILITY="OVERLAY_TO_ACCESSIBILITY"
    """Overlay UI artifacts dropped → pivot to Accessibility Service ATS."""
    C2_PROTOCOL_SHIFT="C2_PROTOCOL_SHIFT"
    """HTTP stub removed → pivot to DNS/WebSocket/Telegram C2."""
    DGA_ADOPTION="DGA_ADOPTION"
    """Hardcoded C2 stub vanished → pivot to DGA C2 migration."""
    CAPABILITY_DELAYED="CAPABILITY_DELAYED"
    """Feature removed — not abandoned.  Expect reappearance in v_n+2."""
    STEALTH_UPGRADE="STEALTH_UPGRADE"
    """Permission removed alongside new obfuscation layer."""
    ADVERSARIAL_INJECTION="ADVERSARIAL_INJECTION"
    """NAV-MIRAGE: injected artifact to poison the forecast."""
    UNKNOWN="UNKNOWN"
@dataclass
class NAVEvent:
    artifact_class:str=""
    version_from:str=""
    version_to:str=""
    count_before:int=0
    count_after:int=0
    delta_count:int=0
    event_type:NAVEventType=NAVEventType.ABANDONED_PATH
    redirection_hypothesis:NAVRedirectionHypothesis=NAVRedirectionHypothesis.UNKNOWN
    nav_score:float=0.0
    mirage_confidence:float=0.0
    supporting_evidence:list[str]=field(default_factory=list)
@dataclass
class NAVHistory:
    family:str=""
    artifact_class:str=""
    version_sequence:list[str]=field(default_factory=list)
    """Ordered list of version strings analysed so far."""
    count_sequence:list[int]=field(default_factory=list)
    """Artifact count at each version in version_sequence."""
    is_mirage_candidate:bool=False
    """True if the rapid appear-then-disappear pattern was detected."""
    first_appearance_version:Optional[str]=None
    first_disappearance_version:Optional[str]=None
@dataclass
class NAVResult:
    nav_events:list[NAVEvent]=field(default_factory=list)
    """All NAV events detected in this version pair."""
    mirage_suspects:list[NAVEvent]=field(default_factory=list)
    """NAV events classified as NAV-MIRAGE adversarial poisoning attempts."""
    aggregate_nav_score:float=0.0
    """Normalised aggregate score [0.0, 1.0] for Stage K integration."""
    nav_adjustment:float=0.0
    """Additive confidence adjustment applied to Stage K formula."""
    total_artifacts_lost:int=0
    """Sum of delta_count across all NAV events."""
    has_redirection:bool=False
    """True if any NAV event implies a forecast redirection."""
    primary_redirection:Optional[NAVRedirectionHypothesis]=None
    """The highest-priority redirection hypothesis (if any)."""
    def to_dict(self)->dict:
        return{
            "nav_events":[
                {
                    "artifact_class":e.artifact_class,
                    "version_from":e.version_from,
                    "version_to":e.version_to,
                    "count_before":e.count_before,
                    "count_after":e.count_after,
                    "delta_count":e.delta_count,
                    "event_type":e.event_type.value,
                    "redirection_hypothesis":e.redirection_hypothesis.value,
                    "nav_score":round(e.nav_score,4),
                    "mirage_confidence":round(e.mirage_confidence,4),
                    "supporting_evidence":e.supporting_evidence,
                }
                for e in self.nav_events
            ],
            "mirage_suspects_count":len(self.mirage_suspects),
            "aggregate_nav_score":round(self.aggregate_nav_score,4),
            "nav_adjustment":round(self.nav_adjustment,4),
            "total_artifacts_lost":self.total_artifacts_lost,
            "has_redirection":self.has_redirection,
            "primary_redirection":(
                self.primary_redirection.value
                if self.primary_redirection
                else None
            ),
        }
