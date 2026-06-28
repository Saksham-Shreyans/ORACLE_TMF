from __future__ import annotations
import logging
import time
from typing import Optional
from config.stage2_settings import(
    NAV_CONFIDENCE_WEIGHT,
    NAV_MIN_DROP_COUNT,
    NAV_MIRAGE_MIN_VERSIONS,
    NAV_MIRAGE_VELOCITY_THRESHOLD,
)
from models.nav_models import(
    NAVEvent,
    NAVEventType,
    NAVHistory,
    NAVRedirectionHypothesis,
    NAVResult,
)
from models.mutation_artifact_graph import(
    ArtifactClass,
    MutationArtifactGraph,
)
logger=logging.getLogger(__name__)
class NAVEngine:
    ENGINE_NAME="NAV_ENGINE"
    _REDIRECT_MAP:dict[str,NAVRedirectionHypothesis]={
        ArtifactClass.UNFINISHED_UI_FLOW.value:NAVRedirectionHypothesis.OVERLAY_TO_ACCESSIBILITY,
        ArtifactClass.C2_ENDPOINT_STUB.value:NAVRedirectionHypothesis.C2_PROTOCOL_SHIFT,
        ArtifactClass.PLACEHOLDER_STRING.value:NAVRedirectionHypothesis.DGA_ADOPTION,
        ArtifactClass.PARTIAL_API.value:NAVRedirectionHypothesis.CAPABILITY_DELAYED,
        ArtifactClass.UNUSED_PERMISSION.value:NAVRedirectionHypothesis.STEALTH_UPGRADE,
        ArtifactClass.DEAD_CODE.value:NAVRedirectionHypothesis.CAPABILITY_DELAYED,
        ArtifactClass.GENAI_API_SCAFFOLD.value:NAVRedirectionHypothesis.CAPABILITY_DELAYED,
    }
    _EVENT_TYPE_MAP:dict[str,NAVEventType]={
        ArtifactClass.DEAD_CODE.value:NAVEventType.ABANDONED_PATH,
        ArtifactClass.UNFINISHED_UI_FLOW.value:NAVEventType.ABANDONED_PATH,
        ArtifactClass.GENAI_API_SCAFFOLD.value:NAVEventType.ABANDONED_PATH,
        ArtifactClass.C2_ENDPOINT_STUB.value:NAVEventType.CAPABILITY_REGRESSION,
        ArtifactClass.PARTIAL_API.value:NAVEventType.CAPABILITY_REGRESSION,
        ArtifactClass.PLACEHOLDER_STRING.value:NAVEventType.CAPABILITY_REGRESSION,
        ArtifactClass.UNUSED_PERMISSION.value:NAVEventType.PERMISSION_REMOVAL,
    }
    def __init__(self)->None:
        logger.info("[NAV] Negative Artifact Vector engine initialised")
    def run(
        self,
        mag_curr:MutationArtifactGraph,
        mag_prev:Optional[MutationArtifactGraph]=None,
        history_map:Optional[dict[str,NAVHistory]]=None,
    )->NAVResult:
        t0=time.perf_counter()
        logger.info("[NAV] Starting NAV analysis")
        result=NAVResult()
        if mag_prev is None:
            logger.info("[NAV] No previous version — NAV not applicable")
            return result
        curr_counts=self._class_counts(mag_curr)
        prev_counts=self._class_counts(mag_prev)
        version_from=mag_prev.family_version or "v_n-1"
        version_to=mag_curr.family_version or "v_n"
        nav_events:list[NAVEvent]=[]
        for artifact_class,prev_count in prev_counts.items():
            curr_count=curr_counts.get(artifact_class,0)
            delta=prev_count-curr_count
            if delta<NAV_MIN_DROP_COUNT:
                continue
            event=self._build_event(
                artifact_class=artifact_class,
                version_from=version_from,
                version_to=version_to,
                count_before=prev_count,
                count_after=curr_count,
                delta=delta,
            )
            nav_events.append(event)
            logger.debug(
                "[NAV] Event: class=%s drop=%d→%d type=%s",
                artifact_class,prev_count,curr_count,event.event_type.value,
            )
        mirage_suspects:list[NAVEvent]=[]
        if history_map:
            mirage_suspects=self._detect_mirage(nav_events,history_map,curr_counts)
            for suspect in mirage_suspects:
                suspect.event_type=NAVEventType.NAV_MIRAGE_SUSPECT
                suspect.redirection_hypothesis=NAVRedirectionHypothesis.ADVERSARIAL_INJECTION
        aggregate_score=self._compute_aggregate_score(nav_events)
        nav_adjustment=self._compute_confidence_adjustment(nav_events,mirage_suspects)
        primary_redirection=self._primary_redirection(nav_events,mirage_suspects)
        result.nav_events=nav_events
        result.mirage_suspects=mirage_suspects
        result.aggregate_nav_score=round(aggregate_score,4)
        result.nav_adjustment=round(nav_adjustment,4)
        result.total_artifacts_lost=sum(e.delta_count for e in nav_events)
        result.has_redirection=primary_redirection is not None
        result.primary_redirection=primary_redirection
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[NAV] Complete in %.1f ms | events=%d | mirage_suspects=%d | "
            "aggregate_score=%.3f | adjustment=%.3f",
            elapsed_ms,
            len(nav_events),
            len(mirage_suspects),
            aggregate_score,
            nav_adjustment,
        )
        return result
    def update_history(
        self,
        family:str,
        mag:MutationArtifactGraph,
        history_map:dict[str,NAVHistory],
        version:str,
    )->dict[str,NAVHistory]:
        counts=self._class_counts(mag)
        for artifact_class,count in counts.items():
            if artifact_class not in history_map:
                history_map[artifact_class]=NAVHistory(
                    family=family,
                    artifact_class=artifact_class,
                )
            history=history_map[artifact_class]
            history.version_sequence.append(version)
            history.count_sequence.append(count)
            if count>0 and history.first_appearance_version is None:
                history.first_appearance_version=version
            if(
                count==0
                and history.first_appearance_version is not None
                and history.first_disappearance_version is None
            ):
                history.first_disappearance_version=version
            if self._is_mirage_pattern(history):
                history.is_mirage_candidate=True
                logger.warning(
                    "[NAV-MIRAGE] Rapid appear-then-disappear pattern detected: "
                    "class=%s family=%s",
                    artifact_class,family,
                )
        return history_map
    @staticmethod
    def _class_counts(mag:MutationArtifactGraph)->dict[str,int]:
        return{
            ArtifactClass.DEAD_CODE.value:len(mag.dead_code),
            ArtifactClass.UNUSED_PERMISSION.value:len(mag.unused_permissions),
            ArtifactClass.PLACEHOLDER_STRING.value:len(mag.placeholder_strings),
            ArtifactClass.C2_ENDPOINT_STUB.value:len(mag.c2_stubs),
            ArtifactClass.PARTIAL_API.value:len(mag.partial_apis),
            ArtifactClass.UNFINISHED_UI_FLOW.value:len(mag.unfinished_ui_flows),
            ArtifactClass.GENAI_API_SCAFFOLD.value:len(mag.genai_scaffolds),
        }
    def _build_event(
        self,
        artifact_class:str,
        version_from:str,
        version_to:str,
        count_before:int,
        count_after:int,
        delta:int,
    )->NAVEvent:
        event_type=self._EVENT_TYPE_MAP.get(artifact_class,NAVEventType.ABANDONED_PATH)
        redirection=self._REDIRECT_MAP.get(artifact_class,NAVRedirectionHypothesis.UNKNOWN)
        nav_score=min(1.0,delta/max(count_before,1))
        evidence=[
            f"{artifact_class}count dropped from{count_before}to{count_after}"
            f"between{version_from}and{version_to}.",
            f"Delta:{delta}artifacts lost(NAV score:{nav_score:.3f}).",
            f"Implied redirection:{redirection.value}.",
        ]
        return NAVEvent(
            artifact_class=artifact_class,
            version_from=version_from,
            version_to=version_to,
            count_before=count_before,
            count_after=count_after,
            delta_count=delta,
            event_type=event_type,
            redirection_hypothesis=redirection,
            nav_score=round(nav_score,4),
            mirage_confidence=0.0,
            supporting_evidence=evidence,
        )
    def _detect_mirage(
        self,
        nav_events:list[NAVEvent],
        history_map:dict[str,NAVHistory],
        curr_counts:dict[str,int],
    )->list[NAVEvent]:
        suspects:list[NAVEvent]=[]
        for event in nav_events:
            history=history_map.get(event.artifact_class)
            if history is None:
                continue
            if not self._is_mirage_pattern(history):
                continue
            velocity=self._compute_mirage_velocity(history)
            if velocity>=NAV_MIRAGE_VELOCITY_THRESHOLD:
                event.mirage_confidence=round(min(1.0,velocity),4)
                event.supporting_evidence.append(
                    f"NAV-MIRAGE:artifact appeared in "
                    f"{history.first_appearance_version}and vanished in "
                    f"{history.first_disappearance_version}— "
                    f"velocity={velocity:.3f}≥{NAV_MIRAGE_VELOCITY_THRESHOLD}."
                    "Possible adversarial artifact injection."
                )
                suspects.append(event)
                logger.warning(
                    "[NAV-MIRAGE] Suspect: class=%s velocity=%.3f",
                    event.artifact_class,velocity,
                )
        return suspects
    @staticmethod
    def _is_mirage_pattern(history:NAVHistory)->bool:
        if len(history.count_sequence)<NAV_MIRAGE_MIN_VERSIONS:
            return False
        if history.first_appearance_version is None:
            return False
        if history.first_disappearance_version is None:
            return False
        return True
    @staticmethod
    def _compute_mirage_velocity(history:NAVHistory)->float:
        if not history.version_sequence:
            return 0.0
        n_versions=len(history.version_sequence)
        appear_idx=(
            history.version_sequence.index(history.first_appearance_version)
            if history.first_appearance_version in history.version_sequence
            else 0
        )
        disappear_idx=(
            history.version_sequence.index(history.first_disappearance_version)
            if history.first_disappearance_version in history.version_sequence
            else n_versions
        )
        lifespan=max(1,disappear_idx-appear_idx)
        return round(1.0/lifespan,4)
    @staticmethod
    def _compute_aggregate_score(nav_events:list[NAVEvent])->float:
        if not nav_events:
            return 0.0
        return sum(e.nav_score for e in nav_events)/len(nav_events)
    @staticmethod
    def _compute_confidence_adjustment(
        nav_events:list[NAVEvent],
        mirage_suspects:list[NAVEvent],
    )->float:
        genuine_events=[e for e in nav_events if e not in mirage_suspects]
        if not genuine_events and not mirage_suspects:
            return 0.0
        genuine_score=(
            sum(e.nav_score for e in genuine_events)/max(len(genuine_events),1)
        )if genuine_events else 0.0
        mirage_penalty=(
            NAV_CONFIDENCE_WEIGHT*(
                sum(e.mirage_confidence for e in mirage_suspects)
                /max(len(mirage_suspects),1)
            )
        )if mirage_suspects else 0.0
        adjustment=NAV_CONFIDENCE_WEIGHT*genuine_score-mirage_penalty
        return round(adjustment,4)
    @staticmethod
    def _primary_redirection(
        nav_events:list[NAVEvent],
        mirage_suspects:list[NAVEvent],
    )->Optional[NAVRedirectionHypothesis]:
        genuine=[e for e in nav_events if e not in mirage_suspects]
        if not genuine:
            return None
        best=max(genuine,key=lambda e:e.nav_score)
        if best.redirection_hypothesis==NAVRedirectionHypothesis.UNKNOWN:
            return None
        return best.redirection_hypothesis
