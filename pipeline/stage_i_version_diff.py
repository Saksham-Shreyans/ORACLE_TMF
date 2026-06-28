from __future__ import annotations
import json
import logging
import time
from typing import Optional
from config.settings import MVV_CLIP_HIGH,MVV_CLIP_LOW
from models.mutation_artifact_graph import(
    MutationArtifactGraph,
    VersionDelta,
)
logger=logging.getLogger(__name__)
class VersionDiffEngine:
    STAGE_NAME="STAGE_I"
    def run(
        self,
        mag_curr:MutationArtifactGraph,
        mag_prev:Optional[MutationArtifactGraph]=None,
    )->VersionDelta:
        t0=time.perf_counter()
        logger.info("[Stage I] Starting version diff engine")
        if mag_prev is None:
            logger.info("[Stage I] No previous version — using empty baseline")
            mag_prev=MutationArtifactGraph()
        curr_fingerprints=self._build_fingerprint_set(mag_curr)
        prev_fingerprints=self._build_fingerprint_set(mag_prev)
        added_fps=curr_fingerprints-prev_fingerprints
        removed_fps=prev_fingerprints-curr_fingerprints
        artifacts_added=self._lookup_artifacts(mag_curr,added_fps)
        artifacts_removed=self._lookup_artifacts(mag_prev,removed_fps)
        edit_distance=self._compute_edit_distance(
            len(curr_fingerprints),len(prev_fingerprints),
            len(added_fps),len(removed_fps),
        )
        n_added=len(added_fps)
        n_removed=len(removed_fps)
        mvv_raw=n_added/(n_added+n_removed+1)
        mvv_normalized=self._clip(mvv_raw*3.0,MVV_CLIP_LOW,MVV_CLIP_HIGH)
        delta=VersionDelta(
            artifacts_added=artifacts_added,
            artifacts_removed=artifacts_removed,
            edit_distance=edit_distance,
            mvv_raw=round(mvv_raw,4),
            mvv_normalized=round(mvv_normalized,4),
        )
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Stage I] Complete in %.1f ms | added=%d | removed=%d | "
            "edit_dist=%.1f | MVV=%.3f",
            elapsed_ms,n_added,n_removed,edit_distance,mvv_normalized,
        )
        return delta
    def _build_fingerprint_set(self,mag:MutationArtifactGraph)->set[str]:
        fingerprints:set[str]=set()
        for a in mag.dead_code:
            fingerprints.add(f"DC:{a.class_name}::{a.method_name}")
        for a in mag.unused_permissions:
            fingerprints.add(f"UP:{a.permission_name}")
        for a in mag.placeholder_strings:
            fingerprints.add(f"PS:{a.value[:64]}")
        for a in mag.c2_stubs:
            fingerprints.add(f"C2:{a.class_name}::{a.method_name}::{a.extracted_url}")
        for a in mag.partial_apis:
            fingerprints.add(f"PA:{a.class_name}::{a.interface_extended}")
        for a in mag.unfinished_ui_flows:
            fingerprints.add(f"UI:{a.layout_file}")
        for a in mag.genai_scaffolds:
            fingerprints.add(f"GS:{a.class_name}::{a.provider}")
        return fingerprints
    def _lookup_artifacts(
        self,mag:MutationArtifactGraph,fingerprints:set[str]
    )->list[dict]:
        index:dict[str,dict]={}
        for a in mag.dead_code:
            fp=f"DC:{a.class_name}::{a.method_name}"
            index[fp]={
                "type":"dead_code","class_name":a.class_name,
                "method_name":a.method_name,"fingerprint":fp,
            }
        for a in mag.unused_permissions:
            fp=f"UP:{a.permission_name}"
            index[fp]={"type":"unused_permission","permission":a.permission_name,"fingerprint":fp}
        for a in mag.placeholder_strings:
            fp=f"PS:{a.value[:64]}"
            index[fp]={"type":"placeholder_string","value":a.value[:64],"fingerprint":fp}
        for a in mag.c2_stubs:
            fp=f"C2:{a.class_name}::{a.method_name}::{a.extracted_url}"
            index[fp]={"type":"c2_stub","class_name":a.class_name,"fingerprint":fp}
        for a in mag.partial_apis:
            fp=f"PA:{a.class_name}::{a.interface_extended}"
            index[fp]={"type":"partial_api","class_name":a.class_name,"fingerprint":fp}
        for a in mag.unfinished_ui_flows:
            fp=f"UI:{a.layout_file}"
            index[fp]={"type":"ui_flow","layout_file":a.layout_file,"fingerprint":fp}
        for a in mag.genai_scaffolds:
            fp=f"GS:{a.class_name}::{a.provider}"
            index[fp]={"type":"genai_scaffold","class_name":a.class_name,"fingerprint":fp}
        return[index[fp]for fp in fingerprints if fp in index]
    @staticmethod
    def _compute_edit_distance(
        n_curr:int,n_prev:int,n_added:int,n_removed:int
    )->float:
        return float(n_added+n_removed)
    @staticmethod
    def _clip(value:float,low:float,high:float)->float:
        return max(low,min(high,value))
