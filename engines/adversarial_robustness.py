"""
ORACLE-TMF  ·  engines/adversarial_robustness.py
==================================================
ADVERSARIAL ROBUSTNESS TESTING MODULE
Evaluates the stability of the DTE XGBoost classifier under adversarial
feature perturbation.  This directly addresses the #1 cited gap in
2025-2026 SOTA Android malware research: adversarial robustness.
METHODOLOGY:
  1. Fast Gradient Sign Method (FGSM)-inspired perturbation:
     For each artifact's feature vector x, compute perturbed vectors
     x' = x ± ε along each feature dimension.
  2. Stability score: percentage of classifications that remain stable
     under ε-perturbation across all feature dimensions.
  3. Boundary distance: minimum ε that causes a classification flip,
     computed via binary search along each feature axis.
OUTPUT:
  RobustnessReport dict containing:
    - overall_stability:    float [0,1] — fraction of stable classifications
    - per_class_stability:  dict[DTEClass, float] — stability per class
    - avg_boundary_distance: float — mean ε to flip a classification
    - vulnerable_artifacts: list — artifacts that flip at ε < 0.1
    - perturbation_matrix:  list — per-artifact perturbation results
Research basis:
  • Goodfellow et al. (2015) — "Explaining and Harnessing Adversarial Examples"
  • Carlini & Wagner (2017) — "Towards Evaluating the Robustness of Neural Networks"
  • ORACLE-TMF: "First adversarial robustness evaluation for dormancy classification"
"""
from __future__ import annotations
import logging
import time
from typing import Optional
import numpy as np
from models.mutation_artifact_graph import DeadCodeArtifact,DTEClass
logger=logging.getLogger(__name__)

_FEATURE_NAMES=["trigger_depth","guard_entropy","api_sensitivity","guard_indegree"]
class AdversarialRobustnessTester:
    """
    Tests the DTE classifier's robustness to adversarial feature perturbation.
    Usage
    -----
    >>> from engines.dte_engine import DTEEngine
    >>> dte = DTEEngine()
    >>> tester = AdversarialRobustnessTester(dte)
    >>> report = tester.evaluate(artifacts)
    """
    
    DEFAULT_EPSILONS=[0.01,0.05,0.1,0.2,0.3,0.5,0.75,1.0]
    
    _FEATURE_BOUNDS={
        0:(0.0,10.0),
        1:(0.0,8.0),
        2:(0.0,1.0),
        3:(0.0,20.0),
    }
    def __init__(self,dte_engine)->None:
        """
        Parameters
        ----------
        dte_engine : DTEEngine
            A trained DTE engine instance (with a loaded XGBoost model).
        """
        self._model=dte_engine._model
        self._build_features=dte_engine._build_feature_matrix
    
    
    
    def evaluate(
        self,
        artifacts:list[DeadCodeArtifact],
        epsilons:Optional[list[float]]=None,
    )->dict:
        """
        Evaluate adversarial robustness of DTE classifications.
        Parameters
        ----------
        artifacts : list[DeadCodeArtifact]
            Classified artifacts (dte_label must be set).
        epsilons : list[float], optional
            Perturbation magnitudes to test. Defaults to DEFAULT_EPSILONS.
        Returns
        -------
        dict — RobustnessReport with:
            overall_stability, per_class_stability, avg_boundary_distance,
            vulnerable_artifacts, epsilon_stability_curve, perturbation_matrix
        """
        if not artifacts:
            return self._empty_report()
        t0=time.perf_counter()
        eps_list=epsilons or self.DEFAULT_EPSILONS
        logger.info(
            "[Robustness] Evaluating %d artifacts across %d epsilon values",
            len(artifacts),len(eps_list),
        )
        X=self._build_features(artifacts)
        original_preds=self._model.predict(X)
        
        epsilon_stability={}
        for eps in eps_list:
            stable_count=0
            for i in range(len(X)):
                if self._is_stable_at_epsilon(X[i],int(original_preds[i]),eps):
                    stable_count+=1
            stability=stable_count/len(X)
            epsilon_stability[eps]=round(stability,4)
        
        perturbation_matrix=[]
        boundary_distances=[]
        vulnerable=[]
        for i,artifact in enumerate(artifacts):
            orig_class=int(original_preds[i])
            bd=self._find_boundary_distance(X[i],orig_class)
            boundary_distances.append(bd)
            
            feature_vulnerabilities=self._per_feature_vulnerability(X[i],orig_class)
            entry={
                "class_name":artifact.class_name,
                "method_name":artifact.method_name,
                "original_class":DTEClass(artifact.dte_label).value if isinstance(artifact.dte_label,DTEClass)else str(artifact.dte_label),
                "boundary_distance":round(bd,4),
                "most_vulnerable_feature":feature_vulnerabilities[0][0]if feature_vulnerabilities else "",
                "feature_vulnerabilities":feature_vulnerabilities,
            }
            perturbation_matrix.append(entry)
            if bd<0.1:
                vulnerable.append(entry)
        
        per_class_stability={}
        for dte_cls in DTEClass:
            class_indices=[
                i for i,a in enumerate(artifacts)if a.dte_label==dte_cls
            ]
            if class_indices:
                stable=sum(
                    1 for i in class_indices
                    if self._is_stable_at_epsilon(X[i],int(original_preds[i]),0.1)
                )
                per_class_stability[dte_cls.value]=round(stable/len(class_indices),4)
        
        overall_stability=epsilon_stability.get(0.1,1.0)
        avg_boundary=float(np.mean(boundary_distances))if boundary_distances else 0.0
        elapsed_ms=(time.perf_counter()-t0)*1000
        logger.info(
            "[Robustness] Complete in %.1f ms | stability@ε=0.1=%.3f | "
            "avg_boundary=%.3f | vulnerable=%d",
            elapsed_ms,overall_stability,avg_boundary,len(vulnerable),
        )
        return{
            "overall_stability":round(overall_stability,4),
            "per_class_stability":per_class_stability,
            "avg_boundary_distance":round(avg_boundary,4),
            "min_boundary_distance":round(float(min(boundary_distances)),4)if boundary_distances else 0.0,
            "max_boundary_distance":round(float(max(boundary_distances)),4)if boundary_distances else 0.0,
            "vulnerable_count":len(vulnerable),
            "total_tested":len(artifacts),
            "epsilon_stability_curve":epsilon_stability,
            "vulnerable_artifacts":vulnerable[:10],
            "perturbation_matrix":perturbation_matrix[:50],
        }
    
    
    
    def _is_stable_at_epsilon(
        self,x:np.ndarray,original_class:int,epsilon:float
    )->bool:
        """
        Check if the classification remains stable under ε-perturbation
        along ALL feature dimensions (both + and - directions).
        """
        for feature_idx in range(len(x)):
            lo,hi=self._FEATURE_BOUNDS.get(feature_idx,(0.0,10.0))
            for direction in[+1,-1]:
                x_perturbed=x.copy()
                x_perturbed[feature_idx]=np.clip(
                    x[feature_idx]+direction*epsilon*(hi-lo),
                    lo,hi,
                )
                pred=int(self._model.predict(x_perturbed.reshape(1,-1))[0])
                if pred!=original_class:
                    return False
        return True
    
    
    
    def _find_boundary_distance(
        self,x:np.ndarray,original_class:int,max_steps:int=20
    )->float:
        """
        Find the minimum ε (normalized) that causes a classification flip.
        Uses binary search along the most sensitive feature axis.
        Returns ε ∈ [0, 1]. Returns 1.0 if no flip found.
        """
        min_eps=1.0
        for feature_idx in range(len(x)):
            lo_bound,hi_bound=self._FEATURE_BOUNDS.get(feature_idx,(0.0,10.0))
            feature_range=hi_bound-lo_bound
            if feature_range<=0:
                continue
            for direction in[+1,-1]:
                low,high=0.0,1.0
                found_flip=False
                for _ in range(max_steps):
                    mid=(low+high)/2
                    x_perturbed=x.copy()
                    x_perturbed[feature_idx]=np.clip(
                        x[feature_idx]+direction*mid*feature_range,
                        lo_bound,hi_bound,
                    )
                    pred=int(self._model.predict(x_perturbed.reshape(1,-1))[0])
                    if pred!=original_class:
                        high=mid
                        found_flip=True
                    else:
                        low=mid
                if found_flip and high<min_eps:
                    min_eps=high
        return min_eps
    
    
    
    def _per_feature_vulnerability(
        self,x:np.ndarray,original_class:int
    )->list[tuple[str,float]]:
        """
        For each feature, find the minimum ε that causes a flip.
        Returns sorted list of (feature_name, boundary_distance) tuples.
        """
        vulnerabilities=[]
        for feature_idx in range(len(x)):
            lo_bound,hi_bound=self._FEATURE_BOUNDS.get(feature_idx,(0.0,10.0))
            feature_range=hi_bound-lo_bound
            if feature_range<=0:
                vulnerabilities.append((_FEATURE_NAMES[feature_idx],1.0))
                continue
            min_eps_feature=1.0
            for direction in[+1,-1]:
                low,high=0.0,1.0
                found=False
                for _ in range(15):
                    mid=(low+high)/2
                    x_p=x.copy()
                    x_p[feature_idx]=np.clip(
                        x[feature_idx]+direction*mid*feature_range,
                        lo_bound,hi_bound,
                    )
                    if int(self._model.predict(x_p.reshape(1,-1))[0])!=original_class:
                        high=mid
                        found=True
                    else:
                        low=mid
                if found and high<min_eps_feature:
                    min_eps_feature=high
            vulnerabilities.append((
                _FEATURE_NAMES[feature_idx],
                round(min_eps_feature,4),
            ))
        
        vulnerabilities.sort(key=lambda x:x[1])
        return vulnerabilities
    
    
    
    @staticmethod
    def _empty_report()->dict:
        return{
            "overall_stability":1.0,
            "per_class_stability":{},
            "avg_boundary_distance":1.0,
            "min_boundary_distance":1.0,
            "max_boundary_distance":1.0,
            "vulnerable_count":0,
            "total_tested":0,
            "epsilon_stability_curve":{},
            "vulnerable_artifacts":[],
            "perturbation_matrix":[],
        }
