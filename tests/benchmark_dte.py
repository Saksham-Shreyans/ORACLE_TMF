"""
ORACLE-TMF  ·  tests/benchmark_dte.py
=======================================
DTE Cross-Validation Benchmark — Research-Grade Evaluation Framework
Generates paper-ready metrics for the Dormancy Taxonomy Engine:
  • 5-fold stratified cross-validation
  • Per-class precision, recall, F1-score
  • Macro and weighted F1 scores
  • Confusion matrix (printed and saved)
  • ROC/AUC curves per class (One-vs-Rest)
  • Training and inference latency
Usage:
  python tests/benchmark_dte.py
  python tests/benchmark_dte.py --folds 10 --output benchmark_results.json
Novel Contribution:
  "Reproducible evaluation framework with synthetic APK mutation artifact
   generation for dormancy taxonomy classification."
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path
import numpy as np

PROJECT_ROOT=str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0,PROJECT_ROOT)
from config.settings import(
    DTE_LEARNING_RATE,
    DTE_MAX_DEPTH,
    DTE_N_ESTIMATORS,
)
from engines.dte_engine import DTEEngine



CLASS_NAMES=["REMNANT","SCAFFOLDING","LOGIC_BOMB","ENCRYPTED_DROPPER"]
CLASS_DESCRIPTIONS={
    0:"Benign SDK boilerplate (discard)",
    1:"Future capability stub (Stage J)",
    2:"Conditional dormant payload (HIGH PRIORITY)",
    3:"Dynamic loader / dropper (Frida path)",
}
def run_benchmark(n_folds:int=5,output_path:str=None)->dict:
    """
    Run the full DTE benchmark evaluation.
    Returns a dict with all metrics, suitable for paper tables.
    """
    try:
        from sklearn.model_selection import StratifiedKFold
        from sklearn.metrics import(
            accuracy_score,
            classification_report,
            confusion_matrix,
            f1_score,
            precision_recall_fscore_support,
            roc_auc_score,
        )
        from xgboost import XGBClassifier
    except ImportError as exc:
        print(f"ERROR: Missing dependency: {exc}")
        print("Install: pip install scikit-learn xgboost")
        sys.exit(1)
    print("="*72)
    print("  ORACLE-TMF  ·  DTE Benchmark  ·  Dormancy Taxonomy Engine")
    print("="*72)
    print()
    
    rng=np.random.default_rng(seed=42)
    X,y=DTEEngine._generate_synthetic_data(rng)
    n_samples=len(X)
    class_dist={CLASS_NAMES[i]:int(np.sum(y==i))for i in range(4)}
    print(f"  Dataset: {n_samples} synthetic samples")
    print(f"  Features: 4 (trigger_depth, guard_entropy, api_sensitivity, guard_indegree)")
    print(f"  Classes: {len(CLASS_NAMES)}")
    for cls_name,count in class_dist.items():
        pct=count/n_samples*100
        print(f"    {cls_name:25s} : {count:5d} ({pct:.1f}%)")
    print()
    
    print(f"  Running {n_folds}-fold stratified cross-validation...")
    print(f"  Model: XGBoost (n_estimators={DTE_N_ESTIMATORS}, "
          f"max_depth={DTE_MAX_DEPTH}, lr={DTE_LEARNING_RATE})")
    print()
    cv=StratifiedKFold(n_splits=n_folds,shuffle=True,random_state=42)
    fold_metrics=[]
    all_y_true=[]
    all_y_pred=[]
    all_y_proba=[]
    train_times=[]
    infer_times=[]
    for fold_idx,(train_idx,test_idx)in enumerate(cv.split(X,y)):
        X_train,X_test=X[train_idx],X[test_idx]
        y_train,y_test=y[train_idx],y[test_idx]
        model=XGBClassifier(
            n_estimators=DTE_N_ESTIMATORS,
            max_depth=DTE_MAX_DEPTH,
            learning_rate=DTE_LEARNING_RATE,
            n_jobs=-1,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=42,
            subsample=0.8,
            colsample_bytree=0.8,
        )
        
        t0=time.perf_counter()
        model.fit(X_train,y_train)
        train_ms=(time.perf_counter()-t0)*1000
        train_times.append(train_ms)
        
        t0=time.perf_counter()
        y_pred=model.predict(X_test)
        y_proba=model.predict_proba(X_test)
        infer_ms=(time.perf_counter()-t0)*1000
        infer_times.append(infer_ms)
        
        acc=accuracy_score(y_test,y_pred)
        f1_macro=f1_score(y_test,y_pred,average="macro")
        f1_weighted=f1_score(y_test,y_pred,average="weighted")
        fold_metrics.append({
            "fold":fold_idx+1,
            "accuracy":round(acc,4),
            "f1_macro":round(f1_macro,4),
            "f1_weighted":round(f1_weighted,4),
            "train_ms":round(train_ms,1),
            "infer_ms":round(infer_ms,1),
        })
        all_y_true.extend(y_test.tolist())
        all_y_pred.extend(y_pred.tolist())
        all_y_proba.extend(y_proba.tolist())
        print(f"  Fold {fold_idx+1}/{n_folds}: "
              f"acc={acc:.4f}  F1_macro={f1_macro:.4f}  "
              f"F1_weighted={f1_weighted:.4f}  "
              f"train={train_ms:.0f}ms  infer={infer_ms:.0f}ms")
    
    all_y_true=np.array(all_y_true)
    all_y_pred=np.array(all_y_pred)
    all_y_proba=np.array(all_y_proba)
    overall_acc=accuracy_score(all_y_true,all_y_pred)
    overall_f1_macro=f1_score(all_y_true,all_y_pred,average="macro")
    overall_f1_weighted=f1_score(all_y_true,all_y_pred,average="weighted")
    
    precision,recall,f1,support=precision_recall_fscore_support(
        all_y_true,all_y_pred,labels=[0,1,2,3],average=None
    )
    print()
    print("─"*72)
    print("  AGGREGATE RESULTS")
    print("─"*72)
    print(f"  Overall Accuracy:     {overall_acc:.4f}")
    print(f"  F1 (macro):           {overall_f1_macro:.4f}")
    print(f"  F1 (weighted):        {overall_f1_weighted:.4f}")
    print(f"  Avg Train Time:       {np.mean(train_times):.1f} ms")
    print(f"  Avg Inference Time:   {np.mean(infer_times):.1f} ms")
    print()
    
    print("  Per-Class Performance:")
    print(f"  {'Class':<22s} {'Precision':>10s} {'Recall':>10s} "
          f"{'F1':>10s} {'Support':>10s}")
    print("  "+"─"*64)
    per_class={}
    for i in range(4):
        name=CLASS_NAMES[i]
        per_class[name]={
            "precision":round(float(precision[i]),4),
            "recall":round(float(recall[i]),4),
            "f1":round(float(f1[i]),4),
            "support":int(support[i]),
        }
        print(f"  {name:<22s} {precision[i]:>10.4f} {recall[i]:>10.4f} "
              f"{f1[i]:>10.4f} {support[i]:>10d}")
    
    cm=confusion_matrix(all_y_true,all_y_pred,labels=[0,1,2,3])
    print()
    print("  Confusion Matrix:")
    print(f"  {'':>22s}",end="")
    for name in CLASS_NAMES:
        print(f" {name[:8]:>8s}",end="")
    print()
    for i,name in enumerate(CLASS_NAMES):
        print(f"  {name:<22s}",end="")
        for j in range(4):
            print(f" {cm[i,j]:>8d}",end="")
        print()
    
    roc_auc={}
    try:
        for i in range(4):
            y_binary=(all_y_true==i).astype(int)
            auc=roc_auc_score(y_binary,all_y_proba[:,i])
            roc_auc[CLASS_NAMES[i]]=round(auc,4)
        roc_macro=round(np.mean(list(roc_auc.values())),4)
        print()
        print("  ROC AUC (One-vs-Rest):")
        for name,auc in roc_auc.items():
            print(f"    {name:<22s} : {auc:.4f}")
        print(f"    {'MACRO AVERAGE':<22s} : {roc_macro:.4f}")
    except Exception as exc:
        print(f"  ROC AUC computation failed: {exc}")
        roc_macro=0.0
    
    importances=model.feature_importances_
    feature_names=["trigger_depth","guard_entropy","api_sensitivity","guard_indegree"]
    print()
    print("  Feature Importance (gain-based, last fold):")
    for name,imp in sorted(zip(feature_names,importances),key=lambda x:x[1],reverse=True):
        bar="█"*int(imp*40)
        print(f"    {name:<20s} : {imp:.4f}  {bar}")
    print()
    print("="*72)
    print("  Benchmark complete.")
    print("="*72)
    
    results={
        "benchmark":"ORACLE-TMF DTE Cross-Validation",
        "model":f"XGBoost (n_est={DTE_N_ESTIMATORS}, depth={DTE_MAX_DEPTH}, lr={DTE_LEARNING_RATE})",
        "n_folds":n_folds,
        "n_samples":n_samples,
        "class_distribution":class_dist,
        "overall":{
            "accuracy":round(overall_acc,4),
            "f1_macro":round(overall_f1_macro,4),
            "f1_weighted":round(overall_f1_weighted,4),
            "avg_train_ms":round(float(np.mean(train_times)),1),
            "avg_infer_ms":round(float(np.mean(infer_times)),1),
        },
        "per_class":per_class,
        "roc_auc_ovr":roc_auc,
        "roc_auc_macro":roc_macro,
        "confusion_matrix":cm.tolist(),
        "per_fold":fold_metrics,
        "feature_importance":{
            name:round(float(imp),4)
            for name,imp in zip(feature_names,importances)
        },
    }
    
    if output_path:
        os.makedirs(os.path.dirname(output_path)or ".",exist_ok=True)
        with open(output_path,"w",encoding="utf-8")as fh:
            json.dump(results,fh,indent=2)
        print(f"\n  Results saved to: {output_path}")
    return results



if __name__=="__main__":
    parser=argparse.ArgumentParser(
        description="ORACLE-TMF DTE Benchmark — Cross-Validation Evaluation"
    )
    parser.add_argument(
        "--folds",type=int,default=5,
        help="Number of cross-validation folds (default: 5)"
    )
    parser.add_argument(
        "--output",type=str,default=None,
        help="Path to save benchmark results as JSON"
    )
    args=parser.parse_args()
    results=run_benchmark(n_folds=args.folds,output_path=args.output)
