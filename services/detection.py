"""Predictive analytics: anomaly detection with two candidate models (Z-score threshold, Isolation Forest)."""
import os
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

EVENT_TYPES = ["login_success", "login_failed", "logout", "privilege_change", "access_denied", "other"]
FEATURES = ["total", "failed", "fail_ratio", "unique_users", "off_hours_ratio"] + ["ev_" + e for e in EVENT_TYPES]
MODEL_FILE = "best_model.joblib"


class ZScoreModel:
    """Statistical threshold: anomalous if volume features exceed N standard deviations (after scaling)."""
    COLS = [FEATURES.index(c) for c in ("total", "failed", "unique_users")]

    def __init__(self, threshold=3.0):
        self.threshold = threshold

    def fit(self, X):
        return self

    def score(self, X):
        return np.asarray(X)[:, self.COLS].max(axis=1)

    def predict(self, X):
        return np.where(self.score(X) > self.threshold, -1, 1)


def build_features(df):
    """Aggregate events into IP x hour windows; the categorical event_type is one-hot encoded and summed."""
    d = df.copy()
    d["window"] = d.event_time.dt.floor("h")
    d["is_fail"] = (d.status == "failure").astype(int)
    h = d.event_time.dt.hour
    d["off"] = ((h < 6) | (h >= 22)).astype(int)
    enc = pd.get_dummies(d["event_type"]).reindex(columns=EVENT_TYPES, fill_value=0).astype(int)
    enc.columns = ["ev_" + c for c in EVENT_TYPES]
    d = pd.concat([d, enc], axis=1)
    agg = dict(total=("log_id", "count"), failed=("is_fail", "sum"), unique_users=("username", "nunique"),
               off_hours_ratio=("off", "mean"), log_id=("log_id", "max"))
    agg.update({c: (c, "sum") for c in enc.columns})
    f = d.groupby(["ip_address", "window"]).agg(**agg).reset_index()
    f["fail_ratio"] = f.failed / f.total
    return f


def weak_labels(f, cfg):
    """Rule-based reference labels used to evaluate the candidate models."""
    brute = f.failed >= cfg["BRUTE_FORCE_FAILURES"]
    spray = (f.unique_users >= cfg["SPRAY_USER_THRESHOLD"]) & (f.fail_ratio >= 0.6)
    return (brute | spray).astype(int).to_numpy()


def _raw_score(model, Xs):
    return model.score(Xs) if isinstance(model, ZScoreModel) else -model.decision_function(Xs)


def _severity(score):
    return "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 40 else "Low"


def _alert_type(r, cfg):
    if r.failed >= cfg["BRUTE_FORCE_FAILURES"] and r.unique_users <= 2:
        return "Brute Force Attempt"
    if r.unique_users >= cfg["SPRAY_USER_THRESHOLD"] and r.fail_ratio >= 0.6:
        return "Password Spraying"
    if r.off_hours_ratio >= 0.8 and r.total >= 5:
        return "Off-hours Access"
    if r.failed >= 3:
        return "Repeated Failed Logins"
    return "Abnormal Access Volume"


def run_detection(df, cfg, model_dir):
    feats = build_features(df)
    y = weak_labels(feats, cfg)
    X = feats[FEATURES].to_numpy(float)
    n = len(feats)

    if n >= 20:
        strat = y if (y.sum() >= 2 and (n - y.sum()) >= 2) else None
        tr, te = train_test_split(np.arange(n), test_size=0.3, random_state=42, stratify=strat)
    else:
        tr = te = np.arange(n)
    scaler = StandardScaler().fit(X[tr])
    Xs = scaler.transform(X)

    candidates = {"Statistical Z-Score": ZScoreModel(3.0),
                  "Isolation Forest": IsolationForest(n_estimators=200, contamination=0.1, random_state=42)}
    results = []
    for name, model in candidates.items():
        model.fit(Xs[tr])
        pred = (model.predict(Xs[te]) == -1).astype(int)
        tn, fp, fn, tp = confusion_matrix(y[te], pred, labels=[0, 1]).ravel()
        results.append({"model": name, "accuracy": float(accuracy_score(y[te], pred)),
                        "precision": float(precision_score(y[te], pred, zero_division=0)),
                        "recall": float(recall_score(y[te], pred, zero_division=0)),
                        "f1": float(f1_score(y[te], pred, zero_division=0)),
                        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp), "is_best": False})
    best = max(results, key=lambda r: (r["f1"], r["accuracy"]))
    best["is_best"] = True
    model = candidates[best["model"]]
    if not isinstance(model, ZScoreModel):
        model.fit(Xs)                                   # refit the best model on all windows

    raw = _raw_score(model, Xs)
    lo, hi = raw.min(), raw.max()
    score = 100 * (raw - lo) / (hi - lo) if hi > lo else np.zeros(n)
    flagged = (model.predict(Xs) == -1) | (y == 1)
    score = np.where(y == 1, np.maximum(score, 55), score)

    alerts = []
    for i, r in enumerate(feats.itertuples()):
        if not flagged[i]:
            continue
        s = round(float(score[i]), 1)
        alerts.append({"log_id": int(r.log_id), "alert_type": _alert_type(r, cfg), "severity": _severity(s), "score": s,
                       "ip": r.ip_address, "window": f"{r.window:%Y-%m-%d %H:00}", "failed": int(r.failed),
                       "total": int(r.total), "users": int(r.unique_users)})

    summary = {"trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "best": best["model"], "windows": int(n),
               "train": int(len(tr)), "test": int(len(te)), "metrics": results, "flagged": alerts}
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler, "features": FEATURES, **summary}, os.path.join(model_dir, MODEL_FILE))
    return summary


def load_saved(model_dir):
    path = os.path.join(model_dir, MODEL_FILE)
    return joblib.load(path) if os.path.exists(path) else None
