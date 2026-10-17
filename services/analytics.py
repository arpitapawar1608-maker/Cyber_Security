"""Business logic: descriptive and diagnostic analytics (predictive = detection.py)."""
import math

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score, silhouette_score
from sklearn.preprocessing import StandardScaler

from services.detection import build_features


def descriptive(df):
    """What happened?"""
    if df.empty:
        return {"empty": True, "kpis": dict(total=0, failed=0, success=0, failure_rate=0, unique_ips=0),
                "trend": {"labels": [], "failed": [], "success": []}, "top_ips": [], "event_types": []}
    failed = df[df.status == "failure"]
    span = df.event_time.max() - df.event_time.min()
    freq, fmt = ("h", "%d %b %H:%M") if span <= pd.Timedelta(days=2) else ("D", "%d %b")
    total_s = df.set_index("event_time").resample(freq).size()
    fail_s = failed.set_index("event_time").resample(freq).size().reindex(total_s.index, fill_value=0)
    top = failed.groupby("ip_address").agg(failed=("log_id", "count"), users=("username", "nunique")) \
        .sort_values("failed", ascending=False).head(10)
    totals = df.groupby("ip_address").size()
    return {
        "empty": False,
        "kpis": dict(total=int(len(df)), failed=int(len(failed)), success=int(len(df) - len(failed)),
                     failure_rate=round(100 * len(failed) / len(df), 1), unique_ips=int(df.ip_address.nunique())),
        "trend": {"labels": [t.strftime(fmt) for t in total_s.index], "failed": fail_s.astype(int).tolist(),
                  "success": (total_s - fail_s).astype(int).tolist()},
        "top_ips": [{"ip": ip, "failed": int(r.failed), "users": int(r.users), "total": int(totals[ip])}
                    for ip, r in top.iterrows()],
        "event_types": [{"type": t, "count": int(n)} for t, n in df.event_type.value_counts().items()],
    }


def diagnostic(df, cfg):
    """Why did it happen?"""
    if df.empty or (df.status == "failure").sum() == 0:
        return {"hourly": [0] * 24, "profiles": [], "findings": ["No failed events available to diagnose."]}
    failed = df[df.status == "failure"]
    hourly = failed.event_time.dt.hour.value_counts().reindex(range(24), fill_value=0)
    off = hourly[[h for h in range(24) if h < 6 or h >= 22]].sum() / hourly.sum() * 100
    profiles = []
    for ip, g in failed.groupby("ip_address"):
        allg = df[df.ip_address == ip]
        n_fail = len(g)
        per_hour = g.groupby(g.event_time.dt.floor("h"))
        peak_hr, peak_users = int(per_hour.size().max()), int(per_hour.username.nunique().max())
        if peak_hr >= cfg["BRUTE_FORCE_FAILURES"] and peak_users <= 2:
            pattern = "Brute force (few accounts, many attempts)"
        elif peak_users >= cfg["SPRAY_USER_THRESHOLD"] and peak_hr >= cfg["SPRAY_USER_THRESHOLD"]:
            pattern = "Password spraying (many accounts)"
        elif n_fail >= 3:
            pattern = "Repeated failures"
        else:
            pattern = "Low volume"
        profiles.append({"ip": ip, "failed": n_fail, "total": len(allg), "fail_ratio": round(n_fail / len(allg) * 100, 1),
                         "users": g.username.nunique(), "first_seen": str(g.event_time.min()),
                         "last_seen": str(g.event_time.max()), "pattern": pattern})
    profiles = sorted(profiles, key=lambda p: p["failed"], reverse=True)[:10]
    brute = sum(p["pattern"].startswith("Brute") for p in profiles)
    spray = sum(p["pattern"].startswith("Password") for p in profiles)
    findings = [
        f"Peak failure hour is {int(hourly.idxmax()):02d}:00 with {int(hourly.max())} failed events.",
        f"{off:.0f}% of failed events occur off-hours (22:00-06:00).",
        f"{brute} source IP(s) match brute-force behaviour; {spray} match password-spraying behaviour.",
        f"Top offender {profiles[0]['ip']} caused {profiles[0]['failed']} failures against {profiles[0]['users']} account(s).",
    ]
    return {"hourly": hourly.astype(int).tolist(), "profiles": profiles, "findings": findings}


def _num(x, n=3):
    try:
        x = float(x)
        return None if math.isnan(x) else round(x, n)
    except (TypeError, ValueError):
        return None


def _fit_regressors(df):
    """Hourly failed-login series + two regressors trained on the first 75% and tested on the last 25%."""
    if df.empty:
        return None
    total = df.set_index("event_time").resample("h").size()
    s = df[df.status == "failure"].set_index("event_time").resample("h").size().reindex(total.index, fill_value=0)
    if len(s) < 12:
        return None

    def feats(t, h):
        return np.column_stack([t, np.sin(2 * np.pi * h / 24), np.cos(2 * np.pi * h / 24)])

    X, y = feats(np.arange(len(s)), s.index.hour.values), s.values.astype(float)
    cut = int(len(s) * 0.75)
    models = {"Linear Regression": LinearRegression(), "Random Forest Regressor": RandomForestRegressor(n_estimators=100, random_state=42)}
    metrics = []
    for name, m in models.items():
        m.fit(X[:cut], y[:cut])
        p = m.predict(X[cut:])
        mse = mean_squared_error(y[cut:], p)
        metrics.append({"model": name, "mae": _num(mean_absolute_error(y[cut:], p)), "mse": _num(mse),
                        "rmse": _num(math.sqrt(mse)), "r2": _num(r2_score(y[cut:], p))})
    return s, X, y, models, metrics, feats


def regression(df):
    """Regression metrics (MAE, MSE, RMSE, R2) of the two hourly failed-login regressors."""
    fit = _fit_regressors(df)
    if fit is None:
        return {"available": False}
    return {"available": True, "models": fit[4]}


def forecast(df, horizon=6):
    """Predictive analytics - what may happen next: expected failed logins per hour for the next hours."""
    fit = _fit_regressors(df)
    if fit is None:
        return {"available": False}
    s, X, y, models, metrics, feats = fit
    best = min(metrics, key=lambda m: m["rmse"])
    model = models[best["model"]].fit(X, y)                       # refit the best regressor on all hours
    steps = np.arange(1, horizon + 1)
    future = s.index[-1] + pd.to_timedelta(steps, unit="h")
    pred = np.clip(model.predict(feats(len(s) - 1 + steps, future.hour.values)), 0, None)
    hist = s.tail(48)
    return {"available": True, "model": best["model"],
            "history": {"labels": [t.strftime("%d %b %H:%M") for t in hist.index], "values": hist.astype(int).tolist()},
            "forecast": {"labels": [t.strftime("%d %b %H:%M") for t in future], "values": [round(float(v), 1) for v in pred]},
            "total": round(float(pred.sum()), 1)}


def clustering(df, cfg):
    """KMeans on IP-hour windows (k chosen from 2-4 by best silhouette score) with a short cluster interpretation."""
    if df.empty:
        return {"available": False}
    f = build_features(df)
    cols = ["total", "failed", "fail_ratio", "unique_users", "off_hours_ratio"]
    if len(f) < 10:
        return {"available": False}
    X = StandardScaler().fit_transform(f[cols].to_numpy(float))
    best = None
    for k in (2, 3, 4):
        labels = KMeans(n_clusters=k, n_init=10, random_state=42).fit_predict(X)
        if len(set(labels)) < 2:
            continue
        sc = silhouette_score(X, labels)
        if best is None or sc > best[0]:
            best = (sc, k, labels)
    if best is None:
        return {"available": False}
    sc, k, labels = best
    f["cluster"] = labels
    rows = []
    for c, g in f.groupby("cluster"):
        af = g.failed.mean()
        label = ("Attack-like (high failures)" if af >= cfg["BRUTE_FORCE_FAILURES"]
                 else "Occasional failures" if af >= 1 else "Normal activity")
        rows.append({"cluster": int(c) + 1, "windows": int(len(g)), "avg_failed": _num(af, 2), "avg_total": _num(g.total.mean(), 2),
                     "avg_accounts": _num(g.unique_users.mean(), 2), "interpretation": label})
    rows.sort(key=lambda r: -r["avg_failed"])
    return {"available": True, "k": int(k), "silhouette": _num(sc), "clusters": rows}
