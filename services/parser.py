"""Log parsing & normalisation (CSV and plain-text/syslog files)."""
import ipaddress
import re
from datetime import datetime

import pandas as pd

ALIASES = {
    "event_time": ["event_time", "timestamp", "time", "datetime", "date", "@timestamp"],
    "ip_address": ["ip_address", "ip", "src_ip", "source_ip", "remote_ip", "client_ip"],
    "username": ["username", "user", "user_name", "account"],
    "event_type": ["event_type", "event", "action", "type", "message"],
    "status": ["status", "result", "outcome"],
}
FAIL_EVENTS = {"login_failed", "access_denied"}


def normalize_event(raw):
    t = str(raw or "").lower()
    if re.search(r"fail|invalid|bad password|wrong", t):
        return "login_failed"
    if re.search(r"denied|forbidden|unauthori", t):
        return "access_denied"
    if re.search(r"logout|logoff|log off|disconnect|session closed", t):
        return "logout"
    if re.search(r"sudo|privilege|escalat|role change", t):
        return "privilege_change"
    if re.search(r"login|logon|accepted|success|authenticated|session opened", t):
        return "login_success"
    return "other"


def normalize_status(raw):
    t = str(raw or "").lower()
    return "failure" if re.search(r"fail|denied|invalid|error|reject|unauthor|\b40[13]\b|block", t) else "success"


def _finish(event_raw, status_raw):
    ev = normalize_event(event_raw)
    st = normalize_status(status_raw) if status_raw is not None else ("failure" if ev in FAIL_EVENTS else "success")
    if st == "failure" and ev in ("login_success", "other"):
        ev = "login_failed" if ev == "login_success" else ev
    if ev in FAIL_EVENTS:
        st = "failure"
    return ev, st


def _valid_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def parse_csv(path):
    try:
        raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    except Exception as exc:
        raise ValueError(f"Could not read CSV file: {exc}")
    raw.columns = [c.strip().lower() for c in raw.columns]
    cols = {}
    for target, names in ALIASES.items():
        for n in names:
            if n in raw.columns:
                cols[target] = n
                break
    missing = [c for c in ("event_time", "ip_address") if c not in cols]
    if missing:
        raise ValueError("CSV must contain a time column and an IP column "
                         f"(missing: {', '.join(missing)}). Accepted names: timestamp/time, ip/ip_address/src_ip.")
    df = pd.DataFrame({
        "event_time": pd.to_datetime(raw[cols["event_time"]], errors="coerce"),
        "ip_address": raw[cols["ip_address"]].str.strip(),
        "username": raw[cols["username"]].str.strip() if "username" in cols else "unknown",
        "_event": raw[cols["event_type"]] if "event_type" in cols else "other",
        "_status": raw[cols["status"]] if "status" in cols else None,
    })
    total = len(df)
    df = df.dropna(subset=["event_time"])
    df = df[df["ip_address"].map(_valid_ip)]
    df["username"] = df["username"].replace("", "unknown")
    pairs = [_finish(e, s) for e, s in zip(df["_event"], df["_status"] if "status" in cols else [None] * len(df))]
    df["event_type"] = [p[0] for p in pairs]
    df["status"] = [p[1] for p in pairs]
    df["event_time"] = df["event_time"].dt.tz_localize(None) if df["event_time"].dt.tz is not None else df["event_time"]
    df["event_time"] = df["event_time"].dt.strftime("%Y-%m-%d %H:%M:%S")
    df = df[["event_time", "ip_address", "username", "event_type", "status"]]
    return df, {"lines": total, "parsed": len(df), "skipped": total - len(df)}


ISO = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
SYS = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER = [re.compile(p, re.I) for p in (
    r"for (?:invalid user )?(\S+) from", r"invalid user (\S+)", r"\buser[=: ]+\"?([\w.\-@]+)", r"\bacct[=:]\s*(\w+)")]


def parse_text(path):
    rows, total, now = [], 0, datetime.now()
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            ts = None
            m = ISO.search(line)
            if m:
                ts = pd.to_datetime(m.group(1).replace("T", " "), errors="coerce")
            else:
                m = SYS.search(line)
                if m:
                    try:
                        ts = datetime.strptime(f"{now.year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")
                        if ts > now:
                            ts = ts.replace(year=now.year - 1)
                    except ValueError:
                        ts = None
            ips = [i for i in IP.findall(line) if _valid_ip(i)]
            if ts is None or pd.isna(ts) or not ips:
                continue
            user = "unknown"
            for rx in USER:
                um = rx.search(line)
                if um:
                    user = um.group(1)
                    break
            ev, st = _finish(line, None)
            rows.append((pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M:%S"), ips[0], user, ev, st))
    df = pd.DataFrame(rows, columns=["event_time", "ip_address", "username", "event_type", "status"])
    return df, {"lines": total, "parsed": len(df), "skipped": total - len(df)}


def parse_file(path, ext):
    df, stats = parse_csv(path) if ext == "csv" else parse_text(path)
    if df.empty:
        raise ValueError("No valid log records could be parsed from this file.")
    return df, stats
