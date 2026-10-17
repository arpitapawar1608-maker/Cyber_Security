"""Data-access layer: every SQL statement lives here."""
import pandas as pd

from db import get_db


def q(sql, args=()):
    return [dict(r) for r in get_db().execute(sql, args).fetchall()]


def q1(sql, args=()):
    r = get_db().execute(sql, args).fetchone()
    return dict(r) if r else None


def run(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


# ---- users -----------------------------------------------------------------
def get_user_by_name(username):
    return q1("SELECT * FROM users WHERE username = ?", (username,))


def create_user(username, password_hash, role="analyst"):
    return run("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)", (username, password_hash, role))


# ---- master data: log sources ---------------------------------------------
def list_sources():
    return q("""SELECT s.*, (SELECT COUNT(*) FROM security_logs l WHERE l.source_id = s.source_id) AS log_count
                FROM log_sources s ORDER BY s.source_name""")


def get_source(sid):
    return q1("SELECT * FROM log_sources WHERE source_id = ?", (sid,))


def create_source(name, server, stype):
    return run("INSERT INTO log_sources (source_name, server_name, source_type) VALUES (?,?,?)", (name, server, stype))


def update_source(sid, name, server, stype):
    run("UPDATE log_sources SET source_name=?, server_name=?, source_type=? WHERE source_id=?", (name, server, stype, sid))


def delete_source(sid):
    run("DELETE FROM log_sources WHERE source_id = ?", (sid,))


# ---- security logs ---------------------------------------------------------
def insert_logs(df, source_id):
    db = get_db()
    rows = [(source_id, r.event_time, r.ip_address, r.username, r.event_type, r.status) for r in df.itertuples()]
    db.executemany("""INSERT INTO security_logs (source_id, event_time, ip_address, username, event_type, status)
                      VALUES (?,?,?,?,?,?)""", rows)
    db.commit()
    return len(rows)


def fetch_logs_df(source_id=None):
    sql, args = "SELECT log_id, source_id, event_time, ip_address, username, event_type, status FROM security_logs", []
    if source_id:
        sql += " WHERE source_id = ?"
        args.append(source_id)
    df = pd.read_sql_query(sql + " ORDER BY event_time", get_db(), params=args)
    df["event_time"] = pd.to_datetime(df["event_time"])
    return df


def export_logs(limit=50000):
    return q("""SELECT l.log_id, s.source_name, s.server_name, l.event_time, l.ip_address, l.username,
                       l.event_type, l.status FROM security_logs l JOIN log_sources s ON s.source_id=l.source_id
                ORDER BY l.event_time DESC LIMIT ?""", (limit,))


# ---- alerts ----------------------------------------------------------------
SEV_ORDER = "CASE a.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END"


def list_alerts(status=None, severity=None, source_id=None, by_time=False, limit=500):
    where, args = [], []
    for col, val in (("a.status", status), ("a.severity", severity), ("l.source_id", source_id)):
        if val:
            where.append(f"{col} = ?")
            args.append(val)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    order = "a.created_at DESC, a.alert_id DESC" if by_time else f"{SEV_ORDER}, a.score DESC"
    return q(f"""SELECT a.*, l.ip_address, l.username, l.event_time, s.source_name
                 FROM alerts a JOIN security_logs l ON l.log_id = a.log_id
                 JOIN log_sources s ON s.source_id = l.source_id {w}
                 ORDER BY {order} LIMIT ?""", args + [limit])


def insert_alerts(alerts):
    db, created = get_db(), 0
    for a in alerts:
        if db.execute("SELECT 1 FROM alerts WHERE log_id=? AND alert_type=?", (a["log_id"], a["alert_type"])).fetchone():
            continue
        db.execute("INSERT INTO alerts (log_id, alert_type, severity, score, created_at) VALUES (?,?,?,?,datetime('now','localtime'))",
                   (a["log_id"], a["alert_type"], a["severity"], a["score"]))
        created += 1
    db.commit()
    return created


def update_alert_status(alert_id, status):
    run("UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id))


def alert_summary(source_id=None):
    where, args = ("WHERE l.source_id = ?", [source_id]) if source_id else ("", [])
    base = f"FROM alerts a JOIN security_logs l ON l.log_id = a.log_id {where}"
    sev = {r["k"]: r["n"] for r in q(f"SELECT a.severity k, COUNT(*) n {base} GROUP BY a.severity", args)}
    sta = {r["k"]: r["n"] for r in q(f"SELECT a.status k, COUNT(*) n {base} GROUP BY a.status", args)}
    return {"severity": sev, "status": sta}
