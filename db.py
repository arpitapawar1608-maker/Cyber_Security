"""Database layer: connection handling, schema (4 tables) and seed data."""
import os
import sqlite3

from flask import current_app, g
from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin'))
);

CREATE TABLE IF NOT EXISTS log_sources (
    source_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL UNIQUE,
    server_name TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT 'auth'
);

CREATE TABLE IF NOT EXISTS security_logs (
    log_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id  INTEGER NOT NULL REFERENCES log_sources(source_id) ON DELETE CASCADE,
    event_time TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    username   TEXT,
    event_type TEXT NOT NULL,
    status     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_time ON security_logs(event_time);
CREATE INDEX IF NOT EXISTS idx_logs_ip   ON security_logs(ip_address);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id     INTEGER NOT NULL REFERENCES security_logs(log_id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('Low','Medium','High','Critical')),
    score      REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    status     TEXT NOT NULL DEFAULT 'Open'
               CHECK (status IN ('Open','Investigating','Resolved','False Positive'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    con = sqlite3.connect(app.config["DATABASE"])
    con.executescript(SCHEMA)
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        con.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                    ("admin", generate_password_hash("Admin@123"), "admin"))
    if con.execute("SELECT COUNT(*) FROM log_sources").fetchone()[0] == 0:
        con.execute("INSERT INTO log_sources (source_name, server_name, source_type) VALUES (?,?,?)",
                    ("Web Server Auth Log", "web-01", "auth"))
    con.commit()
    con.close()
