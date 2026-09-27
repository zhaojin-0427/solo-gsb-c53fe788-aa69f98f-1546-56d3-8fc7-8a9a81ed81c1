"""SQLite 持久化：保存每次实验的输入参数、按角色持久化的上传证书与完整分析结果。"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

from . import cert_core as cc

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    verify_time TEXT,
    dns_name TEXT,
    purpose TEXT,
    leaf_count INTEGER DEFAULT 0,
    intermediate_count INTEGER DEFAULT 0,
    anchor_count INTEGER DEFAULT 0,
    result_json TEXT NOT NULL
);

-- 新会话按角色持久化原始上传证书（PEM），供信任锚替换预演无损重放。
-- 旧会话没有对应行：前端与预演接口据此明确标记为「不可预演」。
CREATE TABLE IF NOT EXISTS session_certs (
    session_id INTEGER NOT NULL,
    role TEXT NOT NULL,              -- leaf / intermediate / anchor
    position INTEGER NOT NULL,       -- 去重后的上传顺序
    fingerprint TEXT NOT NULL,       -- SHA-256 指纹
    cert_pem TEXT NOT NULL,
    PRIMARY KEY (session_id, role, position)
);
"""

ROLE_KEYS = ("leaf", "intermediate", "anchor")


def connect(db_path: str | Path) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path: str | Path) -> None:
    with _LOCK, connect(db_path) as conn:
        conn.executescript(SCHEMA)


def _dedupe(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    """按指纹去重并保持首次出现顺序（同一角色内重复上传不产生多余行）。"""
    seen: set[str] = set()
    out = []
    for cert in certs:
        f = cc.fp(cert)
        if f in seen:
            continue
        seen.add(f)
        out.append(cert)
    return out


def save_session(db_path, *, verify_time: str, dns_name, purpose,
                 leaf_count: int, intermediate_count: int, anchor_count: int,
                 result: dict, certs: dict | None = None) -> int:
    """保存一次实验。certs 给定时（新会话）在同一事务内按角色持久化原始证书，
    形如 {"leaf": [...], "intermediate": [...], "anchor": [...]}。"""
    certs = certs or {}
    with _LOCK, connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO sessions
               (created_at, verify_time, dns_name, purpose,
                leaf_count, intermediate_count, anchor_count, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now(timezone.utc).isoformat(), verify_time, dns_name, purpose,
             leaf_count, intermediate_count, anchor_count, json.dumps(result, ensure_ascii=False)),
        )
        session_id = cur.lastrowid
        for role in ROLE_KEYS:
            for pos, cert in enumerate(_dedupe(certs.get(role, []))):
                conn.execute(
                    """INSERT INTO session_certs (session_id, role, position, fingerprint, cert_pem)
                       VALUES (?, ?, ?, ?, ?)""",
                    (session_id, role, pos, cc.fp(cert), cc.cert_to_pem(cert)),
                )
        return session_id


def list_sessions(db_path, limit: int = 50) -> list[dict]:
    with _LOCK, connect(db_path) as conn:
        rows = conn.execute(
            """SELECT s.id, s.created_at, s.verify_time, s.dns_name, s.purpose,
                      s.leaf_count, s.intermediate_count, s.anchor_count,
                      EXISTS (SELECT 1 FROM session_certs c
                              WHERE c.session_id = s.id AND c.role = 'leaf') AS replayable
               FROM sessions s ORDER BY s.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_session(db_path, session_id: int) -> dict | None:
    with _LOCK, connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["result"] = json.loads(d.pop("result_json"))
        d["replayable"] = bool(conn.execute(
            "SELECT 1 FROM session_certs WHERE session_id = ? AND role = 'leaf' LIMIT 1",
            (session_id,),
        ).fetchone())
        return d


def get_session_certs(db_path, session_id: int) -> dict[str, list[str]]:
    """返回按角色分组的原始证书 PEM（字符串），保持上传顺序。

    旧会话在 session_certs 中没有任何行，三个角色均返回空列表；
    调用方以 leaf 是否为空区分「可重放」与「不可预演」（叶证书至少有一本）。
    """
    out: dict[str, list[str]] = {role: [] for role in ROLE_KEYS}
    with _LOCK, connect(db_path) as conn:
        rows = conn.execute(
            """SELECT role, cert_pem FROM session_certs
               WHERE session_id = ? ORDER BY role, position""",
            (session_id,),
        ).fetchall()
    for r in rows:
        out[r["role"]].append(r["cert_pem"])
    return out
