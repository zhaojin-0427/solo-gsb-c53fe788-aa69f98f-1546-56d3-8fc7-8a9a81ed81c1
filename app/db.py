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

-- 离线 CSR 签发的幂等记录：单行同时承载幂等键、请求哈希、序列号与证书 PEM，
-- 一次 INSERT 即完成「证书 + 序列号 + 幂等记录」的原子提交（失败整体回滚）。
CREATE TABLE IF NOT EXISTS issuance_records (
    idem_key TEXT PRIMARY KEY,          -- 幂等键
    request_hash TEXT NOT NULL,         -- 规范化 CSR + 签发者指纹 + 起止时间 的 SHA-256
    issuer_fp TEXT NOT NULL,            -- 签发者证书 SHA-256 指纹
    issuer_spki_fp TEXT NOT NULL,       -- 签发者公钥（SPKI）：序列号唯一性作用域
    serial_hex TEXT NOT NULL,           -- 叶证书序列号（十六进制）
    subject TEXT NOT NULL,
    dns_names TEXT NOT NULL,            -- JSON 数组
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,             -- 签发的叶证书（PEM），幂等重放时原样返回
    created_at TEXT NOT NULL
);

-- 同一签发者公钥下序列号不得重复（硬约束，配合应用层的确定性派生）
CREATE UNIQUE INDEX IF NOT EXISTS idx_issuance_serial
    ON issuance_records (issuer_spki_fp, serial_hex);
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


# ============================================================================
# 离线 CSR 签发：幂等记录
# ============================================================================
def get_issuance(db_path, idem_key: str) -> dict | None:
    """按幂等键查询签发记录；不存在返回 None。"""
    with _LOCK, connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM issuance_records WHERE idem_key = ?", (idem_key,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["dns_names"] = json.loads(d["dns_names"])
        return d


def commit_issuance(db_path, record: dict) -> None:
    """原子提交签发记录（证书 PEM + 序列号 + 幂等键在同一行、同一事务）。

    idem_key 冲突或 (issuer_spki_fp, serial_hex) 冲突时抛出
    sqlite3.IntegrityError，由调用方决定重放 / 409 / 重派生序列号。
    """
    with _LOCK, connect(db_path) as conn:
        conn.execute(
            """INSERT INTO issuance_records
               (idem_key, request_hash, issuer_fp, issuer_spki_fp, serial_hex,
                subject, dns_names, not_before, not_after, cert_pem, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (record["idem_key"], record["request_hash"], record["issuer_fp"],
             record["issuer_spki_fp"], record["serial_hex"], record["subject"],
             json.dumps(record["dns_names"], ensure_ascii=False),
             record["not_before"], record["not_after"], record["cert_pem"],
             record["created_at"]),
        )


def count_issuances(db_path) -> int:
    """签发记录总数（测试与自检用）。"""
    with _LOCK, connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM issuance_records").fetchone()["c"]
