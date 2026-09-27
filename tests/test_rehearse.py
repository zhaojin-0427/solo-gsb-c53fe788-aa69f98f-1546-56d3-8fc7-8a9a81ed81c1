"""信任锚替换预演测试：重放、按叶指纹对齐、有效性翻转/选中链变化/无变化、
旧会话不可预演、基线漂移、只读不新增会话。"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from cryptography.x509.oid import ExtendedKeyUsageOID

from app import cert_core as cc
from app import db as database
from app import rehearse as rh
from app.service import analyze
from scripts.generate_samples import issue, key_ec, name, self_signed_root

T = datetime(2025, 6, 1, tzinfo=timezone.utc)


def _save(db_path, leaves, inters, anchors, dns="www.example.com", purpose="serverAuth"):
    result = analyze(leaves, inters, anchors, verify_time=T, dns_name=dns,
                     purpose_key=purpose)
    return database.save_session(
        db_path,
        verify_time=result["params"]["verify_time"],
        dns_name=dns, purpose=purpose,
        leaf_count=len(leaves), intermediate_count=len(inters),
        anchor_count=len(anchors), result=result,
        certs={"leaf": leaves, "intermediate": inters, "anchor": anchors},
    )


def _run(db_path, ids, anchors):
    return rh.rehearse(
        lambda sid: database.get_session(db_path, sid),
        lambda sid: database.get_session_certs(db_path, sid),
        ids, anchors,
    )


def _standard_chain(cn="www.example.com"):
    root, rk = self_signed_root("Root A")
    ica, ik = issue(name("ICA A"), root, rk, ca=True, path_len=0)
    leaf, _ = issue(name(cn), ica, ik, dns=[cn],
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    return root, rk, ica, ik, leaf


# ---------------------------------------------------------------------------
def test_new_session_persists_certs_by_role(tmp_path):
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root, rk, ica, ik, leaf = _standard_chain()
    sid = _save(dbp, [leaf], [ica], [root])

    pems = database.get_session_certs(dbp, sid)
    assert len(pems["leaf"]) == 1
    assert len(pems["intermediate"]) == 1
    assert len(pems["anchor"]) == 1
    # PEM 可无损还原，指纹与原证书一致
    assert cc.fp(cc.load_certificates(pems["leaf"][0].encode())[0]) == cc.fp(leaf)
    row = database.get_session(dbp, sid)
    assert row["replayable"] is True


def test_rehearse_validity_flip(tmp_path):
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root, rk, ica, ik, leaf = _standard_chain()
    sid = _save(dbp, [leaf], [ica], [root])

    # 替代锚是一本无关自签根：原链无法到达信任点 → 有效翻转为无效
    other, _ = self_signed_root("Root B")
    rep = _run(dbp, [sid], [other])
    assert rep["summary"]["sessions"] == 1

    s = rep["sessions"][0]
    assert s["status"] == "ok" and s["replayable"] is True
    assert s["outcome"] == "changed"
    assert s["leaf_counts"]["validity_flip"] == 1

    leaf_diff = s["leaves"][0]
    assert leaf_diff["outcome"] == "validity_flip"
    assert leaf_diff["baseline"]["valid"] is True
    assert leaf_diff["alternative"]["valid"] is False
    # 两侧选中路径：基线为 叶→ICA→根，替代侧无选中链
    assert leaf_diff["baseline"]["selected_path"] == [cc.fp(leaf), cc.fp(ica), cc.fp(root)]
    assert leaf_diff["alternative"]["selected_path"] is None

    # 新增 / 移除锚的指纹
    added = {a["fingerprint"] for a in s["anchors_added"]}
    removed = {a["fingerprint"] for a in s["anchors_removed"]}
    assert added == {cc.fp(other)}
    assert removed == {cc.fp(root)}


def test_rehearse_unchanged_when_anchor_set_equal(tmp_path):
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root, rk, ica, ik, leaf = _standard_chain()
    sid = _save(dbp, [leaf], [ica], [root])

    rep = _run(dbp, [sid], [root])  # 同组锚重放
    s = rep["sessions"][0]
    assert s["outcome"] == "unchanged"
    assert s["leaf_counts"] == {"validity_flip": 0, "chain_changed": 0,
                                "unchanged": 1, "baseline_drift": 0}
    assert s["anchors_added"] == [] and s["anchors_removed"] == []
    d = s["leaves"][0]
    assert d["baseline"]["selected_path"] == d["alternative"]["selected_path"]


def test_rehearse_cross_signed_chain_changed(tmp_path):
    """交叉签发两条有效链：基线含两根，替代只保留未被选中的那根 → 选中链变化。"""
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root_a, rak = self_signed_root("Root AA")
    root_b, rbk = self_signed_root("Root BB")
    ik = key_ec()
    ica_a, _ = issue(name("Shared ICA"), root_a, rak, subject_key=ik, ca=True, path_len=0)
    ica_b, _ = issue(name("Shared ICA"), root_b, rbk, subject_key=ik, ca=True, path_len=0)
    leaf, _ = issue(name("s.example.com"), ica_a, ik, dns=["s.example.com"],
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    sid = _save(dbp, [leaf], [ica_a, ica_b], [root_a, root_b], dns="s.example.com")

    baseline = analyze([leaf], [ica_a, ica_b], [root_a, root_b],
                       verify_time=T, dns_name="s.example.com", purpose_key="serverAuth")
    base_path = baseline["leaves"][0]["chains"][baseline["leaves"][0]["selected_index"]]["ids"]
    # 基线选中链终止的根
    chosen_root_fp = base_path[-1]
    kept = root_b if chosen_root_fp == cc.fp(root_a) else root_a
    removed_root = root_a if chosen_root_fp == cc.fp(root_a) else root_b

    rep = _run(dbp, [sid], [kept])
    s = rep["sessions"][0]
    assert s["outcome"] == "changed", s
    assert s["leaf_counts"]["chain_changed"] == 1
    d = s["leaves"][0]
    assert d["outcome"] == "chain_changed"
    assert d["baseline"]["valid"] and d["alternative"]["valid"]
    assert d["baseline"]["selected_path"][-1] == chosen_root_fp
    assert d["alternative"]["selected_path"][-1] == cc.fp(kept)
    assert {a["fingerprint"] for a in s["anchors_removed"]} == {cc.fp(removed_root)}
    assert d["baseline"]["selected_subjects"]
    assert d["alternative"]["selected_subjects"]


def test_rehearse_empty_anchors_flips_to_untrusted(tmp_path):
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root, rk, ica, ik, leaf = _standard_chain()
    sid = _save(dbp, [leaf], [ica], [root])

    rep = _run(dbp, [sid], [])  # 移除全部锚
    s = rep["sessions"][0]
    assert s["leaf_counts"]["validity_flip"] == 1
    assert {a["fingerprint"] for a in s["anchors_removed"]} == {cc.fp(root)}
    assert s["anchors_added"] == []


def test_old_session_without_certs_is_not_replayable(tmp_path):
    """模拟旧版数据：sessions 有行但 session_certs 无任何证书 → 明确不可预演。"""
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    with database.connect(dbp) as conn:
        cur = conn.execute(
            """INSERT INTO sessions
               (created_at, verify_time, dns_name, purpose,
                leaf_count, intermediate_count, anchor_count, result_json)
               VALUES (?, ?, ?, ?, 1, 1, 1, ?)""",
            (datetime.now(timezone.utc).isoformat(), T.isoformat(), "x.example.com",
             "serverAuth", json.dumps({"params": {"verify_time": T.isoformat()},
                                       "graph": {"nodes": [], "edges": []},
                                       "leaves": []})),
        )
        sid = cur.lastrowid

    assert database.get_session(dbp, sid)["replayable"] is False
    rep = _run(dbp, [sid], [])
    s = rep["sessions"][0]
    assert s["replayable"] is False
    assert s["outcome"] == "not_replayable"
    assert "不可预演" in s["reason"] or "无法无损重放" in s["reason"]
    assert rep["summary"]["not_replayable"] == 1


def test_baseline_drift_marked_and_not_attributed(tmp_path):
    """篡改存档结论（selected_index 置空）后重放：基线与存档不一致 → baseline_drift，
    不报告为锚替换造成的翻转/链变化。"""
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root, rk, ica, ik, leaf = _standard_chain()
    sid = _save(dbp, [leaf], [ica], [root])

    other, _ = self_signed_root("Root B")
    with database.connect(dbp) as conn:
        row = conn.execute("SELECT result_json FROM sessions WHERE id=?", (sid,)).fetchone()
        archived = json.loads(row["result_json"])
        archived["leaves"][0]["selected_index"] = None  # 存档声称：无有效链
        conn.execute("UPDATE sessions SET result_json=? WHERE id=?",
                     (json.dumps(archived), sid))

    rep = _run(dbp, [sid], [other])
    s = rep["sessions"][0]
    assert s["outcome"] == "baseline_drift"
    assert s["baseline_drift"] is True
    d = s["leaves"][0]
    assert d["outcome"] == "baseline_drift"
    assert d["archived"]["valid"] is False
    assert d["baseline"]["valid"] is True


def test_baseline_drift_when_failure_rule_changes(tmp_path):
    """存档与基线重放都无有效链，但首败规则不同（UNTRUSTED_ROOT→存档被改成 LOOP），
    同样属于基线漂移，不能归因于锚替换。"""
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root, rk, ica, ik, leaf = _standard_chain()
    # 存档时就没有锚：基线重放必然 UNTRUSTED_ROOT
    result = analyze([leaf], [ica], [], verify_time=T, dns_name="www.example.com",
                     purpose_key="serverAuth")
    sid = database.save_session(
        dbp, verify_time=T.isoformat(), dns_name="www.example.com", purpose="serverAuth",
        leaf_count=1, intermediate_count=1, anchor_count=0, result=result,
        certs={"leaf": [leaf], "intermediate": [ica], "anchor": []})
    # 篡改存档首败规则
    with database.connect(dbp) as conn:
        row = conn.execute("SELECT result_json FROM sessions WHERE id=?", (sid,)).fetchone()
        archived = json.loads(row["result_json"])
        for c in archived["leaves"][0]["chains"]:
            if c["failure"] and c["failure"]["rule"] == "UNTRUSTED_ROOT":
                c["failure"]["rule"] = "LOOP"
        conn.execute("UPDATE sessions SET result_json=? WHERE id=?",
                     (json.dumps(archived), sid))

    other, _ = self_signed_root("Root B")
    rep = _run(dbp, [sid], [other])
    s = rep["sessions"][0]
    assert s["outcome"] == "baseline_drift"
    assert s["leaves"][0]["outcome"] == "baseline_drift"


def test_rehearse_is_readonly_no_new_session(tmp_path):
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root, rk, ica, ik, leaf = _standard_chain()
    sid = _save(dbp, [leaf], [ica], [root])
    before = database.list_sessions(dbp)
    assert len(before) == 1

    other, _ = self_signed_root("Root B")
    _run(dbp, [sid], [other])
    _run(dbp, [sid], [])
    assert len(database.list_sessions(dbp)) == 1
    # 原报告未被改写
    row = database.get_session(dbp, sid)
    assert row["result"]["leaves"][0]["selected_index"] is not None


def test_rehearse_multiple_sessions_aggregation_and_missing(tmp_path):
    dbp = tmp_path / "lab.db"
    database.init_db(dbp)
    root, rk, ica, ik, leaf = _standard_chain()
    s1 = _save(dbp, [leaf], [ica], [root])
    s2 = _save(dbp, [leaf], [ica], [root])

    rep = _run(dbp, [s1, s2, 999], [root])
    assert rep["summary"]["sessions"] == 2
    assert rep["summary"]["unchanged"] == 2
    assert rep["summary"]["errors"] == 1
    errors = [s for s in rep["sessions"] if s["status"] == "error"]
    assert errors and errors[0]["session_id"] == 999
    # 顺序与选择顺序一致
    assert [s["session_id"] for s in rep["sessions"] if s["status"] == "ok"] == [s1, s2]
