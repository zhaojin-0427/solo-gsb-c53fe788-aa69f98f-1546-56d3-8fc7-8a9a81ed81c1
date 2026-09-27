"""端到端核验引擎冒烟测试：对每个样例场景断言首个失败规则/选链结果。"""
from datetime import datetime, timezone
from pathlib import Path

from app import cert_core as cc
from app.service import analyze

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def load_dir(role_dir: Path):
    certs = []
    if role_dir.exists():
        for f in sorted(role_dir.iterdir()):
            # 跳过 DER 重复样本（标准场景单独测试 DER）
            if f.suffix in (".pem", ".der") and f.name != "leaf-der.der":
                certs.extend(cc.load_certificates(f.read_bytes()))
    return certs


CASES = {
    "01-standard": ("2025-06-01T00:00:00Z", "www.example.com", "serverAuth", None, 1, 1),
    "02-cross-signed": ("2025-06-01T00:00:00Z", "app.example.com", "serverAuth", None, 2, 2),
    "03-same-name": ("2025-06-01T00:00:00Z", "bank.example.com", "serverAuth", "UNTRUSTED_ROOT", 0, 4),
    "05-expired": ("2025-06-01T00:00:00Z", "old.example.com", "serverAuth", "VALIDITY", 0, 1),
    "06-pathlen": ("2025-06-01T00:00:00Z", "deep.example.com", "serverAuth", "PATH_LEN", 0, 1),
    "07-name-constraints": ("2025-06-01T00:00:00Z", "www.evil.example.com", "serverAuth", "NAME_CONSTRAINTS", 0, 1),
    "08-eku": ("2025-06-01T00:00:00Z", "client.example.com", "serverAuth", "EXTENDED_KEY_USAGE", 0, 1),
    "09-hostname": ("2025-06-01T00:00:00Z", "wrong.example.com", "serverAuth", "HOSTNAME", 0, 1),
}


def run_case(sid, vt, dns, purpose, expect_rule, expect_valid, expect_chains):
    d = SAMPLES / sid
    leaves = load_dir(d / "leaf")
    inters = load_dir(d / "intermediates")
    anchors = load_dir(d / "anchors")
    t = datetime.fromisoformat(vt.replace("Z", "+00:00")) if vt else datetime.now(timezone.utc)
    res = analyze(leaves, inters, anchors, t, dns, purpose)
    lr = res["leaves"][0]
    assert lr["candidate_count"] == expect_chains, (sid, lr["candidate_count"])
    assert lr["valid_count"] == expect_valid, (sid, lr["valid_count"])
    if expect_rule is None:
        assert lr["selected_index"] == 0, sid
    else:
        # 所有候选链都失败，且选中链为 None；检查每条链第一个失败，至少一条命中预期规则
        rules = [c["failure"]["rule"] for c in lr["chains"] if c["failure"]]
        assert expect_rule in rules, (sid, rules)
    return res


def test_all_scenarios():
    for sid, (vt, dns, purpose, rule, valid, chains) in CASES.items():
        run_case(sid, vt, dns, purpose, rule, valid, chains)


def test_loop():
    d = SAMPLES / "04-loop"
    leaves = load_dir(d / "leaf")
    inters = load_dir(d / "intermediates")
    res = analyze(leaves, inters, [],
                  datetime(2025, 6, 1, tzinfo=timezone.utc),
                  "loop.example.com", "serverAuth")
    lr = res["leaves"][0]
    rules = [c["failure"]["rule"] for c in lr["chains"] if c["failure"]]
    assert "LOOP" in rules, rules
    assert lr["valid_count"] == 0


def test_same_name_scenario_reports_signature_paths():
    """场景 03（同名不同钥）：主体名可相连但验签失败的边必须产生 SIGNATURE
    淘汰链（首个签名失败节点 + 结构化证据），且 LOOP / UNTRUSTED_ROOT 语义不变。"""
    d = SAMPLES / "03-same-name"
    leaves = load_dir(d / "leaf")
    inters = load_dir(d / "intermediates")
    anchors = load_dir(d / "anchors")
    res = analyze(leaves, inters, anchors,
                  datetime(2025, 6, 1, tzinfo=timezone.utc),
                  "bank.example.com", "serverAuth")
    lr = res["leaves"][0]
    assert lr["valid_count"] == 0
    assert lr["selected_index"] is None
    assert lr["eliminated_count"] == lr["candidate_count"]
    rules = [c["failure"]["rule"] for c in lr["chains"] if c["failure"]]
    # 验签失败的候选路径进入淘汰列表；原有环路 / 未达锚路径保持原语义
    assert "SIGNATURE" in rules, rules
    assert "LOOP" in rules, rules
    assert "UNTRUSTED_ROOT" in rules, rules
    # 每条 SIGNATURE 链：断边终点是候选签发者，首败节点是签名无法验证的证书
    for c in lr["chains"]:
        f = c["failure"]
        if f and f["rule"] == "SIGNATURE":
            assert f["node"] == c["ids"][-2]
            assert f["node_index"] == len(c["ids"]) - 2
            assert f["issuer_fp"] == c["ids"][-1]
            assert f["signature_algorithm"]
            assert f["sig_error"]
            assert f["rule_label"] == "签名核验"
            assert f["rule_ref"]
            # 图上对应边仍是红色虚线（不可走）
            edge = next(e for e in res["graph"]["edges"]
                        if e["source"] == c["ids"][-2] and e["target"] == c["ids"][-1])
            assert edge["sig_ok"] is False and edge["usable"] is False
            assert edge["sig_failed"] is True


def test_der_loading():
    der_bytes = (SAMPLES / "01-standard" / "leaf" / "leaf-der.der").read_bytes()
    certs = cc.load_certificates(der_bytes)
    assert len(certs) == 1


def test_dns_match():
    assert cc.dns_match("*.example.com", "a.example.com")
    assert not cc.dns_match("*.example.com", "a.b.example.com")
    assert cc.dns_match("WWW.Example.COM", "www.example.com")
    assert not cc.dns_match("*", "evil.com")
