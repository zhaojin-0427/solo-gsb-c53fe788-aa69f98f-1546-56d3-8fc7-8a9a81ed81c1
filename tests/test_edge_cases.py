"""额外边界行为测试。"""
import datetime as dt
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from app import cert_core as cc
from app.service import analyze
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.generate_samples import self_signed_root, issue, name  # noqa: E402

T = datetime(2025, 6, 1, tzinfo=timezone.utc)


def test_anchor_at_intermediate():
    """信任锚直接是签发叶证书的 ICA（无自签根在场）也应成链。"""
    ica, ik = self_signed_root("Trusted ICA as Anchor")
    leaf, _ = issue(name("direct.example.com"), ica, ik,
                    dns=["direct.example.com"], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    res = analyze([leaf], [], [ica], T, "direct.example.com", "serverAuth")
    lr = res["leaves"][0]
    assert lr["valid_count"] == 1, lr
    assert lr["selected_index"] == 0


def test_no_eku_check_when_purpose_empty():
    root, rk = self_signed_root("Root")
    ica, ik = issue(name("ICA"), root, rk, ca=True, path_len=0)
    leaf, _ = issue(name("x.example.com"), ica, ik, dns=["x.example.com"],
                    eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    res = analyze([leaf], [ica], [root], T, "x.example.com", "")
    assert res["leaves"][0]["valid_count"] == 1


def test_wildcard_not_cross_label():
    assert cc.dns_match("*.example.com", "a.example.com")
    assert not cc.dns_match("*.example.com", "a.b.example.com")
    assert not cc.dns_match("*.example.com", "example.com")
    # 多星号非法
    assert not cc.dns_match("a.*.com", "a.b.com")
    # 大小写与尾点
    assert cc.dns_match("WWW.EXAMPLE.COM.", "www.example.com")


def test_self_signed_leaf_is_untrusted():
    """自签叶证书：即使链终止于自身，只要没上传对应锚也不信任。"""
    root, rk = self_signed_root("Self Leaf")
    res = analyze([root], [], [], T, None, None)
    lr = res["leaves"][0]
    assert lr["valid_count"] == 0
    assert lr["chains"][0]["failure"]["rule"] == "UNTRUSTED_ROOT"


def test_self_signed_leaf_as_anchor_trusted():
    root, _ = self_signed_root("Self Leaf Trusted")
    res = analyze([root], [], [root], T, None, None)
    lr = res["leaves"][0]
    assert lr["valid_count"] == 1
    assert lr["chains"][0]["length"] == 1


def test_not_yet_valid():
    root, rk = self_signed_root("R")
    ica, ik = issue(name("I"), root, rk, ca=True, path_len=0)
    leaf, _ = issue(
        name("future.example.com"), ica, ik, dns=["future.example.com"],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        not_before=dt.datetime(2028, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc),
    )
    res = analyze([leaf], [ica], [root], T, "future.example.com", "serverAuth")
    lr = res["leaves"][0]
    assert lr["chains"][0]["failure"]["rule"] == "VALIDITY"
    assert "尚未生效" in lr["chains"][0]["failure"]["message"]


def test_deterministic_selection_across_order():
    """交叉签发：交换中间证书上传顺序，选中链的指纹序列必须一致。"""
    root_a, rak = self_signed_root("Root AA")
    root_b, rbk = self_signed_root("Root BB")
    from scripts.generate_samples import key_ec
    ik = key_ec()
    ica_a, _ = issue(name("Shared ICA"), root_a, rak, subject_key=ik, ca=True, path_len=0)
    ica_b, _ = issue(name("Shared ICA"), root_b, rbk, subject_key=ik, ca=True, path_len=0)
    leaf, _ = issue(name("s.example.com"), ica_a, ik, dns=["s.example.com"],
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])

    r1 = analyze([leaf], [ica_a, ica_b], [root_a, root_b], T, "s.example.com", "serverAuth")
    r2 = analyze([leaf], [ica_b, ica_a], [root_b, root_a], T, "s.example.com", "serverAuth")
    ids1 = r1["leaves"][0]["chains"][r1["leaves"][0]["selected_index"]]["ids"]
    ids2 = r2["leaves"][0]["chains"][r2["leaves"][0]["selected_index"]]["ids"]
    assert ids1 == ids2


def test_signature_tamper_detected():
    root, rk = self_signed_root("R")
    ica, ik = issue(name("I"), root, rk, ca=True, path_len=0)
    leaf, _ = issue(name("t.example.com"), ica, ik, dns=["t.example.com"],
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    # 用错误的密钥签发“同名 CA”（DN 完全一致、公钥不同），验证签边失败
    rogue, gk = self_signed_root("I", o="Lab")
    leaf2, _ = issue(name("t2.example.com"), rogue, gk, dns=["t2.example.com"],
                     eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    res = analyze([leaf2], [ica], [root], T, "t2.example.com", "serverAuth")
    g = res["graph"]
    assert any(not e["sig_ok"] for e in g["edges"]), g["edges"]
    lr = res["leaves"][0]
    assert lr["valid_count"] == 0
    # 验签失败的同名候选路径必须进入淘汰列表：SIGNATURE 规则 + 首个失败节点 + 结构化证据
    sig = [c for c in lr["chains"] if c["failure"] and c["failure"]["rule"] == "SIGNATURE"]
    assert len(sig) == 1, lr["chains"]
    chain, f = sig[0], sig[0]["failure"]
    leaf2_fp, ica_fp = cc.fp(leaf2), cc.fp(ica)
    assert chain["ids"] == [leaf2_fp, ica_fp]      # 路径在断边处终止，不继续向上枚举
    assert chain["complete"] is False
    assert f["node"] == leaf2_fp                   # 首个签名失败节点 = 签名无法验证的证书
    assert f["node_index"] == 0
    assert f["issuer_fp"] == ica_fp
    assert f["issuer"] == cc.name_one_line(ica.subject)
    assert f["sig_error"]
    assert f["signature_algorithm"]
    assert "aki_ski_match" in f
    assert f["rule_label"] == "签名核验"
    assert f["rule_ref"]


def test_signature_failed_path_eliminated_valid_chain_still_selected():
    """同一叶证书既有「同名不同钥、验签失败」的候选签发者边，又有可验签并
    到达信任锚的路径：失败路径进淘汰列表且不计入有效链，有效链按原稳定规则选出。"""
    root, rk = self_signed_root("Anchor Root", o="Real CA")
    ica, ik = issue(name("Shared ICA"), root, rk, ca=True, path_len=0)
    rogue, gk = self_signed_root("Rogue Root", o="Bad CA")
    # 同名不同钥的伪造 ICA：主体 DN 与真 ICA 完全一致，公钥不同
    ica_bad, _ = issue(name("Shared ICA"), rogue, gk, ca=True, path_len=0)
    leaf, _ = issue(name("m.example.com"), ica, ik, dns=["m.example.com"],
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])

    res = analyze([leaf], [ica, ica_bad, rogue], [root], T, "m.example.com", "serverAuth")
    lr = res["leaves"][0]
    assert lr["candidate_count"] == 2
    assert lr["valid_count"] == 1
    assert lr["eliminated_count"] == 1

    # 验签失败路径：淘汰 + 证据，且不计入有效链
    sig = [c for c in lr["chains"] if c["failure"] and c["failure"]["rule"] == "SIGNATURE"]
    assert len(sig) == 1
    assert sig[0]["ids"] == [cc.fp(leaf), cc.fp(ica_bad)]
    assert sig[0]["failure"]["node"] == cc.fp(leaf)
    assert sig[0]["failure"]["issuer_fp"] == cc.fp(ica_bad)

    # 有效链不受淘汰链影响，仍按稳定规则选中（叶 → 真 ICA → 锚）
    selected = lr["chains"][lr["selected_index"]]
    assert selected["failure"] is None
    assert selected["complete"] is True
    assert selected["ids"] == [cc.fp(leaf), cc.fp(ica), cc.fp(root)]

    # 上传顺序不影响选链稳定性
    res2 = analyze([leaf], [rogue, ica_bad, ica], [root], T, "m.example.com", "serverAuth")
    lr2 = res2["leaves"][0]
    assert lr2["chains"][lr2["selected_index"]]["ids"] == selected["ids"]


def test_multiple_pem_in_one_file(tmp_path):
    root, rk = self_signed_root("R")
    ica, ik = issue(name("I"), root, rk, ca=True, path_len=0)
    from cryptography.hazmat.primitives import serialization
    blob = (ica.public_bytes(serialization.Encoding.PEM) +
            root.public_bytes(serialization.Encoding.PEM))
    certs = cc.load_certificates(blob)
    assert len(certs) == 2
