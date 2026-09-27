"""离线 CSR 签发测试：校验规则、幂等（同键同参字节相同 / 异参 409 / 并发与重连）、
序列号唯一、原子提交（失败不留记录）、签发结果可送入链验证。"""
from __future__ import annotations

import datetime as dt
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID

from app import cert_core as cc
from app import db as database
from app import issuer
from app.service import analyze
from scripts.generate_samples import issue, key_ec, key_rsa, name

NB = "2025-01-01T00:00:00Z"
NA = "2026-01-01T00:00:00Z"
VERIFY_T = dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------------------
# 构造助手
# ---------------------------------------------------------------------------
def make_ca(cn="Test Issuing CA", key=None, **kw):
    """自签 CA（默认 EC，2024~2030，cA=TRUE + keyCertSign）。"""
    sk = key or key_ec()
    cert, _ = issue(name(cn), None, sk, subject_key=sk, ca=True, **kw)
    return cert, sk


def make_csr(cn="www.example.com", dns=("www.example.com",), key=None,
             san=True, san_names=None):
    sk = key or key_ec()
    builder = x509.CertificateSigningRequestBuilder().subject_name(name(cn))
    if san:
        names = san_names if san_names is not None else [x509.DNSName(d) for d in dns]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(sk, hashes.SHA256()), sk


def make_bad_signature_csr():
    """末字节翻转：DER 结构不变但签名失效。"""
    csr, _ = make_csr()
    der = csr.public_bytes(Encoding.DER)
    bad = der[:-1] + bytes([der[-1] ^ 0x01])
    return x509.load_der_x509_csr(bad)


def pem(cert):
    return cert.public_bytes(Encoding.PEM)


def key_pem(key):
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def run_issue(db_path, ca_cert, ca_key, csr, nb=NB, na=NA, idem="k1",
              csr_bytes=None):
    return issuer.issue(
        db_path,
        ca_cert_bytes=pem(ca_cert),
        ca_key_bytes=key_pem(ca_key),
        csr_bytes=csr_bytes if csr_bytes is not None else pem(csr),
        not_before_str=nb, not_after_str=na, idem_key=idem,
    )


@pytest.fixture()
def dbp(tmp_path):
    p = tmp_path / "lab.db"
    database.init_db(p)
    return p


# ---------------------------------------------------------------------------
# 正常签发
# ---------------------------------------------------------------------------
def test_issue_rsa_end_to_end_and_chain_verifiable(dbp):
    ca_cert, ca_key = make_ca(key=key_rsa())
    csr, _ = make_csr(key=key_rsa(), dns=["www.example.com", "example.com"])

    r = run_issue(dbp, ca_cert, ca_key, csr)
    assert r["idempotent_replay"] is False
    leaf = cc.load_certificates(r["cert_pem"].encode())[0]

    # 主体 / 签发者 / 有效期 / 序列号
    assert cc.name_key(leaf.subject) == cc.name_key(csr.subject)
    assert cc.name_key(leaf.issuer) == cc.name_key(ca_cert.subject)
    assert cc.cert_not_before(leaf) == dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
    assert cc.cert_not_after(leaf) == dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    assert leaf.serial_number > 0
    assert format(leaf.serial_number, "x") == r["serial"]

    # 扩展：CA=FALSE、serverAuth、适配 RSA 的 Key Usage、DNS SAN
    bc = cc.basic_constraints(leaf)
    assert bc == (False, None)
    eku = cc.eku(leaf)
    assert eku == {ExtendedKeyUsageOID.SERVER_AUTH}
    ku = cc.key_usage(leaf)
    assert ku.digital_signature and ku.key_encipherment
    assert not ku.key_cert_sign
    assert cc.san_dns(leaf) == ["www.example.com", "example.com"]

    # 签名可被 CA 验证；叶公钥与 CSR 一致
    ok, err = cc.verify_signature(leaf, ca_cert)
    assert ok, err
    spki = lambda k: k.public_key().public_bytes(  # noqa: E731
        Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert spki(leaf) == spki(csr)

    # 下载结果可直接送入原链验证入口
    res = analyze([leaf], [], [ca_cert], VERIFY_T, "www.example.com", "serverAuth")
    lr = res["leaves"][0]
    assert lr["valid_count"] == 1 and lr["selected_index"] == 0


def test_issue_ec_key_usage_adapted(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    r = run_issue(dbp, ca_cert, ca_key, csr)
    leaf = cc.load_certificates(r["cert_pem"].encode())[0]
    ku = cc.key_usage(leaf)
    assert ku.digital_signature
    assert not ku.key_encipherment  # EC 叶不置 keyEncipherment
    assert r["key_usage"].startswith("digitalSignature")


def test_der_csr_accepted(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    der = csr.public_bytes(Encoding.DER)
    r = run_issue(dbp, ca_cert, ca_key, csr, csr_bytes=der)
    assert r["dns_names"] == ["www.example.com"]


# ---------------------------------------------------------------------------
# 幂等
# ---------------------------------------------------------------------------
def test_idempotent_same_params_byte_identical(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    r1 = run_issue(dbp, ca_cert, ca_key, csr)
    r2 = run_issue(dbp, ca_cert, ca_key, csr)
    assert r1["idempotent_replay"] is False
    assert r2["idempotent_replay"] is True
    assert r1["cert_pem"] == r2["cert_pem"]  # 字节相同
    assert database.count_issuances(dbp) == 1


def test_idempotent_replay_after_reconnect(dbp):
    """状态只在 SQLite：模拟重启（重新 init 同一文件）后同键同参仍字节相同。"""
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    r1 = run_issue(dbp, ca_cert, ca_key, csr)
    database.init_db(dbp)  # 模拟进程重启后的启动初始化
    r2 = run_issue(dbp, ca_cert, ca_key, csr)
    assert r2["idempotent_replay"] is True
    assert r1["cert_pem"] == r2["cert_pem"]


def test_idempotent_concurrent_same_params(dbp):
    """同键同参并发：全部成功且返回字节相同的证书，库里只有一条记录。"""
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(
            lambda _: run_issue(dbp, ca_cert, ca_key, csr), range(8)))
    pems = {r["cert_pem"] for r in results}
    assert len(pems) == 1
    assert database.count_issuances(dbp) == 1


def test_same_key_different_params_conflict(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    run_issue(dbp, ca_cert, ca_key, csr, idem="k")
    # 异参（不同 notAfter）→ 409
    with pytest.raises(issuer.IdempotencyConflict):
        run_issue(dbp, ca_cert, ca_key, csr, na="2026-06-01T00:00:00Z", idem="k")
    # 异参（不同 CSR）→ 409
    csr2, _ = make_csr(cn="other.example.com", dns=["other.example.com"])
    with pytest.raises(issuer.IdempotencyConflict):
        run_issue(dbp, ca_cert, ca_key, csr2, idem="k")
    assert database.count_issuances(dbp) == 1


def test_same_params_different_key_new_serial(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    r1 = run_issue(dbp, ca_cert, ca_key, csr, idem="k1")
    r2 = run_issue(dbp, ca_cert, ca_key, csr, idem="k2")
    assert r1["serial"] != r2["serial"]
    assert database.count_issuances(dbp) == 2


def test_serials_unique_under_same_issuer(dbp):
    ca_cert, ca_key = make_ca()
    serials = set()
    for i in range(6):
        csr, _ = make_csr(cn=f"host{i}.example.com", dns=[f"host{i}.example.com"])
        r = run_issue(dbp, ca_cert, ca_key, csr, idem=f"k{i}")
        assert r["serial"] not in serials
        serials.add(r["serial"])


# ---------------------------------------------------------------------------
# 校验失败（且不留任何记录）
# ---------------------------------------------------------------------------
def _expect_error(dbp, ca_cert, ca_key, csr, fragment, **kw):
    with pytest.raises(issuer.IssuanceError) as ei:
        run_issue(dbp, ca_cert, ca_key, csr, **kw)
    assert fragment in str(ei.value)
    assert database.count_issuances(dbp) == 0  # 失败不得留下成功记录


def test_csr_signature_invalid_rejected(dbp):
    ca_cert, ca_key = make_ca()
    _expect_error(dbp, ca_cert, ca_key, make_bad_signature_csr(), "CSR 签名验证失败")


def test_ca_not_ca_rejected(dbp):
    root, rk = make_ca("Root")
    # 一本 cA=FALSE 的证书冒充 CA
    not_ca, nk = issue(name("Fake CA"), root, rk, ca=False)
    csr, _ = make_csr()
    _expect_error(dbp, not_ca, nk, csr, "cA=FALSE")


def test_ca_without_key_cert_sign_rejected(dbp):
    ca_cert, ca_key = make_ca(ku_cert_sign=False)
    csr, _ = make_csr()
    _expect_error(dbp, ca_cert, ca_key, csr, "keyCertSign")


def test_key_mismatch_rejected(dbp):
    ca_cert, _ = make_ca()
    other_key = key_ec()
    csr, _ = make_csr()
    _expect_error(dbp, ca_cert, other_key, csr, "不匹配")


def test_validity_unordered_rejected(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    _expect_error(dbp, ca_cert, ca_key, csr, "无序", nb=NA, na=NB)
    _expect_error(dbp, ca_cert, ca_key, csr, "无序", nb=NB, na=NB)


def test_validity_outside_ca_rejected(dbp):
    ca_cert, ca_key = make_ca()  # CA 有效期 2024-01-01 ~ 2030-01-01
    csr, _ = make_csr()
    _expect_error(dbp, ca_cert, ca_key, csr, "落在 CA 有效期内",
                  nb="2020-01-01T00:00:00Z")
    _expect_error(dbp, ca_cert, ca_key, csr, "落在 CA 有效期内",
                  na="2031-01-01T00:00:00Z")


def test_csr_without_dns_san_rejected(dbp):
    ca_cert, ca_key = make_ca()
    csr_no_san, _ = make_csr(san=False)
    _expect_error(dbp, ca_cert, ca_key, csr_no_san, "subjectAltName")
    import ipaddress
    csr_ip_only, _ = make_csr(san_names=[x509.IPAddress(ipaddress.ip_address("10.0.0.1"))])
    _expect_error(dbp, ca_cert, ca_key, csr_ip_only, "DNS 名称")


def test_name_constraints_enforced(dbp):
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("example.com")],
        excluded_subtrees=[x509.DNSName("evil.example.com")],
    )
    ca_cert, ca_key = make_ca(name_constraints=nc)
    csr_bad, _ = make_csr(cn="www.evil.example.com", dns=["www.evil.example.com"])
    _expect_error(dbp, ca_cert, ca_key, csr_bad, "禁止子树")
    csr_out, _ = make_csr(cn="other.org", dns=["other.org"])
    _expect_error(dbp, ca_cert, ca_key, csr_out, "允许子树")
    # 约束内的名称可以签发
    csr_ok, _ = make_csr(cn="www.example.com", dns=["www.example.com"])
    r = run_issue(dbp, ca_cert, ca_key, csr_ok)
    assert r["dns_names"] == ["www.example.com"]


def test_unsupported_key_types_rejected(dbp):
    # Ed25519 CA：私钥类型不被接受
    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_ca = (
        x509.CertificateBuilder()
        .subject_name(name("Ed CA")).issuer_name(name("Ed CA"))
        .public_key(ed_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2024, 1, 1)).not_valid_after(dt.datetime(2030, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .sign(ed_key, algorithm=None)
    )
    csr, _ = make_csr()
    _expect_error(dbp, ed_ca, ed_key, csr, "仅支持 RSA / EC")

    # Ed25519 CSR：叶公钥类型不被接受
    ed_csr_key = ed25519.Ed25519PrivateKey.generate()
    ed_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name("ed.example.com"))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("ed.example.com")]),
                       critical=False)
        .sign(ed_csr_key, algorithm=None)
    )
    ca_cert, ca_key = make_ca()
    _expect_error(dbp, ca_cert, ca_key, ed_csr, "仅支持 RSA / EC")


def test_encrypted_key_rejected(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    enc_key = ca_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"))
    with pytest.raises(issuer.IssuanceError) as ei:
        issuer.issue(dbp, ca_cert_bytes=pem(ca_cert), ca_key_bytes=enc_key,
                     csr_bytes=pem(csr), not_before_str=NB, not_after_str=NA,
                     idem_key="k")
    assert "已加密" in str(ei.value)
    assert database.count_issuances(dbp) == 0


def test_failed_attempt_does_not_burn_idem_key(dbp):
    """失败的尝试不落库：同一幂等键修正参数后仍可成功签发。"""
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    with pytest.raises(issuer.IssuanceError):
        run_issue(dbp, ca_cert, ca_key, csr, na="2031-01-01T00:00:00Z", idem="k")
    assert database.count_issuances(dbp) == 0
    r = run_issue(dbp, ca_cert, ca_key, csr, idem="k")
    assert r["idempotent_replay"] is False
    assert database.count_issuances(dbp) == 1


def test_empty_idem_key_rejected(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    _expect_error(dbp, ca_cert, ca_key, csr, "幂等键不能为空", idem="  ")


def test_multiple_certs_as_ca_rejected(dbp):
    ca_cert, ca_key = make_ca()
    csr, _ = make_csr()
    with pytest.raises(issuer.IssuanceError) as ei:
        issuer.issue(dbp, ca_cert_bytes=pem(ca_cert) + pem(ca_cert),
                     ca_key_bytes=key_pem(ca_key), csr_bytes=pem(csr),
                     not_before_str=NB, not_after_str=NA, idem_key="k")
    assert "单本" in str(ei.value)
