#!/usr/bin/env python3
"""生成实验台内置样例证书集（全部本地离线生成）。

场景：
  01-standard      标准三级链 Root -> ICA -> Leaf（另含一本 DER 格式证书演示）
  02-cross-signed  交叉签发：同一 ICA 公钥分别被 RootA / RootB 签发，两条候选链
  03-same-name     同名不同钥：恶意根与本地锚同名，叶证书由恶意根签发 -> UNTRUSTED
  04-loop          ICA1 <-> ICA2 互相签发形成环路，且无锚 -> LOOP
  05-expired       叶证书已过期 -> VALIDITY
  06-pathlen       超长链超出 pathLenConstraint -> PATH_LEN
  07-name-constr   ICA 名称约束禁止 evil.example -> NAME_CONSTRAINTS
  08-eku           叶证书仅有 clientAuth，请求 serverAuth -> EXTENDED_KEY_USAGE
  09-hostname      SAN 与请求主机名不匹配 -> HOSTNAME

用法: python scripts/generate_samples.py
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else (
    Path(__file__).resolve().parent.parent / "data" / "samples")

NOT_BEFORE = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)


def key_rsa(size=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def key_ec():
    return ec.generate_private_key(ec.SECP256R1())


def name(cn, o="Lab"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _nb(nb=NOT_BEFORE, na=NOT_AFTER):
    return nb, na


def issue(subject_name, issuer_cert, issuer_key, *, subject_key=None,
         ca=False, path_len=None, dns=None, eku=None, ku_cert_sign=True,
         not_before=NOT_BEFORE, not_after=NOT_AFTER, serial=None,
         name_constraints=None, ca_basic=True, is_leaf=False):
    """签发证书。subject_key 缺省新生成密钥并返回 (cert, key)。"""
    sk = subject_key or key_ec()
    pk = sk.public_key()
    builder = x509.CertificateBuilder().subject_name(subject_name).issuer_name(
        issuer_cert.subject if issuer_cert is not None else subject_name
    ).public_key(pk).serial_number(
        serial or x509.random_serial_number()
    ).not_valid_before(not_before).not_valid_after(not_after)

    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=ku_cert_sign, crl_sign=True,
                content_commitment=False, data_encipherment=False,
                key_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
    else:
        if ca_basic:
            builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, data_encipherment=False,
                key_encipherment=True, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)

    if dns is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]), critical=False)
    if eku is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku), critical=False)
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)

    # SKI / AKI
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(pk), critical=False)
    if issuer_cert is not None:
        try:
            icas = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                critical=False)
        except x509.ExtensionNotFound:
            pass

    sig_key = issuer_key or sk
    cert = builder.sign(sig_key, hashes.SHA256())
    return cert, sk


def self_signed_root(cn, o="Lab Root", **kw):
    sk = key_ec()
    cert, key = issue(name(cn, o), None, sk, subject_key=sk, ca=True, **kw)
    return cert, key


def write_scenario(sid: str, readme: str, *, leaf=None, intermediates=(), anchors=(),
                   der=()):
    d = OUT / sid
    for sub in ("leaf", "intermediates", "anchors"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    (d / "README.md").write_text(readme, encoding="utf-8")

    def dump(cert, path: Path):
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    if leaf:
        for i, c in enumerate(_as_list(leaf)):
            dump(c, d / "leaf" / f"leaf-{i+1}.pem")
    for i, c in enumerate(intermediates):
        dump(c, d / "intermediates" / f"ica-{i+1}.pem")
    for i, c in enumerate(anchors):
        dump(c, d / "anchors" / f"root-{i+1}.pem")
    for c, fname in der:
        (d / "leaf" / fname).write_bytes(c.public_bytes(serialization.Encoding.DER))


def _as_list(x):
    return x if isinstance(x, (list, tuple)) else [x]


# ============================================================================
def s01():
    root, rk = self_signed_root("Standard Root CA")
    ica, ik = issue(name("Standard ICA"), root, rk, ca=True, path_len=0)
    leaf, _ = issue(name("www.example.com"), ica, ik, dns=["www.example.com", "example.com"],
                    eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    # 另存一本 DER 叶证书，证明 DER 可解析（上传时单独使用）
    write_scenario(
        "01-standard",
        "# 场景 01：标准三级链\n\nRoot（锚）→ ICA(pathLen=0) → Leaf(SAN: www.example.com)。"
        "另附 DER 格式叶证书 leaf-der.der，用于验证 DER 解析。\n\n"
        "建议参数：时间 2025-06-01T00:00:00Z，DNS=www.example.com，用途=serverAuth。\n",
        leaf=[leaf], intermediates=[ica], anchors=[root],
        der=[(leaf, "leaf-der.der")],
    )


def s02():
    root_a, rak = self_signed_root("Root A", o="Lab Root A")
    root_b, rbk = self_signed_root("Root B", o="Lab Root B")
    # 同一个 ICA 密钥/主体，被两个根交叉签发
    ica_key = key_ec()
    ica_a, _ = issue(name("Cross ICA"), root_a, rak, subject_key=ica_key, ca=True, path_len=0)
    ica_b, _ = issue(name("Cross ICA"), root_b, rbk, subject_key=ica_key, ca=True, path_len=0)
    # 叶证书由 ICA 签发（AKI 取决于 ICA 公钥，两本 ICA 同钥，均可验证）
    leaf, _ = issue(name("app.example.com"), ica_a, ica_key,
                    dns=["app.example.com"],
                    eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    write_scenario(
        "02-cross-signed",
        "# 场景 02：交叉签发\n\nCross ICA 的同一主体/公钥分别被 Root A、Root B 签发；"
        "两个根均为信任锚。叶证书可走出两条不同候选链（长度相同），"
        "系统按指纹字典序稳定选出一条，另一条同样有效。\n\n"
        "建议参数：DNS=app.example.com，用途=serverAuth。\n",
        leaf=leaf, intermediates=[ica_a, ica_b], anchors=[root_a, root_b],
    )


def s03():
    # 真锚
    root, rk = self_signed_root("Global Trust Root", o="Real CA")
    # 同名不同钥的伪造根
    rogue, gk = self_signed_root("Global Trust Root", o="Real CA")
    ica, ik = issue(name("Rogue ICA"), rogue, gk, ca=True, path_len=0)
    leaf, _ = issue(name("bank.example.com"), ica, ik, dns=["bank.example.com"],
                    eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    write_scenario(
        "03-same-name",
        "# 场景 03：同名主体（同名不同钥）\n\n信任锚为真 Global Trust Root；"
        "伪造根与锚 **同名却不同公钥/指纹**，且叶证书链由伪造根签发。"
        "图上可见：Rogue ICA → 真锚 的签名失败红虚线边、伪造根的自环边；"
        "候选链分别终止于 SIGNATURE（主体名可相连但验签失败的首个节点证据）、"
        "UNTRUSTED_ROOT（同名不同钥证据）与 LOOP。\n\n"
        "建议参数：DNS=bank.example.com，用途=serverAuth。\n",
        leaf=leaf, intermediates=[ica, rogue], anchors=[root],
    )


def s04():
    k1, k2 = key_ec(), key_ec()
    n1, n2 = name("Loop CA 1"), name("Loop CA 2")
    # 先各自自签占位以拿到“证书对象”，再互相签发（用主体名互相引用）
    ca1_self, _ = issue(n1, None, k1, subject_key=k1, ca=True)
    ca2_self, _ = issue(n2, None, k2, subject_key=k2, ca=True)
    # ca1 由 ca2 签，ca2 由 ca1 签（交叉引用对方主体名与密钥）
    ca1, _ = issue(n1, ca2_self, k2, subject_key=k1, ca=True)
    ca2, _ = issue(n2, ca1_self, k1, subject_key=k2, ca=True)
    leaf, _ = issue(name("loop.example.com"), ca1, k1, dns=["loop.example.com"],
                    eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    write_scenario(
        "04-loop",
        "# 场景 04：签发环路\n\nLoop CA 1 与 Loop CA 2 互相签发，叶证书由 CA1 签发。"
        "DFS 枚举时出现 CA1→CA2→CA1 闭合环；本场景没有任何信任锚，"
        "候选路径以 LOOP / UNTRUSTED_ROOT 逐条淘汰。\n\n"
        "建议参数：DNS=loop.example.com，用途=serverAuth。\n",
        leaf=leaf, intermediates=[ca1, ca2], anchors=[],
    )


def s05():
    root, rk = self_signed_root("Expiry Root CA")
    ica, ik = issue(name("Expiry ICA"), root, rk, ca=True, path_len=0)
    leaf, _ = issue(
        name("old.example.com"), ica, ik, dns=["old.example.com"],
        eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH],
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
    )
    write_scenario(
        "05-expired",
        "# 场景 05：证书过期\n\n叶证书有效期 2020-01-01 ~ 2021-01-01。"
        "在默认（当前）时间或以 2025-06-01 校验时，叶节点 VALIDITY 失败。\n\n"
        "建议参数：校验时间 2025-06-01T00:00:00Z，DNS=old.example.com。\n",
        leaf=leaf, intermediates=[ica], anchors=[root],
    )


def s06():
    root, rk = self_signed_root("PathLen Root CA")
    # 根 path_len=1：根下最多 1 个非自签发中间 CA
    ica1, i1k = issue(name("PL ICA 1"), root, rk, ca=True, path_len=0)
    ica2, i2k = issue(name("PL ICA 2"), ica1, i1k, ca=True, path_len=0)
    leaf, _ = issue(name("deep.example.com"), ica2, i2k, dns=["deep.example.com"],
                    eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    write_scenario(
        "06-pathlen",
        "# 场景 06：pathLenConstraint 超限\n\nRoot(pathLen=1) → ICA1(pathLen=0) "
        "→ ICA2(pathLen=0) → Leaf。ICA2 位于 ICA1 之下已使 ICA1 的 pathLen=0 被突破；"
        "根的 pathLen=1 同样被两层中间 CA 突破，首个失败按叶→根顺序报告。\n\n"
        "建议参数：DNS=deep.example.com，用途=serverAuth。\n",
        leaf=leaf, intermediates=[ica1, ica2], anchors=[root],
    )


def s07():
    root, rk = self_signed_root("NC Root CA")
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(".example.com"), x509.DNSName("example.com")],
        excluded_subtrees=[x509.DNSName("evil.example.com")],
    )
    ica, ik = issue(name("NC ICA"), root, rk, ca=True, path_len=0,
                    name_constraints=nc)
    leaf, _ = issue(name("www.evil.example.com"), ica, ik,
                    dns=["www.evil.example.com"],
                    eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    write_scenario(
        "07-name-constraints",
        "# 场景 07：Name Constraints\n\nICA 允许子树 .example.com，但显式禁止 "
        "evil.example.com（及其子域）。叶证书 SAN 为 www.evil.example.com，"
        "在 ICA 节点触发 NAME_CONSTRAINTS（excluded 优先于 permitted）。\n\n"
        "建议参数：DNS=www.evil.example.com，用途=serverAuth。\n",
        leaf=leaf, intermediates=[ica], anchors=[root],
    )


def s08():
    root, rk = self_signed_root("EKU Root CA")
    ica, ik = issue(name("EKU ICA"), root, rk, ca=True, path_len=0)
    leaf, _ = issue(name("client.example.com"), ica, ik, dns=["client.example.com"],
                    eku=[x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
    write_scenario(
        "08-eku",
        "# 场景 08：扩展密钥用途不符\n\n叶证书 EKU 仅含 clientAuth，"
        "实验请求用途 serverAuth，叶节点 EXTENDED_KEY_USAGE 失败。\n\n"
        "建议参数：DNS=client.example.com，用途=serverAuth。\n",
        leaf=leaf, intermediates=[ica], anchors=[root],
    )


def s09():
    root, rk = self_signed_root("Host Root CA")
    ica, ik = issue(name("Host ICA"), root, rk, ca=True, path_len=0)
    leaf, _ = issue(name("correct.example.com"), ica, ik,
                    dns=["correct.example.com", "*.other.example.org"],
                    eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    write_scenario(
        "09-hostname",
        "# 场景 09：主机名不匹配\n\n叶证书 SAN 为 correct.example.com 与 "
        "*.other.example.org；以 DNS=wrong.example.com 校验时 HOSTNAME 失败，"
        "证据列出全部已呈现标识符。通配匹配遵循 RFC 6125（不跨标签）。\n\n"
        "建议参数：DNS=wrong.example.com，用途=serverAuth。\n",
        leaf=leaf, intermediates=[ica], anchors=[root],
    )


def main():
    for fn in (s01, s02, s03, s04, s05, s06, s07, s08, s09):
        fn()
        print("generated", fn.__name__)
    print("samples at", OUT)


if __name__ == "__main__":
    main()
