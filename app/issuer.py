"""离线 CSR 签发：本地 CA 对「含 DNS SAN 的 CSR」签发服务器叶证书。

设计约束（与 README「离线 CSR 签发」一节一致）：

- 全程离线：不发起任何网络请求，不做 CRL / OCSP / AIA；
- 仅支持 RSA / EC 密钥（CA 私钥与 CSR 公钥）；
- CA 私钥仅用于本次请求的签名运算：不落库、不写日志、不随响应返回；
- 幂等：幂等键绑定「规范化 CSR（DER 重编码）+ 签发者证书指纹 + 起止时间」，
  同键同参（含并发与重启后重试）返回字节相同的证书（直接回放库存 PEM）；
  同键异参返回 409；
- 序列号在同一签发者公钥（SPKI）下不得重复：由请求确定派生 + 数据库唯一索引
  双重保证；证书、序列号与幂等记录在同一 SQLite 事务中原子提交，
  任何失败都不会留下成功记录，也不会返回证书。
"""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID

from . import cert_core as cc
from . import db as database


class IssuanceError(Exception):
    """可预期的签发校验失败（HTTP 400）。"""


class IdempotencyConflict(Exception):
    """同一幂等键绑定了不同请求参数（HTTP 409）。"""


MAX_IDEM_KEY_LEN = 200
_SERIAL_RETRY = 5  # 序列号碰撞时的重派生次数（理论上几乎不会触发）


# ============================================================================
# 解析
# ============================================================================
def load_ca_certificate(data: bytes) -> x509.Certificate:
    try:
        certs = cc.load_certificates(data)
    except ValueError as exc:
        raise IssuanceError(f"CA 证书解析失败: {exc}") from exc
    if len(certs) != 1:
        raise IssuanceError(f"CA 证书须为单本证书（收到 {len(certs)} 本）")
    return certs[0]


def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    if not data:
        raise IssuanceError("CSR 文件为空")
    try:
        return x509.load_pem_x509_csr(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_csr(data)
    except ValueError:
        pass
    raise IssuanceError("无法识别的 CSR 格式（仅支持 PEM/DER PKCS#10）")


def load_private_key(data: bytes):
    """解析未加密的 PEM/DER 私钥（PKCS#8 / PKCS#1 / SEC1）。

    私钥仅在本次请求内存中使用：调用方不得将其写库或写日志。
    """
    if not data:
        raise IssuanceError("CA 私钥文件为空")
    for loader in (serialization.load_pem_private_key,
                   serialization.load_der_private_key):
        try:
            return loader(data, password=None)
        except TypeError:
            raise IssuanceError(
                "CA 私钥已加密：本实验台不处理口令，请提供未加密的 PEM/DER 私钥")
        except ValueError:
            continue
    raise IssuanceError("无法识别的私钥格式（仅支持未加密的 PEM/DER：PKCS#8 / PKCS#1 / SEC1）")


def parse_time(value: str, field: str) -> datetime:
    """ISO 8601 → UTC、整秒（X.509 时间不保存亚秒，规范化后参与幂等哈希）。"""
    v = (value or "").strip()
    if not v:
        raise IssuanceError(f"{field}不能为空，请使用 ISO 8601（如 2026-01-01T00:00:00Z）")
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise IssuanceError(f"{field}格式无法解析: {value!r}，请使用 ISO 8601")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0)


# ============================================================================
# 校验
# ============================================================================
def _require_rsa_or_ec(key, what: str, kinds: tuple) -> None:
    if not isinstance(key, kinds):
        raise IssuanceError(f"{what}仅支持 RSA / EC 密钥，收到 {type(key).__name__}")


def _validate_key_matches_cert(ca_cert: x509.Certificate, ca_key) -> None:
    cert_spki = ca_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    key_spki = ca_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if cert_spki != key_spki:
        raise IssuanceError("CA 私钥与 CA 证书公钥不匹配（SPKI 不一致）")


def _validate_ca_identity(ca_cert: x509.Certificate) -> None:
    """CA 身份：Basic Constraints cA=TRUE 且 Key Usage 置 keyCertSign。"""
    bc = cc.basic_constraints(ca_cert)
    if bc is None:
        raise IssuanceError("CA 证书缺少 Basic Constraints 扩展，不具备 CA 身份")
    if not bc[0]:
        raise IssuanceError("CA 证书 Basic Constraints 为 cA=FALSE，不能作为签发 CA")
    ku = cc.key_usage(ca_cert)
    if ku is None:
        raise IssuanceError("CA 证书缺少 Key Usage 扩展，无法确认 keyCertSign")
    if not ku.key_cert_sign:
        raise IssuanceError("CA 证书 Key Usage 未置 keyCertSign，不得签发证书")


def _validate_csr_signature(csr: x509.CertificateSigningRequest) -> None:
    if not csr.is_signature_valid:
        raise IssuanceError("CSR 签名验证失败（请求被篡改或与其公钥不匹配）")


def _extract_dns_san(csr: x509.CertificateSigningRequest) -> list[str]:
    """仅接受含 DNS SAN 的扩展请求；返回去重保序的 DNS 名称列表。"""
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise IssuanceError("CSR 未请求 subjectAltName 扩展：本签发端仅接受含 DNS SAN 的扩展请求")
    seen: set[str] = set()
    dns_names: list[str] = []
    for d in san.get_values_for_type(x509.DNSName):
        d = d.strip()
        if d and d.casefold() not in seen:
            seen.add(d.casefold())
            dns_names.append(d)
    if not dns_names:
        raise IssuanceError("CSR 的 SAN 扩展不含任何 DNS 名称（dNSName）")
    return dns_names


def _validate_validity(not_before: datetime, not_after: datetime,
                       ca_cert: x509.Certificate) -> None:
    if not_before >= not_after:
        raise IssuanceError(
            "起止时间无序：notBefore "
            f"{not_before.isoformat()} 须早于 notAfter {not_after.isoformat()}")
    ca_nb, ca_na = cc.cert_not_before(ca_cert), cc.cert_not_after(ca_cert)
    if not_before < ca_nb or not_after > ca_na:
        raise IssuanceError(
            "证书有效期须落在 CA 有效期内："
            f"CA 为 {ca_nb.isoformat()} ~ {ca_na.isoformat()}，"
            f"请求为 {not_before.isoformat()} ~ {not_after.isoformat()}")


def _validate_name_constraints(ca_cert: x509.Certificate, dns_names: list[str]) -> None:
    bad = cc.check_name_constraints(ca_cert, dns_names, "CSR")
    if bad is not None:
        raise IssuanceError(bad["message"])


# ============================================================================
# 证书构建
# ============================================================================
def _leaf_key_usage(pub) -> tuple[x509.KeyUsage, str]:
    """适配叶公钥类型的 Key Usage：RSA 可加密传输，EC 仅用于签名。"""
    if isinstance(pub, rsa.RSAPublicKey):
        return x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), "digitalSignature + keyEncipherment（RSA）"
    return x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    ), "digitalSignature（EC）"


def _request_hash(csr_der: bytes, issuer_fp: str,
                  not_before: datetime, not_after: datetime) -> str:
    """幂等请求指纹：规范化 CSR（DER 重编码）+ 签发者指纹 + 起止时间。"""
    h = hashlib.sha256()
    h.update(b"x509lab/issue/v1\n")
    h.update(issuer_fp.encode("ascii"))
    h.update(b"\n")
    h.update(not_before.isoformat().encode("ascii"))
    h.update(b"\n")
    h.update(not_after.isoformat().encode("ascii"))
    h.update(b"\n")
    h.update(csr_der)
    return h.hexdigest()


def _derive_serial(issuer_spki_fp: str, idem_key: str, request_hash: str,
                   attempt: int) -> int:
    """确定性派生 128 bit 正序列号（≤ 20 字节，RFC 5280 §4.1.2.2）。

    同一（签发者公钥, 幂等键, 请求）恒得同一序列号；不同幂等键即使请求相同
    也会得到不同序列号。数据库唯一索引兜底防碰撞。
    """
    digest = hashlib.sha256(
        f"x509lab/serial/v1\n{issuer_spki_fp}\n{idem_key}\n{request_hash}\n{attempt}"
        .encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:16], "big") | (1 << 127)


def _build_leaf(csr: x509.CertificateSigningRequest, ca_cert: x509.Certificate,
                ca_key, serial: int, not_before: datetime, not_after: datetime,
                dns_names: list[str], ku: x509.KeyUsage) -> x509.Certificate:
    pub = csr.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(pub)
        .serial_number(serial)
        # cryptography 将朴素时间按 UTC 编码；此处已规范化为 UTC
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ku, critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(d) for d in dns_names]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False)
    )
    # RSA → PKCS#1 v1.5 + SHA-256；EC → ECDSA + SHA-256
    return builder.sign(ca_key, hashes.SHA256())


def _result_from_record(record: dict, *, replay: bool) -> dict:
    cert = x509.load_pem_x509_certificate(record["cert_pem"].encode("ascii"))
    _, ku_label = _leaf_key_usage(cert.public_key())
    return {
        "cert_pem": record["cert_pem"],
        "idempotent_replay": replay,
        "serial": record["serial_hex"],
        "subject": record["subject"],
        "issuer": cc.name_one_line(cert.issuer),
        "issuer_fingerprint": record["issuer_fp"],
        "fingerprint": cc.fp(cert),
        "not_before": record["not_before"],
        "not_after": record["not_after"],
        "dns_names": list(record["dns_names"]),
        "basic_constraints": "CA=FALSE",
        "key_usage": ku_label,
        "eku": "serverAuth",
        "download_name": f"leaf-{record['serial_hex'][:16]}.pem",
        "created_at": record["created_at"],
        "offline": True,
    }


# ============================================================================
# 签发编排
# ============================================================================
def issue(db_path, *, ca_cert_bytes: bytes, ca_key_bytes: bytes, csr_bytes: bytes,
          not_before_str: str, not_after_str: str, idem_key: str) -> dict:
    """校验 → 幂等判定 → 签名 → 原子提交。任何失败都不落库、不返回证书。"""
    idem_key = (idem_key or "").strip()
    if not idem_key:
        raise IssuanceError("幂等键不能为空")
    if len(idem_key) > MAX_IDEM_KEY_LEN:
        raise IssuanceError(f"幂等键过长（>{MAX_IDEM_KEY_LEN} 字符）")

    ca_cert = load_ca_certificate(ca_cert_bytes)
    csr = load_csr(csr_bytes)
    not_before = parse_time(not_before_str, "notBefore（生效时间）")
    not_after = parse_time(not_after_str, "notAfter（失效时间）")

    issuer_fp = cc.fp(ca_cert)
    issuer_spki_fp = cc.spki_fp(ca_cert)
    request_hash = _request_hash(csr.public_bytes(Encoding.DER), issuer_fp,
                                 not_before, not_after)

    # ---- 幂等快路径：同键同参 → 直接回放库存证书（字节相同，无需触碰私钥）----
    existing = database.get_issuance(db_path, idem_key)
    if existing is not None:
        if existing["request_hash"] == request_hash:
            return _result_from_record(existing, replay=True)
        raise IdempotencyConflict(
            f"幂等键 {idem_key!r} 已绑定另一组请求参数（规范化 CSR / 签发者 / "
            "起止时间不同），请更换幂等键或核对请求")

    # ---- 完整校验（任一失败即抛错：不落库、不返回证书）----
    # 私钥仅在本次请求作用域内使用，绝不写库或日志
    ca_key = load_private_key(ca_key_bytes)
    _require_rsa_or_ec(ca_key, "CA 私钥",
                       (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))
    leaf_pub = csr.public_key()
    _require_rsa_or_ec(leaf_pub, "CSR 公钥",
                       (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))
    _validate_key_matches_cert(ca_cert, ca_key)
    _validate_ca_identity(ca_cert)
    _validate_csr_signature(csr)
    dns_names = _extract_dns_san(csr)
    _validate_validity(not_before, not_after, ca_cert)
    _validate_name_constraints(ca_cert, dns_names)

    ku, _ = _leaf_key_usage(leaf_pub)

    # ---- 派生序列号 + 签名 + 原子提交（并发同键竞态由唯一约束兜底）----
    for attempt in range(_SERIAL_RETRY):
        serial = _derive_serial(issuer_spki_fp, idem_key, request_hash, attempt)
        cert = _build_leaf(csr, ca_cert, ca_key, serial,
                           not_before, not_after, dns_names, ku)
        record = {
            "idem_key": idem_key,
            "request_hash": request_hash,
            "issuer_fp": issuer_fp,
            "issuer_spki_fp": issuer_spki_fp,
            "serial_hex": format(serial, "x"),
            "subject": cc.name_one_line(cert.subject),
            "dns_names": dns_names,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "cert_pem": cc.cert_to_pem(cert),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            database.commit_issuance(db_path, record)
        except sqlite3.IntegrityError:
            # 并发下同键先到：返回已提交记录（同参）或报冲突（异参）；
            # 否则为序列号碰撞（不同键派生出相同序列号）：换 attempt 重派生
            raced = database.get_issuance(db_path, idem_key)
            if raced is not None:
                if raced["request_hash"] == request_hash:
                    return _result_from_record(raced, replay=True)
                raise IdempotencyConflict(
                    f"幂等键 {idem_key!r} 已绑定另一组请求参数，请更换幂等键或核对请求")
            continue
        return _result_from_record(record, replay=False)
    raise IssuanceError("序列号分配失败（碰撞重试耗尽），请重试")
