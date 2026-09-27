"""X.509 证书解析与基本密码学核验原语。

所有函数均在本地运行，不发起任何网络请求（不做 CRL / OCSP / AIA 抓取）。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, dsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

# ---- 用途（EKU）映射 -------------------------------------------------------
PURPOSE_OIDS: dict[str, ObjectIdentifier] = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
}
PURPOSE_LABELS: dict[str, str] = {
    "serverAuth": "TLS WWW 服务器认证 (serverAuth)",
    "clientAuth": "TLS WWW 客户端认证 (clientAuth)",
    "codeSigning": "可执行代码签名 (codeSigning)",
    "emailProtection": "电子邮件保护 (emailProtection)",
    "timeStamping": "时间戳 (timeStamping)",
    "OCSPSigning": "OCSP 响应签名 (OCSPSigning)",
}
ANY_EKU = ObjectIdentifier("2.5.29.37.0")

# 对主机名有意义的通用名 / SAN 标签
_EMAIL_OIDS = {NameOID.EMAIL_ADDRESS, NameOID.DOMAIN_COMPONENT}


# ============================================================================
# 加载
# ============================================================================
def load_certificates(data: bytes) -> list[x509.Certificate]:
    """从 PEM（可含多本）或 DER 字节中解析证书。"""
    if not data:
        raise ValueError("空文件")
    certs: list[x509.Certificate] = []
    try:
        pem_certs = x509.load_pem_x509_certificates(data)
        if pem_certs:
            return list(pem_certs)
    except ValueError:
        pass
    try:
        certs.append(x509.load_der_x509_certificate(data))
        return certs
    except ValueError:
        pass
    # PEM 文件但内容损坏等情况：给出明确错误
    if b"-----BEGIN" in data:
        raise ValueError("PEM 内容存在但无法解析为证书")
    raise ValueError("无法识别的证书格式（仅支持 PEM/DER X.509）")


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(Encoding.PEM).decode()


# ============================================================================
# 名称 / 标识工具
# ====================================================================
def _rdn_value(attr) -> str:
    v = attr.value
    return v.casefold() if isinstance(v, str) else str(v).casefold()


def name_key(name: x509.Name) -> tuple[tuple[tuple[str, str], ...], ...]:
    """RFC 5280 7.1 风格的名称规范化键：RDN 序列（顶层顺序敏感），
    每个 RDN 内的属性类型集合无序；属性值做 casefold 比较。"""
    out = []
    for rdn in name.rdns:
        attrs = frozenset((a.oid.dotted_string, _rdn_value(a)) for a in attr_iter(rdn))
        out.append(tuple(sorted(attrs)))
    return tuple(out)


def attr_iter(rdn: x509.RelativeDistinguishedName):
    for a in rdn:
        yield a


def name_one_line(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def spki_fp(cert: x509.Certificate) -> str:
    return cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ).hex()


def serial_hex(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "x")


def get_extension(cert: x509.Certificate, oid: ObjectIdentifier):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def basic_constraints(cert: x509.Certificate):
    bc = get_extension(cert, x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    if bc is None:
        return None
    return bool(bc.ca), bc.path_length


def key_usage(cert: x509.Certificate) -> Optional[x509.KeyUsage]:
    return get_extension(cert, x509.oid.ExtensionOID.KEY_USAGE)


def eku(cert: x509.Certificate) -> Optional[set[ObjectIdentifier]]:
    v = get_extension(cert, x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
    return set(v) if v is not None else None


def san_dns(cert: x509.Certificate) -> list[str]:
    v = get_extension(cert, x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if v is None:
        return []
    return list(v.get_values_for_type(x509.DNSName))


def san_emails(cert: x509.Certificate) -> list[str]:
    v = get_extension(cert, x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if v is None:
        return []
    return list(v.get_values_for_type(x509.RFC822Name))


def cn_values(name: x509.Name) -> list[str]:
    return [a.value for a in name.get_attributes_for_oid(NameOID.COMMON_NAME)]


def self_issued(child: x509.Certificate) -> bool:
    return name_key(child.subject) == name_key(child.issuer)


# ============================================================================
# 签名核验
# ============================================================================
def verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> tuple[bool, Optional[str]]:
    """用 issuer 公钥验证 child 的签名。返回 (是否通过, 失败原因)。"""
    pub = issuer.public_key()
    tbs = child.tbs_certificate_bytes
    sig = child.signature
    alg_oid = child.signature_algorithm_oid.dotted_string
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if alg_oid == "1.2.840.113549.1.1.10":  # rsassaPss
                params = child.signature_algorithm_parameters
                hash_alg = getattr(params, "algorithm", None)
                if hash_alg is None:
                    hash_alg = getattr(params, "_algorithm", None) or hashes.SHA256()
                mgf_hash = hash_alg
                if isinstance(params.mgf, padding.MGF1):
                    mgf_hash = params.mgf.algorithm
                pub.verify(sig, tbs,
                           padding.PSS(mgf=padding.MGF1(mgf_hash), salt_length=params.salt_length),
                           hash_alg)
            else:
                pub.verify(sig, tbs, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, tbs, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, ed25519.Ed25519PublicKey) or isinstance(pub, ed448.Ed448PublicKey):
            pub.verify(sig, tbs)
        elif isinstance(pub, dsa.DSAPublicKey):
            pub.verify(sig, tbs, child.signature_hash_algorithm)
        else:
            return False, f"不支持的发行者公钥类型: {type(pub).__name__}"
        return True, None
    except InvalidSignature:
        return False, "签名值校验失败（公钥不匹配或数据被篡改）"
    except Exception as exc:  # noqa: BLE001 - 实验台需要把任何密码学异常转成可读证据
        return False, f"签名验证异常: {type(exc).__name__}: {exc}"


# ============================================================================
# 时间
# ============================================================================
def cert_not_before(cert: x509.Certificate) -> datetime:
    return _aware(cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before)


def cert_not_after(cert: x509.Certificate) -> datetime:
    return _aware(cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ============================================================================
# 主机名匹配（RFC 6125）
# ============================================================================
def dns_match(pattern: str, hostname: str) -> bool:
    p = pattern.strip(".").casefold()
    h = hostname.strip(".").casefold()
    if p == h:
        return True
    if not p.startswith("*."):
        return False
    # 仅允许最左侧标签为 *，且 * 只能出现一次；剩余部分（含点）必须一致
    suffix = p[1:]  # ".example.com"
    if "*" in suffix:
        return False
    if not h.endswith(suffix):
        return False
    left = h[: -len(suffix)]
    # 通配符不得匹配跨标签（不含点）且不能为空
    return bool(left) and "." not in left


def presented_dns_ids(cert: x509.Certificate) -> list[str]:
    """RFC 6125：有 SAN 时只用 SAN；否则回退 CN。"""
    sans = san_dns(cert)
    if sans:
        return sans
    return [cn for cn in cn_values(cert.subject) if " " not in cn]


# ============================================================================
# Name Constraints（RFC 5280 4.2.1.10，仅实现 DNS 部分）
# ============================================================================
def name_constraints(cert: x509.Certificate):
    return get_extension(cert, x509.oid.ExtensionOID.NAME_CONSTRAINTS)


def dns_constraint_match(constraint: str, name: str) -> bool:
    """RFC 5280: 以点开头表示子域；不带点表示主机本身或同域。"""
    c = constraint.casefold()
    n = name.strip(".").casefold()
    if c.startswith("."):
        return n.endswith(c)
    return n == c or n.endswith("." + c)


def check_name_constraints(ca: x509.Certificate, dns_names: Iterable[str], where: str) -> Optional[dict]:
    """对给定 DNS 标识符集合施加 ca 的 nameConstraints。返回失败证据或 None。"""
    nc = name_constraints(ca)
    if nc is None:
        return None
    permitted = [s.value.lower() for s in (nc.permitted_subtrees or []) if isinstance(s, x509.DNSName)]
    excluded = [s.value.lower() for s in (nc.excluded_subtrees or []) if isinstance(s, x509.DNSName)]
    # 无 DNS 类型约束时不干预 DNS 名称
    all_subtrees = list(nc.permitted_subtrees or []) + list(nc.excluded_subtrees or [])
    if not any(isinstance(s, x509.DNSName) for s in all_subtrees):
        return None
    for name in dns_names:
        for c in excluded:
            if dns_constraint_match(c, name):
                return {
                    "rule": "NAME_CONSTRAINTS",
                    "node": fp(ca),
                    "message": f"{where} 的 DNS 名称 {name!r} 命中该 CA 禁止子树 {c!r}",
                    "constraint": c,
                    "kind": "excluded",
                    "presented_name": name,
                }
        if permitted and not any(dns_constraint_match(c, name) for c in permitted):
            return {
                "rule": "NAME_CONSTRAINTS",
                "node": fp(ca),
                "message": f"{where} 的 DNS 名称 {name!r} 不在该 CA 允许子树 {permitted} 内",
                "constraints": permitted,
                "kind": "permitted",
                "presented_name": name,
            }
    return None
