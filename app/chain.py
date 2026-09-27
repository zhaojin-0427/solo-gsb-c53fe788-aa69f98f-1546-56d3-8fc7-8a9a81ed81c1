"""候选证书图构建、候选链无重复枚举、逐链规则核验与稳定选链。

规则实现参考 RFC 5280 / RFC 6125；不做吊销检查，不访问网络。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from . import cert_core as cc

MAX_CHAINS = 300
MAX_DEPTH = 32

# ---- 规则中文标签 -----------------------------------------------------------
RULE_LABELS: dict[str, str] = {
    "SIGNATURE": "签名核验",
    "VALIDITY": "证书有效期",
    "BASIC_CONSTRAINTS": "Basic Constraints（CA 身份）",
    "KEY_USAGE": "Key Usage（密钥用途位）",
    "EXTENDED_KEY_USAGE": "Extended Key Usage（扩展密钥用途）",
    "HOSTNAME": "主机名匹配 (RFC 6125)",
    "NAME_CONSTRAINTS": "Name Constraints（名称约束, RFC 5280 4.2.1.10）",
    "PATH_LEN": "pathLenConstraint（路径长度约束）",
    "UNTRUSTED_ROOT": "信任锚",
    "LOOP": "环路检测",
}

RULE_REFS: dict[str, str] = {
    "SIGNATURE": "RFC 5280 §6.1.3(a)",
    "VALIDITY": "RFC 5280 §6.1.3(a)(2)",
    "BASIC_CONSTRAINTS": "RFC 5280 §4.2.1.9 / §6.1.4(k)",
    "KEY_USAGE": "RFC 5280 §4.2.1.3",
    "EXTENDED_KEY_USAGE": "RFC 5280 §4.2.1.12",
    "HOSTNAME": "RFC 6125 §6",
    "NAME_CONSTRAINTS": "RFC 5280 §4.2.1.10",
    "PATH_LEN": "RFC 5280 §4.2.1.9 / §6.1.4(m)",
    "UNTRUSTED_ROOT": "本地信任锚集合",
    "LOOP": "RFC 5280 名称链无环要求",
}


# ============================================================================
# 证书包装节点
# ============================================================================
@dataclass
class CertNode:
    cert: x509.Certificate
    fp: str
    spki_fp: str
    subject_key: tuple
    issuer_key: tuple
    subject: str
    issuer: str
    is_anchor_upload: bool = False          # 作为信任锚上传
    is_intermediate_upload: bool = False    # 作为中间证书上传
    is_leaf_upload: bool = False            # 作为叶证书上传
    roles: list[str] = field(default_factory=list)


def make_node(cert: x509.Certificate) -> CertNode:
    return CertNode(
        cert=cert,
        fp=cc.fp(cert),
        spki_fp=cc.spki_fp(cert),
        subject_key=cc.name_key(cert.subject),
        issuer_key=cc.name_key(cert.issuer),
        subject=cc.name_one_line(cert.subject),
        issuer=cc.name_one_line(cert.issuer),
    )


# ============================================================================
# 证书图
# ============================================================================
@dataclass
class Edge:
    child_fp: str
    issuer_fp: str
    sig_ok: bool
    sig_error: Optional[str]
    aki_ski_match: Optional[bool]   # None = 双方均无 AKI/SKI 无法比较


@dataclass
class Graph:
    nodes: dict[str, CertNode]
    edges: list[Edge]
    # child_fp -> 候选签发者边（DN 相同即候选；sig_ok 才用于走链）
    candidates: dict[str, list[Edge]]
    # child_fp -> 主体名可相连但颁发者公钥验签失败的边（枚举时产生 SIGNATURE 淘汰链）
    sig_failed: dict[str, list[Edge]]
    rejected_edges: list[Edge]      # DN 相同但签名失败 / AKI-SKI 冲突
    anchors: dict[str, CertNode]    # spki_fp -> 锚节点（同名不同钥各自独立）


def _aki_ski_compatible(child: x509.Certificate, issuer: x509.Certificate) -> Optional[bool]:
    aki = cc.get_extension(child, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    ski = cc.get_extension(issuer, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if aki is None or ski is None or aki.key_identifier is None:
        return None
    return aki.key_identifier == ski.digest


def build_graph(leaf_certs, intermediates, anchors) -> Graph:
    nodes: dict[str, CertNode] = {}

    def ingest(certs, role: str, flag: str):
        for cert in certs:
            f = cc.fp(cert)
            if f not in nodes:
                nodes[f] = make_node(cert)
            node = nodes[f]
            setattr(node, flag, True)
            if role not in node.roles:
                node.roles.append(role)

    ingest(leaf_certs, "leaf", "is_leaf_upload")
    ingest(intermediates, "intermediate", "is_intermediate_upload")
    ingest(anchors, "anchor", "is_anchor_upload")

    # 同名主体索引：subject_key -> [node]
    by_subject: dict[tuple, list[CertNode]] = {}
    for n in nodes.values():
        by_subject.setdefault(n.subject_key, []).append(n)

    anchors_by_spki: dict[str, CertNode] = {}
    for n in nodes.values():
        if n.is_anchor_upload:
            anchors_by_spki[n.spki_fp] = n

    edges: list[Edge] = []
    candidates: dict[str, list[Edge]] = {}
    sig_failed: dict[str, list[Edge]] = {}
    rejected: list[Edge] = []

    for child in nodes.values():
        issuers = by_subject.get(child.issuer_key, [])
        for issuer in issuers:
            if issuer.fp == child.fp and not cc.self_issued(child.cert):
                continue  # 自环只在自签发（同名）时才有意义
            ok, err = cc.verify_signature(child.cert, issuer.cert)
            aki_ski = _aki_ski_compatible(child.cert, issuer.cert)
            edge = Edge(child.fp, issuer.fp, ok, err, aki_ski)
            edges.append(edge)
            if ok and aki_ski is not False:
                candidates.setdefault(child.fp, []).append(edge)
            else:
                rejected.append(edge)
                if not ok:
                    # 主体名可相连但验签失败：保留给枚举阶段产生 SIGNATURE 淘汰链
                    sig_failed.setdefault(child.fp, []).append(edge)
        # 排序保证枚举顺序稳定（按签发者指纹）
        candidates.setdefault(child.fp, []).sort(key=lambda e: e.issuer_fp)
        if child.fp in sig_failed:
            sig_failed[child.fp].sort(key=lambda e: e.issuer_fp)

    return Graph(nodes=nodes, edges=edges, candidates=candidates,
                 sig_failed=sig_failed, rejected_edges=rejected,
                 anchors=anchors_by_spki)


# ============================================================================
# 候选链枚举
# ============================================================================
@dataclass
class Chain:
    fingerprints: list[str]          # leaf -> root
    complete: bool                   # 是否终止于信任锚
    terminal_failure: Optional[str]  # LOOP / MAX_DEPTH / UNTRUSTED_ROOT / SIGNATURE
    trusted_anchor_fp: Optional[str]
    depth: int


def _anchor_match(graph: Graph, node: CertNode) -> Optional[CertNode]:
    """RFC 5280：信任判定为「主体 DN 与锚一致 且 绑定公钥与锚一致」。"""
    for anchor in graph.anchors.values():
        if anchor.subject_key == node.subject_key and anchor.spki_fp == node.spki_fp:
            return anchor
    return None


def enumerate_chains(graph: Graph, leaf_fp: str) -> list[Chain]:
    chains: list[Chain] = []
    seen_paths: set[tuple[str, ...]] = set()
    truncated = False

    def emit(frames: list[str], complete: bool, terminal: Optional[str], anchor_fp: Optional[str]):
        key = tuple(frames)
        if key in seen_paths:
            return
        seen_paths.add(key)
        chains.append(Chain(list(frames), complete, terminal, anchor_fp, len(frames)))

    def dfs(frames: list[str], on_path: set[str]):
        nonlocal truncated
        if len(chains) >= MAX_CHAINS:
            truncated = True
            return
        current_fp = frames[-1]
        node = graph.nodes[current_fp]

        # 1) 当前证书即「信任锚同款」（DN+公钥一致，交叉签发场景的常见终止点）
        anchor = _anchor_match(graph, node)
        if anchor is not None:
            emit(frames, True, None, anchor.fp)
            # 若当前帧本身就是上传的锚证书，则不再向上展开（锚之上无需验证）
            if node.is_anchor_upload:
                return
            # 交叉签发的锚同款中间证书：其上方链也可继续枚举为其它候选
        else:
            # 2) 同名锚存在但公钥不同 —— 不是信任终止；记录为一种终止缺陷的依据在核验阶段给出
            pass

        if len(frames) > MAX_DEPTH:
            emit(frames, False, "MAX_DEPTH", None)
            return

        outgoing = graph.candidates.get(current_fp, [])
        moved = False
        for edge in outgoing:
            nxt = edge.issuer_fp
            if nxt in on_path:
                # 环路：把闭合边指回的节点追加呈现，便于图上定位
                emit(frames + [nxt], False, "LOOP", None)
                continue
            moved = True
            dfs(frames + [nxt], on_path | {nxt})
            if truncated:
                return

        # 主体名称可相连但颁发者公钥验签失败的边：路径在该边断裂，作为被淘汰
        # 候选链记录（首个签名失败节点与证据在逐链核验阶段给出）。断边不可信，
        # 不沿其继续向上枚举，也不算作 moved —— 环路 / 未达锚语义保持不变。
        for edge in graph.sig_failed.get(current_fp, []):
            if len(chains) >= MAX_CHAINS:
                truncated = True
                return
            emit(frames + [edge.issuer_fp], False, "SIGNATURE", None)

        # 未匹配任何可用签发者
        if anchor is None and not moved:
            emit(frames, False, "UNTRUSTED_ROOT", None)

    dfs([leaf_fp], {leaf_fp})

    # 稳定排序：有效链优先，其次长度，再按指纹序列字典序
    chains.sort(key=lambda c: (
        0 if c.complete else 1,
        c.depth,
        tuple(graph.nodes[f].fp for f in c.fingerprints if f in graph.nodes),
    ))
    return chains


# ============================================================================
# 逐链核验
# ============================================================================
@dataclass
class CheckInput:
    verify_time: datetime
    dns_name: Optional[str]
    purpose_oid: Optional[object]      # ObjectIdentifier
    purpose_key: Optional[str]


def _fail(rule: str, node_fp: str, message: str, **extra) -> dict:
    d = {"rule": rule, "node": node_fp, "message": message}
    d.update(extra)
    return d


def verify_chain(graph: Graph, chain: Chain, inp: CheckInput) -> Optional[dict]:
    """返回首个失败证据 dict；None 表示该链有效。

    固定核验顺序（保证“首个失败”可复现）：
    1. 终止性：SIGNATURE（候选签发者验签失败）/ LOOP / 未达信任锚（沿叶→根逐边）
    2. VALIDITY        叶 → 根
    3. BASIC_CONSTRAINTS 叶 → 根
    4. KEY_USAGE       叶 → 根
    5. EXTENDED_KEY_USAGE 叶 → 根
    6. HOSTNAME        仅叶
    7. NAME_CONSTRAINTS 各上层 CA 对其下方所有证书的 DNS 标识符，叶 → 根施 CA
    8. PATH_LEN        叶 → 根
    """
    nodes = graph.nodes

    # ---- 1. 终止性 ----
    if chain.terminal_failure == "SIGNATURE":
        # 链在验签失败的边上断裂：首个签名失败节点 = 签名无法被候选签发者
        # 公钥验证通过的证书（RFC 5280 §6.1.3(a)(1)），即断边的子证书
        child_fp, issuer_fp = chain.fingerprints[-2], chain.fingerprints[-1]
        child_node, issuer_node = nodes[child_fp], nodes[issuer_fp]
        edge = next((e for e in graph.sig_failed.get(child_fp, [])
                     if e.issuer_fp == issuer_fp), None)
        sig_error = edge.sig_error if edge is not None else None
        aki_ski = edge.aki_ski_match if edge is not None else None
        idx = len(chain.fingerprints) - 2
        pos = "叶证书" if idx == 0 else f"路径第 {idx + 1} 位证书"
        alg = child_node.cert.signature_algorithm_oid
        return _fail("SIGNATURE", child_fp,
                     f"{pos} {child_node.subject!r} 的签名无法用候选签发者 "
                     f"{issuer_node.subject!r} 的公钥验证通过（主体名称可相连但验签失败，"
                     f"疑似同名不同钥或证书被篡改）"
                     + (f"：{sig_error}" if sig_error else ""),
                     issuer_fp=issuer_fp,
                     issuer=issuer_node.subject,
                     signature_algorithm=alg._name or alg.dotted_string,
                     sig_error=sig_error,
                     aki_ski_match=aki_ski)
    if chain.terminal_failure == "LOOP":
        # 第一个重复出现的节点即环路闭合点
        seen = {}
        for idx, f in enumerate(chain.fingerprints):
            if f in seen:
                return _fail("LOOP", f,
                             f"证书 {nodes[f].subject!r} 在路径中第 {seen[f]+1} 与第 {idx+1} 位重复出现，名称链成环",
                             first_index=seen[f], repeat_index=idx)
            seen[f] = idx
        return _fail("LOOP", chain.fingerprints[-1], "检测到签发环路")
    if chain.terminal_failure == "MAX_DEPTH":
        return _fail("LOOP", chain.fingerprints[-1],
                     f"候选链深度超过上限 {MAX_DEPTH}（疑似超长名称链/环路）")
    if not chain.complete:
        tip = chain.fingerprints[-1]
        tip_node = nodes[tip]
        # 给出更具体的证据：是否存在同名锚但公钥不同
        same_name_anchors = [a for a in graph.anchors.values()
                             if a.subject_key == tip_node.subject_key]
        if same_name_anchors and all(a.spki_fp != tip_node.spki_fp for a in same_name_anchors):
            return _fail("UNTRUSTED_ROOT", tip,
                         f"根证书主体 {tip_node.subject!r} 与本地锚同名，但公钥/指纹不同（同名不同钥），不予信任",
                         anchor_fingerprints=[a.fp for a in same_name_anchors])
        return _fail("UNTRUSTED_ROOT", tip,
                     f"根证书 {tip_node.subject!r} 不由任何本地信任锚签发且其自身不在信任锚中",
                     issuer=tip_node.issuer)

    fps = chain.fingerprints  # leaf -> root(=anchor)
    certs = [nodes[f].cert for f in fps]
    leaf = certs[0]
    # 叶证书自身即信任锚（链长 1）时，它是信任点而非末端实体，不套用叶角色约束
    leaf_is_anchor = (len(fps) == 1 and chain.trusted_anchor_fp == fps[0])

    # ---- 2. VALIDITY ----
    for i, (f, cert) in enumerate(zip(fps, certs)):
        nb, na = cc.cert_not_before(cert), cc.cert_not_after(cert)
        pos = "叶证书" if i == 0 else ("信任锚" if i == len(certs) - 1 else f"中间证书 #{i}")
        if inp.verify_time < nb:
            return _fail("VALIDITY", f,
                         f"{pos} 尚未生效：校验时间 {inp.verify_time.isoformat()} 早于 notBefore {nb.isoformat()}",
                         not_before=nb.isoformat(), not_after=na.isoformat(),
                         verify_time=inp.verify_time.isoformat())
        if inp.verify_time > na:
            return _fail("VALIDITY", f,
                         f"{pos} 已过期：校验时间 {inp.verify_time.isoformat()} 晚于 notAfter {na.isoformat()}",
                         not_before=nb.isoformat(), not_after=na.isoformat(),
                         verify_time=inp.verify_time.isoformat())

    # ---- 3. BASIC CONSTRAINTS ----
    for i, (f, cert) in enumerate(zip(fps, certs)):
        bc = cc.basic_constraints(cert)
        if i == 0:
            if leaf_is_anchor:
                continue
            if bc is not None and bc[0]:
                return _fail("BASIC_CONSTRAINTS", f,
                             f"叶证书带有 cA=TRUE，Basic Constraints 将其标记为 CA，不能作为末端实体证书",
                             ca=True, path_length=bc[1])
        else:
            if bc is None:
                return _fail("BASIC_CONSTRAINTS", f,
                             f"路径第 {i+1} 位证书 {nodes[f].subject!r} 缺少 Basic Constraints 扩展，"
                             "不得作为 CA 给下级发证",
                             ca=False)
            if not bc[0]:
                return _fail("BASIC_CONSTRAINTS", f,
                             f"路径第 {i+1} 位证书 {nodes[f].subject!r} 的 Basic Constraints 为 cA=FALSE，"
                             "却位于签发路径中",
                             ca=False, path_length=bc[1])

    # ---- 4. KEY USAGE ----
    for i, (f, cert) in enumerate(zip(fps, certs)):
        ku = cc.key_usage(cert)
        if ku is None:
            continue
        if i == 0:
            # digitalSignature 或 keyAgreement（TFS 场景）至少其一
            ok_bit = ku.digital_signature or ku.key_agreement
            if inp.purpose_key in ("serverAuth", "clientAuth") and not ok_bit:
                return _fail("KEY_USAGE", f,
                             "叶证书 Key Usage 未置 digitalSignature（也未置 keyAgreement），"
                             "不能用于 TLS 认证",
                             digital_signature=ku.digital_signature,
                             key_agreement=ku.key_agreement)
        else:
            if not ku.key_cert_sign:
                return _fail("KEY_USAGE", f,
                             f"CA 证书 {nodes[f].subject!r} 的 Key Usage 未置 keyCertSign，不得签发证书",
                             key_cert_sign=False)

    # ---- 5. EXTENDED KEY USAGE ----
    if inp.purpose_oid is not None:
        leaf_eku = cc.eku(leaf)
        if leaf_eku is not None:
            if cc.ANY_EKU not in leaf_eku and inp.purpose_oid not in leaf_eku:
                return _fail("EXTENDED_KEY_USAGE", fps[0],
                             f"叶证书 EKU {sorted(o.dotted_string for o in leaf_eku)} "
                             f"不含所请求用途 {inp.purpose_key} "
                             f"({inp.purpose_oid.dotted_string})，且不含 anyExtendedKeyUsage",
                             required_oid=inp.purpose_oid.dotted_string,
                             present=[o.dotted_string for o in leaf_eku])
        # RFC 5280 §4.2.1.12：CA 的 EKU 若存在且不含该用途，则链不可用于该用途
        for i, (f, cert) in enumerate(zip(fps[1:], certs[1:]), start=1):
            ca_eku = cc.eku(cert)
            if ca_eku is not None and cc.ANY_EKU not in ca_eku and inp.purpose_oid not in ca_eku:
                return _fail("EXTENDED_KEY_USAGE", f,
                             f"路径第 {i+1} 位 CA {nodes[f].subject!r} 的 EKU "
                             f"{sorted(o.dotted_string for o in ca_eku)} 不含 {inp.purpose_key}，"
                             "按 RFC 5280 该链不支持所请求用途",
                             required_oid=inp.purpose_oid.dotted_string,
                             present=[o.dotted_string for o in ca_eku])

    # ---- 6. HOSTNAME ----
    if inp.dns_name:
        ids = cc.presented_dns_ids(leaf)
        if not ids:
            return _fail("HOSTNAME", fps[0],
                         f"叶证书未提供任何 DNS 标识符（SAN/dNSName 为空且无可用 CN），"
                         f"无法匹配主机名 {inp.dns_name!r}",
                         hostname=inp.dns_name)
        if not any(cc.dns_match(p, inp.dns_name) for p in ids):
            return _fail("HOSTNAME", fps[0],
                         f"主机名 {inp.dns_name!r} 与叶证书的 DNS 标识符 {ids} 均不匹配（RFC 6125）",
                         hostname=inp.dns_name, presented=ids)

    # ---- 7. NAME CONSTRAINTS ----
    # 即使未指定主机名，也对各证书自身携带的 DNS 标识符施加约束（RFC 5280）
    presented_per_index = [cc.presented_dns_ids(cert) for cert in certs]

    for ca_index in range(1, len(fps)):
        ca_cert = certs[ca_index]
        for below in range(0, ca_index):
            names = presented_per_index[below]
            if not names:
                continue
            where = "叶证书" if below == 0 else f"第 {below+1} 位下级证书"
            bad = cc.check_name_constraints(ca_cert, names, where)
            if bad:
                bad["node"] = fps[ca_index]
                bad["ca_subject"] = nodes[fps[ca_index]].subject
                return bad

    # ---- 8. PATH LEN ----
    # 对每个非锚 CA i（1..n-2；锚在 n-1），统计其下方非自签发中间 CA 数量
    n = len(fps)
    for i in range(1, n - 1):
        bc = cc.basic_constraints(certs[i])
        if bc is None or bc[1] is None:
            continue
        # 该 CA 与叶之间的中间 CA 个数 = i-1；其中自签发证书不计
        count = 0
        for j in range(1, i):
            if not cc.self_issued(certs[j]):
                count += 1
        if count > bc[1]:
            return _fail("PATH_LEN", fps[i],
                         f"CA {nodes[fps[i]].subject!r} 的 pathLenConstraint={bc[1]}，"
                         f"但其下方存在 {count} 个非自签发中间 CA，超出限制",
                         path_len=bc[1], actual=count)

    return None


# ============================================================================
# 证书摘要（供前端展示）
# ============================================================================
def summarize(cert: x509.Certificate) -> dict:
    bc = cc.basic_constraints(cert)
    ku = cc.key_usage(cert)
    ekus = cc.eku(cert)
    aki = cc.get_extension(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    ski = cc.get_extension(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    return {
        "fingerprint_sha256": cc.fp(cert),
        "spki_sha256": cc.spki_fp(cert),
        "subject": cc.name_one_line(cert.subject),
        "issuer": cc.name_one_line(cert.issuer),
        "serial": cc.serial_hex(cert),
        "not_before": cc.cert_not_before(cert).isoformat(),
        "not_after": cc.cert_not_after(cert).isoformat(),
        "self_issued": cc.self_issued(cert),
        "signature_algorithm": cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string,
        "public_key": _key_desc(cert),
        "basic_constraints": None if bc is None else {"ca": bc[0], "path_len": bc[1]},
        "key_usage": None if ku is None else {
            "digital_signature": ku.digital_signature,
            "key_cert_sign": ku.key_cert_sign,
            "crl_sign": ku.crl_sign,
            "key_agreement": ku.key_agreement,
            "data_encipherment": ku.data_encipherment,
            "key_encipherment": ku.key_encipherment,
            "content_commitment": ku.content_commitment,
            "encipher_only": _ku_bit(ku, "encipher_only"),
            "decipher_only": _ku_bit(ku, "decipher_only"),
        },
        "eku": None if ekus is None else sorted(o.dotted_string for o in ekus),
        "san_dns": cc.san_dns(cert),
        "ski": ski.digest.hex() if ski is not None else None,
        "aki": aki.key_identifier.hex() if aki is not None and aki.key_identifier else None,
    }


def _key_desc(cert: x509.Certificate) -> dict:
    k = cert.public_key()
    if hasattr(k, "key_size"):
        return {"type": type(k).__name__, "size": k.key_size}
    return {"type": type(k).__name__}


def _ku_bit(ku: x509.KeyUsage, name: str):
    # encipher_only / decipher_only 仅在 keyAgreement 置位时才有定义
    try:
        return getattr(ku, name)
    except ValueError:
        return None
