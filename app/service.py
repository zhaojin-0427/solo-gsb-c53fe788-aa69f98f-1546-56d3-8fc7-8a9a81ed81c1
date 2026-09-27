"""把证书图、链枚举与逐链核验串成一次完整实验分析。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509

from . import cert_core as cc
from . import chain as ch


class AnalysisError(Exception):
    pass


def graph_to_dict(graph: ch.Graph) -> dict:
    nodes = []
    for n in sorted(graph.nodes.values(), key=lambda x: x.fp):
        nodes.append({
            "id": n.fp,
            "label": _short_name(n.subject),
            "subject": n.subject,
            "issuer": n.issuer,
            "roles": n.roles,
            "is_anchor": n.is_anchor_upload,
            "summary": ch.summarize(n.cert),
        })
    edges = []
    for e in graph.edges:
        edges.append({
            "source": e.child_fp,
            "target": e.issuer_fp,
            "sig_ok": e.sig_ok,
            "sig_error": e.sig_error,
            "aki_ski_match": e.aki_ski_match,
            # 与 build_graph 同一判定：验签通过且 AKI/SKI 不冲突的边才可走链；
            # 验签失败的边（sig_failed）会在枚举时产生 SIGNATURE 淘汰链
            "usable": e.sig_ok and e.aki_ski_match is not False,
            "sig_failed": not e.sig_ok,
        })
    # 同名主体分组（同名不同钥是交叉签发/伪装的关键线索）
    groups: dict[tuple, list[str]] = {}
    for n in graph.nodes.values():
        groups.setdefault(n.subject_key, []).append(n.fp)
    same_name = [sorted(v) for v in groups.values() if len(v) > 1]
    return {"nodes": nodes, "edges": edges, "same_name_groups": same_name}


def _short_name(rfc4514: str) -> str:
    # rfc4514 是逆序的，CN 通常在最前；取第一个属性展示
    return rfc4514.split(",")[0]


def analyze(leaf_certs: list[x509.Certificate],
            intermediates: list[x509.Certificate],
            anchors: list[x509.Certificate],
            verify_time: datetime,
            dns_name: Optional[str],
            purpose_key: Optional[str]) -> dict:

    if not leaf_certs:
        raise AnalysisError("至少需要一本叶证书")

    purpose_oid = cc.PURPOSE_OIDS.get(purpose_key) if purpose_key else None
    if purpose_key and purpose_oid is None:
        raise AnalysisError(f"未知用途: {purpose_key}")

    if verify_time.tzinfo is None:
        verify_time = verify_time.replace(tzinfo=timezone.utc)
    else:
        verify_time = verify_time.astimezone(timezone.utc)

    graph = ch.build_graph(leaf_certs, intermediates, anchors)
    inp = ch.CheckInput(verify_time=verify_time, dns_name=dns_name,
                        purpose_oid=purpose_oid, purpose_key=purpose_key)

    leaves_result = []
    for leaf in leaf_certs:
        leaf_fp = cc.fp(leaf)
        chains = ch.enumerate_chains(graph, leaf_fp)

        chain_reports = []
        valid_reports = []
        for idx, c in enumerate(chains):
            failure = ch.verify_chain(graph, c, inp)
            report = {
                "index": idx,
                "ids": list(c.fingerprints),
                "subjects": [graph.nodes[f].subject for f in c.fingerprints],
                "length": c.depth,
                "complete": c.complete,
                "anchor_fp": c.trusted_anchor_fp,
                "failure": None,
            }
            if failure is not None:
                failure["rule_label"] = ch.RULE_LABELS.get(failure["rule"], failure["rule"])
                failure["rule_ref"] = ch.RULE_REFS.get(failure["rule"], "")
                # 失败节点在本链中的位置（叶=0）
                try:
                    failure["node_index"] = c.fingerprints.index(failure["node"])
                except ValueError:
                    failure["node_index"] = None
                report["failure"] = failure
            else:
                valid_reports.append(report)
            chain_reports.append(report)

        # 稳定选链：先按长度（更短优先），再按各节点指纹字典序
        selected = None
        if valid_reports:
            selected = min(
                valid_reports,
                key=lambda r: (r["length"], tuple(graph.nodes[i].fp for i in r["ids"])),
            )["index"]

        leaves_result.append({
            "leaf_fp": leaf_fp,
            "leaf_subject": ch.summarize(leaf)["subject"],
            "candidate_count": len(chain_reports),
            "valid_count": len(valid_reports),
            # 淘汰列表：候选链中未计入有效链的部分（含 SIGNATURE / LOOP /
            # UNTRUSTED_ROOT / VALIDITY 等所有首败链）
            "eliminated_count": len(chain_reports) - len(valid_reports),
            "selected_index": selected,
            "chains": chain_reports,
        })

    return {
        "params": {
            "verify_time": verify_time.isoformat(),
            "dns_name": dns_name,
            "purpose": purpose_key,
            "purpose_label": cc.PURPOSE_LABELS.get(purpose_key) if purpose_key else None,
            "offline": True,
        },
        "graph": graph_to_dict(graph),
        "leaves": leaves_result,
    }
