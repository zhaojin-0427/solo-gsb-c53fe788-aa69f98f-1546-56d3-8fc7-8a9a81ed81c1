"""信任锚替换预演：对历史会话无损重放「基线」与「替代锚」两套核验并对齐差异。

关键约束：
- 只读：不新增会话、不改写任何已存档报告；预演结果仅随本次响应返回；
- 无损重放：使用会话保存的叶证书、中间证书、原锚，以及当时的校验时间、
  DNS、用途（从存档报告 params 还原）；
- 旧会话若缺少按角色持久化的原始证书（session_certs 无叶证书），
  明确标记为 not_replayable，不做猜测式重放；
- 基线重放若与存档结论不一致（有效性或选中链），标记 baseline_drift，
  表示差异来自基线本身，不归因于锚替换。
"""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509

from . import cert_core as cc
from . import chain as ch
from .service import analyze


def _parse_pems(pems: list[str]) -> list[x509.Certificate]:
    certs = []
    for pem in pems:
        certs.extend(cc.load_certificates(pem.encode("ascii")))
    return certs


def _parse_verify_time(value: str | None) -> datetime:
    if value:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return datetime.now(timezone.utc)


def _dedupe_fps(certs: list[x509.Certificate]) -> list[str]:
    seen: set[str] = set()
    out = []
    for c in certs:
        f = cc.fp(c)
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _anchor_brief(cert: x509.Certificate) -> dict:
    s = ch.summarize(cert)
    return {
        "fingerprint": s["fingerprint_sha256"],
        "subject": s["subject"],
        "spki_sha256": s["spki_sha256"],
        "not_before": s["not_before"],
        "not_after": s["not_after"],
    }


def _snapshot(leaf_result: dict) -> dict:
    """提取对齐所需的最小结论：有效性、选中链指纹/主体序列、选中首败规则。"""
    idx = leaf_result["selected_index"]
    selected_ids = None
    selected_subjects = None
    if idx is not None:
        chain = leaf_result["chains"][idx]
        selected_ids = list(chain["ids"])
        selected_subjects = list(chain["subjects"])
    first_rule = None
    for c in leaf_result["chains"]:
        if c["failure"] is not None:
            first_rule = c["failure"].get("rule")
            break
    return {
        "valid": idx is not None,
        "selected_index": idx,
        "selected_path": selected_ids,
        "selected_subjects": selected_subjects,
        "first_failure_rule": first_rule,
        "valid_count": leaf_result["valid_count"],
        "candidate_count": leaf_result["candidate_count"],
    }


def _archived_snapshot(archived_leaf: dict) -> dict:
    idx = archived_leaf.get("selected_index")
    selected_ids = None
    selected_subjects = None
    if idx is not None:
        chain = archived_leaf["chains"][idx]
        selected_ids = list(chain["ids"])
        selected_subjects = list(chain.get("subjects", []))
    first_rule = None
    for c in archived_leaf.get("chains", []):
        if c.get("failure"):
            first_rule = c["failure"].get("rule")
            break
    return {
        "valid": idx is not None,
        "selected_index": idx,
        "selected_path": selected_ids,
        "selected_subjects": selected_subjects,
        "first_failure_rule": first_rule,
        "valid_count": archived_leaf.get("valid_count"),
        "candidate_count": archived_leaf.get("candidate_count"),
    }


def _diff_leaves(archived: dict, baseline: dict, alternative: dict) -> list[dict]:
    """按叶证书指纹对齐存档 / 基线重放 / 替代重放三方结论。

    任一指纹集合不一致，或某叶的基线重放结论与存档不一致 → baseline_drift，
    该会话的差异不归因于锚替换。
    """
    by_fp_arch = {l["leaf_fp"]: l for l in archived.get("leaves", [])}
    by_fp_base = baseline["leaves_by_fp"]
    by_fp_alt = alternative["leaves_by_fp"]

    fps = sorted(set(by_fp_arch) | set(by_fp_base) | set(by_fp_alt))
    leaves = []
    drift = False
    for fp in fps:
        a = _archived_snapshot(by_fp_arch[fp]) if fp in by_fp_arch else None
        b = by_fp_base.get(fp)
        c = by_fp_alt.get(fp)

        leaf_drift = a is None or b is None or c is None or (
            a["valid"] != b["valid"]
            or a["selected_path"] != b["selected_path"]
            # 同为无效但首败规则不同，结论同样无法由当前重放复现 → 漂移
            or (not a["valid"] and not b["valid"]
                and a["first_failure_rule"] != b["first_failure_rule"])
        )
        if leaf_drift:
            drift = True

        if leaf_drift:
            outcome = "baseline_drift"
        elif b["valid"] != c["valid"]:
            outcome = "validity_flip"          # 有效性翻转
        elif b["selected_path"] != c["selected_path"]:
            outcome = "chain_changed"          # 选中链变化（同为有效或同为无有效）
        else:
            outcome = "unchanged"              # 无变化

        leaves.append({
            "leaf_fp": fp,
            "leaf_subject": (by_fp_arch.get(fp, {}) or {}).get("leaf_subject")
                            or _subject_of(baseline, alternative, fp),
            "outcome": outcome,
            "archived": a,
            "baseline": b,
            "alternative": c,
        })
    return leaves, drift


def _subject_of(baseline: dict, alternative: dict, fp: str) -> str | None:
    for lr in baseline["result"].get("leaves", []) + alternative["result"].get("leaves", []):
        if lr["leaf_fp"] == fp:
            return lr.get("leaf_subject")
    return None


def _index_leaves(result: dict) -> dict[str, dict]:
    return {lr["leaf_fp"]: _snapshot(lr) for lr in result.get("leaves", [])}


def replay_session(session_row: dict, stored_pems: dict[str, list[str]],
                   replacement_anchors: list[x509.Certificate]) -> dict:
    """对单个历史会话执行锚替换预演。绝不写库、不改写 session_row。"""
    sid = session_row["id"]
    base = {
        "session_id": sid,
        "created_at": session_row.get("created_at"),
        "status": "ok",
        "replayable": True,
        "leaf_count": session_row.get("leaf_count"),
        "intermediate_count": session_row.get("intermediate_count"),
        "anchor_count": session_row.get("anchor_count"),
    }

    leaves_pem = stored_pems.get("leaf", [])
    if not leaves_pem:
        # 旧会话缺少按角色持久化的原始证书：明确不可预演
        base.update(status="ok", replayable=False, outcome="not_replayable",
                    reason="该历史会话未按角色保存原始证书（旧版数据），"
                           "无法无损重放基线与替代方案，故不参与锚替换预演。",
                    leaves=[])
        return base

    leaf_certs = _parse_pems(leaves_pem)
    inter_certs = _parse_pems(stored_pems.get("intermediate", []))
    anchor_certs = _parse_pems(stored_pems.get("anchor", []))

    archived = session_row["result"]
    params = archived.get("params", {})
    vt = _parse_verify_time(params.get("verify_time"))
    dns_name = params.get("dns_name") or None
    purpose_key = params.get("purpose") or None

    # ---- 基线重放：原叶 / 原中间 / 原锚 + 原校验时间、DNS、用途 ----
    baseline_result = analyze(leaf_certs, inter_certs, anchor_certs,
                              verify_time=vt, dns_name=dns_name,
                              purpose_key=purpose_key)
    # ---- 替代方案：只替换锚集合，其余输入完全一致 ----
    alt_result = analyze(leaf_certs, inter_certs, replacement_anchors,
                         verify_time=vt, dns_name=dns_name,
                         purpose_key=purpose_key)

    baseline_pkg = {"result": baseline_result, "leaves_by_fp": _index_leaves(baseline_result)}
    alt_pkg = {"result": alt_result, "leaves_by_fp": _index_leaves(alt_result)}
    leaf_diffs, drift = _diff_leaves(archived, baseline_pkg, alt_pkg)

    base_fps = set(_dedupe_fps(anchor_certs))
    alt_fps = set(_dedupe_fps(replacement_anchors))
    anchor_by_fp = {cc.fp(c): c for c in anchor_certs + list(replacement_anchors)}

    def _brief_set(fps: set[str]) -> list[dict]:
        return [_anchor_brief(anchor_by_fp[f]) for f in sorted(fps)]

    outcome = "baseline_drift" if drift else (
        "unchanged" if all(l["outcome"] == "unchanged" for l in leaf_diffs)
        else "changed"
    )
    counts = {"validity_flip": 0, "chain_changed": 0, "unchanged": 0, "baseline_drift": 0}
    for l in leaf_diffs:
        counts[l["outcome"]] += 1

    base.update(
        outcome=outcome,
        baseline_drift=drift,
        leaf_counts=counts,
        params={"verify_time": params.get("verify_time"),
                "dns_name": dns_name, "purpose": purpose_key},
        original_anchors=_brief_set(base_fps),
        replacement_anchors=_brief_set(alt_fps),
        anchors_added=_brief_set(alt_fps - base_fps),
        anchors_removed=_brief_set(base_fps - alt_fps),
        leaves=leaf_diffs,
    )
    return base


def rehearse(get_session, get_certs, session_ids: list[int],
             replacement_anchors: list[x509.Certificate]) -> dict:
    """对多条历史会话依次预演；单会话问题隔离为该会话的错误条目，不影响其余会话。"""
    results = []
    summary = {"sessions": 0, "replayable": 0, "not_replayable": 0,
               "changed": 0, "unchanged": 0, "baseline_drift": 0, "errors": 0}
    for sid in session_ids:
        row = get_session(sid)
        if row is None:
            results.append({"session_id": sid, "status": "error",
                            "replayable": False, "outcome": "not_found",
                            "error": "会话不存在"})
            summary["errors"] += 1
            continue
        pems = get_certs(sid)
        if not pems.get("leaf"):
            results.append(replay_session(row, pems, replacement_anchors))
            summary["sessions"] += 1
            summary["not_replayable"] += 1
            continue
        try:
            r = replay_session(row, pems, replacement_anchors)
        except Exception as exc:  # noqa: BLE001 - 单会话解析/重放异常隔离
            results.append({"session_id": sid, "status": "error",
                            "replayable": True, "outcome": "error",
                            "error": f"{type(exc).__name__}: {exc}"})
            summary["errors"] += 1
            continue
        results.append(r)
        summary["sessions"] += 1
        summary["replayable"] += 1
        summary[r["outcome"]] += 1

    summary["replacement_anchor_count"] = len(_dedupe_fps(replacement_anchors))
    return {"summary": summary, "sessions": results}
