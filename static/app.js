/* X.509 证书链验证实验台前端 —— 原生 JS，无外部依赖，无任何网络外联（仅同源 API）。 */
"use strict";

const state = {
  files: { leaf: [], intermediates: [], anchors: [] },
  result: null,
  nodeById: new Map(),
  layout: { nodes: new Map(), edges: [] },
  currentLeaf: 0,
};

const $ = (id) => document.getElementById(id);

/* ================= 文件选择 ================= */
function bindDropzone(inputId, listId, key) {
  const input = $(inputId), list = $(listId);
  input.addEventListener("change", () => {
    state.files[key] = Array.from(input.files);
    renderFileList(list, input.files);
  });
}
function renderFileList(el, files) {
  el.innerHTML = "";
  for (const f of files) {
    const t = document.createElement("span");
    t.className = "file-tag";
    t.textContent = `${f.name} (${(f.size / 1024).toFixed(1)}KB)`;
    el.appendChild(t);
  }
}
bindDropzone("in-leaf", "list-leaf", "leaf");
bindDropzone("in-inter", "list-inter", "intermediates");
bindDropzone("in-anchor", "list-anchor", "anchors");

$("btn-clear").addEventListener("click", () => {
  for (const id of ["in-leaf", "in-inter", "in-anchor"]) $(id).value = "";
  state.files = { leaf: [], intermediates: [], anchors: [] };
  for (const id of ["list-leaf", "list-inter", "list-anchor"]) $(id).innerHTML = "";
  $("error-box").hidden = true;
});

/* ================= 提交分析 ================= */
$("btn-run").addEventListener("click", runAnalysis);

async function runAnalysis() {
  const errBox = $("error-box");
  errBox.hidden = true;
  const fd = new FormData();
  state.files.leaf.forEach((f) => fd.append("leaves", f));
  state.files.intermediates.forEach((f) => fd.append("intermediates", f));
  state.files.anchors.forEach((f) => fd.append("anchors", f));
  fd.append("verify_time", $("in-time").value.trim());
  fd.append("dns_name", $("in-dns").value.trim());
  fd.append("purpose", $("in-purpose").value);

  const btn = $("btn-run");
  btn.disabled = true;
  btn.textContent = "验证中…";
  try {
    const resp = await fetch("/api/analyze", { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "请求失败");
    state.result = data.result;
    state.currentLeaf = 0;
    renderAll();
  } catch (e) {
    errBox.textContent = "错误：" + e.message;
    errBox.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "开始链验证";
  }
}

/* ================= 渲染总控 ================= */
function renderAll() {
  const r = state.result;
  state.nodeById = new Map(r.graph.nodes.map((n) => [n.id, n]));
  computeLayout(r.graph);

  const sel = $("leaf-select");
  if (r.leaves.length > 1) {
    sel.hidden = false;
    sel.innerHTML = "";
    r.leaves.forEach((lr, i) => {
      const o = document.createElement("option");
      o.value = i;
      o.textContent = `叶证书 ${i + 1}: ${lr.leaf_subject}`;
      sel.appendChild(o);
    });
    sel.onchange = () => { state.currentLeaf = +sel.value; renderChains(); highlightGraph(); };
  } else {
    sel.hidden = true;
  }
  renderChains();
  drawGraph();
}

/* ================= 图布局（按链长分层） ================= */
function computeLayout(graph) {
  const ranks = new Map();
  graph.nodes.forEach((n) => ranks.set(n.id, n.roles.includes("leaf") ? 0 : null));

  // 迭代松弛：rank(target) >= rank(source)+1；只用「可用边」（签名通过），
  // 自环边不参与；层级上限 5 使环路场景收敛到同一列而不至于列数爆炸
  const usableEdges = graph.edges.filter((e) => e.usable);
  for (let pass = 0; pass < 64; pass++) {
    let changed = false;
    for (const e of usableEdges) {
      if (e.source === e.target) continue;
      const rs = ranks.get(e.source);
      if (rs === null || rs === undefined) continue;
      const want = Math.min(rs + 1, 5);
      if (ranks.get(e.target) === null || ranks.get(e.target) === undefined || ranks.get(e.target) < want) {
        ranks.set(e.target, want);
        changed = true;
      }
    }
    if (!changed) break;
  }
  // 不可达节点（如孤立锚）：放最右列
  let maxRank = 0;
  ranks.forEach((v) => { maxRank = Math.max(maxRank, v ?? 0); });
  graph.nodes.forEach((n) => {
    if (ranks.get(n.id) === null || ranks.get(n.id) === undefined) {
      ranks.set(n.id, Math.min(maxRank + 1, 5));
    }
  });

  // 分列并纵向排布
  const cols = new Map();
  graph.nodes.forEach((n) => {
    const rk = ranks.get(n.id);
    if (!cols.has(rk)) cols.set(rk, []);
    cols.get(rk).push(n.id);
  });
  cols.forEach((arr) => arr.sort((a, b) => state.nodeById.get(a).subject.localeCompare(state.nodeById.get(b).subject)));

  const canvas = $("graph");
  const W = canvas.width, H = canvas.height;
  const colKeys = [...cols.keys()].sort((a, b) => a - b);
  const colW = W / (colKeys.length + 1);

  const placed = new Map();
  colKeys.forEach((rk, ci) => {
    const ids = cols.get(rk);
    const rowH = H / (ids.length + 1);
    ids.forEach((id, ri) => {
      placed.set(id, { x: colW * (ci + 1), y: rowH * (ri + 1), node: state.nodeById.get(id) });
    });
  });
  state.layout = { nodes: placed, edges: graph.edges, graph };
}

/* ================= Canvas 绘图 ================= */
function selectedChainIds() {
  const lr = state.result.leaves[state.currentLeaf];
  if (lr.selected_index === null || lr.selected_index === undefined) return null;
  return new Set(lr.chains[lr.selected_index].ids);
}
function failedNodeIds() {
  const lr = state.result.leaves[state.currentLeaf];
  const s = new Set();
  lr.chains.forEach((c) => { if (c.failure) s.add(c.failure.node); });
  return s;
}

function drawGraph() {
  const canvas = $("graph");
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const { nodes, edges } = state.layout;
  const chainIds = selectedChainIds();

  // 边
  for (const e of edges) {
    const a = nodes.get(e.source), b = nodes.get(e.target);
    if (!a || !b) continue;
    const onSelected = chainIds && chainIds.has(e.source) && chainIds.has(e.target);
    const color = onSelected ? "#c084fc" : (e.sig_ok ? "#6f7d9c" : "#f0556b");
    ctx.strokeStyle = color;
    ctx.lineWidth = onSelected ? 3 : 1.4;
    if (!e.sig_ok) ctx.setLineDash([6, 4]); else ctx.setLineDash([]);
    if (e.source === e.target) {
      // 自环：在节点上方画小圆弧
      ctx.beginPath();
      ctx.arc(a.x, a.y - 22, 11, Math.PI * 0.15, Math.PI * 1.6);
      ctx.stroke();
      ctx.setLineDash([]);
      // 自环箭头
      ctx.beginPath();
      ctx.fillStyle = color;
      ctx.moveTo(a.x + 9, a.y - 14);
      ctx.lineTo(a.x + 15, a.y - 22);
      ctx.lineTo(a.x + 5, a.y - 24);
      ctx.closePath();
      ctx.fill();
      continue;
    }
    ctx.beginPath();
    const mx = (a.x + b.x) / 2;
    ctx.moveTo(a.x, a.y);
    ctx.quadraticCurveTo(mx, a.y, b.x, b.y);
    ctx.stroke();
    ctx.setLineDash([]);
    drawArrow(ctx, a.x, a.y, b.x, b.y, color);
  }

  // 同名分组提示（虚框）
  const groups = state.layout.graph.same_name_groups || [];
  for (const g of groups) {
    const pts = g.map((id) => nodes.get(id)).filter(Boolean);
    if (pts.length < 2) continue;
    pts.forEach((p) => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 30, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(245,166,35,.55)";
      ctx.setLineDash([3, 3]);
      ctx.lineWidth = 1.2;
      ctx.stroke();
      ctx.setLineDash([]);
    });
  }

  // 节点
  const failed = failedNodeIds();
  nodes.forEach((p, id) => {
    const n = p.node;
    let color = "#4f8cff";
    if (n.is_anchor) color = "#f5a623";
    else if (n.roles.includes("intermediate")) color = "#35c48d";
    if (chainIds && chainIds.has(id)) color = "#c084fc";

    ctx.beginPath();
    ctx.arc(p.x, p.y, 17, 0, Math.PI * 2);
    ctx.fillStyle = "#13203a";
    ctx.fill();
    ctx.lineWidth = failed.has(id) ? 3.5 : 2;
    ctx.strokeStyle = failed.has(id) ? "#f0556b" : color;
    ctx.stroke();

    ctx.fillStyle = color;
    ctx.font = "bold 10px sans-serif";
    ctx.textAlign = "center";
    const glyph = n.is_anchor ? "锚" : (n.roles.includes("leaf") ? "叶" : "CA");
    ctx.fillText(glyph, p.x, p.y + 3.5);

    // 主体名
    ctx.fillStyle = "#cdd8ee";
    ctx.font = "10.5px sans-serif";
    const label = n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label;
    ctx.fillText(label, p.x, p.y + 33);
    ctx.fillStyle = "#6f7d9c";
    ctx.font = "9.5px monospace";
    ctx.fillText(id.slice(0, 8), p.x, p.y - 24);
  });
}

function drawArrow(ctx, x1, y1, x2, y2, color) {
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len, uy = dy / len;
  const r = 19;
  // 沿曲线末端切线近似用弦方向（节点很近时足够）
  const px = x2 - ux * r, py = y2 - uy * r;
  const ang = Math.atan2(y2 - y1, x2 - x1);
  ctx.beginPath();
  ctx.fillStyle = color;
  ctx.moveTo(px, py);
  ctx.lineTo(px - 8 * Math.cos(ang - 0.42), py - 8 * Math.sin(ang - 0.42));
  ctx.lineTo(px - 8 * Math.cos(ang + 0.42), py - 8 * Math.sin(ang + 0.42));
  ctx.closePath();
  ctx.fill();
}

/* 画布交互：点击节点 / 悬停提示 */
const canvas = $("graph");
canvas.addEventListener("click", (ev) => {
  const p = pickNode(ev);
  if (p) showCertModal(p.node);
});
canvas.addEventListener("mousemove", (ev) => {
  const p = pickNode(ev);
  canvas.style.cursor = p ? "pointer" : "default";
  if (p) { canvas.title = `${p.node.subject}\n签发者: ${p.node.issuer}\n角色: ${p.node.roles.join(", ")}`; }
});
function pickNode(ev) {
  const rect = canvas.getBoundingClientRect();
  const sx = canvas.width / rect.width, sy = canvas.height / rect.height;
  const x = (ev.clientX - rect.left) * sx, y = (ev.clientY - rect.top) * sy;
  for (const [, p] of state.layout.nodes) {
    if ((p.x - x) ** 2 + (p.y - y) ** 2 <= 19 ** 2) return p;
  }
  return null;
}
function highlightGraph() { drawGraph(); }

/* ================= 证书详情 ================= */
function showCertModal(node) {
  $("modal-content").textContent = JSON.stringify(node.summary, null, 2);
  $("modal").hidden = false;
}
$("modal-close").addEventListener("click", () => { $("modal").hidden = true; });
$("modal").addEventListener("click", (e) => { if (e.target.id === "modal") $("modal").hidden = true; });

/* ================= 候选链列表 ================= */
function renderChains() {
  const r = state.result;
  const lr = r.leaves[state.currentLeaf];
  const box = $("chains");
  box.innerHTML = "";

  $("summary-bar").innerHTML =
    `共枚举 <b>${lr.candidate_count}</b> 条无重复候选链 · 有效 <b style="color:var(--ok)">${lr.valid_count}</b> 条 · ` +
    (lr.selected_index !== null && lr.selected_index !== undefined
      ? `选中：<b style="color:var(--sel)">第 ${lr.selected_index + 1} 条</b>（最短且指纹字典序最先）`
      : `<b style="color:var(--bad)">无有效链</b>`);

  lr.chains.forEach((c, idx) => {
    const card = document.createElement("div");
    const valid = c.failure === null;
    card.className = "chain-card " + (valid ? "valid" : "invalid") +
      (idx === lr.selected_index ? " selected" : "");

    const head = document.createElement("div");
    head.className = "chain-head";
    const badges = [];
    if (idx === lr.selected_index) badges.push(`<span class="badge sel">★ 选中链</span>`);
    badges.push(valid
      ? `<span class="badge ok">有效</span>`
      : `<span class="badge bad">淘汰</span>`);
    head.innerHTML = badges.join("") +
      `<span class="chain-title">路径 #${idx + 1} · ${c.length} 本证书 · ` +
      (valid ? "所有规则通过" : `首败: ${c.failure.rule_label} @ 节点 ${(c.failure.node_index ?? -1) + 1}`) +
      `</span><span class="chev">▾</span>`;
    card.appendChild(head);

    const body = document.createElement("div");
    body.style.display = (idx === lr.selected_index || !valid) ? "block" : "none";

    // 路径节点
    const path = document.createElement("div");
    path.className = "path";
    c.ids.forEach((id, i) => {
      const n = state.nodeById.get(id);
      const chip = document.createElement("span");
      const role = i === 0 ? "leaf" : (n && n.is_anchor ? "anchor" : "inter");
      chip.className = `node-chip ${role}`;
      if (c.failure && c.failure.node === id) chip.classList.add("failed");
      chip.textContent = n ? n.label : id.slice(0, 12);
      chip.title = n ? n.subject : id;
      chip.addEventListener("click", () => n && showCertModal(n));
      path.appendChild(chip);
      if (i < c.ids.length - 1) {
        const ar = document.createElement("span");
        ar.className = "arrow";
        ar.textContent = "→";
        path.appendChild(ar);
      }
    });
    body.appendChild(path);

    // 证据
    if (c.failure) {
      const ev = document.createElement("div");
      ev.className = "evidence";
      const { message, rule, rule_label, rule_ref, node, node_index, ...rest } = c.failure;
      ev.innerHTML =
        `<div><span class="ev-rule">${rule_label}（${rule}）</span> ` +
        `<span class="ev-ref">${rule_ref}</span></div>` +
        `<div class="ev-msg">${escapeHtml(message)}</div>` +
        `<div class="ev-msg">失败节点位置：链上第 ${(node_index ?? -2) + 1} 位 · 指纹 ${node.slice(0, 16)}…（点击查看证书）</div>`;
      if (Object.keys(rest).length) {
        const pre = document.createElement("pre");
        pre.textContent = JSON.stringify(rest, null, 2);
        ev.appendChild(pre);
      }
      const n = state.nodeById.get(node);
      if (n) {
        const btn = document.createElement("button");
        btn.textContent = "查看失败节点证书";
        btn.style.marginTop = "6px";
        btn.addEventListener("click", () => showCertModal(n));
        ev.appendChild(btn);
      }
      body.appendChild(ev);
    }
    card.appendChild(body);

    head.addEventListener("click", () => {
      body.style.display = body.style.display === "none" ? "block" : "none";
    });
    box.appendChild(card);
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
}

/* ================= 样例 ================= */
async function loadSamples() {
  try {
    const resp = await fetch("/api/samples");
    const data = await resp.json();
    const box = $("samples");
    box.innerHTML = "";
    for (const s of data.samples) {
      const card = document.createElement("div");
      card.className = "sample-card";
      const desc = (s.readme || "").replace(/^#.*\n/, "").trim().slice(0, 110);
      card.innerHTML = `<div class="sc-id">${s.id}</div><div class="sc-desc">${escapeHtml(desc)}…</div>`;
      card.addEventListener("click", () => loadSample(s));
      box.appendChild(card);
    }
  } catch {
    $("samples").textContent = "样例不可用";
  }
}

async function loadSample(s) {
  const toFile = async (role, name) => {
    const resp = await fetch(`/api/samples/${s.id}/${role}/${name}`);
    const blob = await resp.blob();
    return new File([blob], name, { type: "application/x-pem-file" });
  };
  state.files = { leaf: [], intermediates: [], anchors: [] };
  for (const name of s.files.leaf || []) {
    if (name.endsWith(".der")) continue; // DER 样本供手动测试，自动加载时只用 PEM
    state.files.leaf.push(await toFile("leaf", name));
  }
  for (const name of s.files.intermediates || []) state.files.intermediates.push(await toFile("intermediates", name));
  for (const name of s.files.anchors || []) state.files.anchors.push(await toFile("anchors", name));

  renderFileList($("list-leaf"), state.files.leaf);
  renderFileList($("list-inter"), state.files.intermediates);
  renderFileList($("list-anchor"), state.files.anchors);

  // 根据场景给出建议参数
  const presets = {
    "01-standard": ["2025-06-01T00:00:00Z", "www.example.com", "serverAuth"],
    "02-cross-signed": ["2025-06-01T00:00:00Z", "app.example.com", "serverAuth"],
    "03-same-name": ["2025-06-01T00:00:00Z", "bank.example.com", "serverAuth"],
    "04-loop": ["2025-06-01T00:00:00Z", "loop.example.com", "serverAuth"],
    "05-expired": ["2025-06-01T00:00:00Z", "old.example.com", "serverAuth"],
    "06-pathlen": ["2025-06-01T00:00:00Z", "deep.example.com", "serverAuth"],
    "07-name-constraints": ["2025-06-01T00:00:00Z", "www.evil.example.com", "serverAuth"],
    "08-eku": ["2025-06-01T00:00:00Z", "client.example.com", "serverAuth"],
    "09-hostname": ["2025-06-01T00:00:00Z", "wrong.example.com", "serverAuth"],
  };
  const p = presets[s.id];
  if (p) {
    $("in-time").value = p[0]; $("in-dns").value = p[1]; $("in-purpose").value = p[2];
  }
}

/* ================= 历史会话 ================= */
$("link-history").addEventListener("click", async (e) => {
  e.preventDefault();
  const resp = await fetch("/api/sessions");
  const data = await resp.json();
  if (!data.sessions.length) { alert("暂无历史会话"); return; }

  const answer = prompt(
    "输入会话编号以重新载入渲染：\n\n" +
    data.sessions.map((s) =>
      `#${s.id}  ${s.created_at.slice(0, 19).replace("T", " ")}  ` +
      `dns=${s.dns_name || "-"} purpose=${s.purpose || "-"} ` +
      `(叶${s.leaf_count}/中${s.intermediate_count}/锚${s.anchor_count})`).join("\n"),
    data.sessions[0].id,
  );
  if (answer === null) return;
  const id = parseInt(answer, 10);
  if (!id) return;
  const r = await fetch(`/api/sessions/${id}`);
  if (!r.ok) { alert("会话不存在: " + id); return; }
  const row = await r.json();
  state.result = row.result;
  state.currentLeaf = 0;
  renderAll();
});

loadSamples();

/* ================= 信任锚替换预演 ================= */
const rehState = { sessions: [], anchorFiles: [] };

const inRehAnchor = $("in-rehearse-anchor");
inRehAnchor.addEventListener("change", () => {
  rehState.anchorFiles = Array.from(inRehAnchor.files);
  renderFileList($("list-rehearse-anchor"), inRehAnchor.files);
});

$("btn-open-rehearse").addEventListener("click", openRehearse);
$("rehearse-close").addEventListener("click", () => { $("rehearse-modal").hidden = true; });
$("rehearse-modal").addEventListener("click", (e) => {
  if (e.target.id === "rehearse-modal") $("rehearse-modal").hidden = true;
});
$("btn-run-rehearse").addEventListener("click", runRehearse);

async function openRehearse() {
  $("rehearse-modal").hidden = false;
  $("reh-results").innerHTML = "";
  $("rehearse-error").textContent = "";
  const listEl = $("reh-session-list");
  listEl.innerHTML = "加载历史会话中…";
  try {
    const resp = await fetch("/api/sessions");
    const data = await resp.json();
    rehState.sessions = data.sessions || [];
    renderSessionPicker();
  } catch (e) {
    listEl.innerHTML = `<span class="placeholder">无法加载历史会话：${escapeHtml(e.message)}</span>`;
  }
}

function renderSessionPicker() {
  const listEl = $("reh-session-list");
  listEl.innerHTML = "";
  if (!rehState.sessions.length) {
    listEl.innerHTML = `<span class="placeholder">暂无历史会话。先在左侧运行一次链验证，新会话会按角色保存可重放证书。</span>`;
    return;
  }
  rehState.sessions.forEach((s) => {
    const row = document.createElement("label");
    row.className = "reh-session" + (s.replayable ? "" : " disabled");
    const when = (s.created_at || "").slice(0, 19).replace("T", " ");
    row.innerHTML =
      `<input type="checkbox" class="reh-check" value="${s.id}"${s.replayable ? "" : " disabled"}>` +
      `<span class="sid">#${s.id}</span>` +
      `<span class="smeta">${when} · dns=${s.dns_name || "-"} · purpose=${s.purpose || "-"} · ` +
      `叶${s.leaf_count}/中${s.intermediate_count}/锚${s.anchor_count}</span>` +
      (s.replayable
        ? `<span class="reh-tag yes">可预演</span>`
        : `<span class="reh-tag no" title="旧版会话未按角色保存原始证书">不可预演</span>`);
    listEl.appendChild(row);
  });
}

$("reh-toggle-all").addEventListener("change", (e) => {
  document.querySelectorAll(".reh-check").forEach((cb) => { cb.checked = e.target.checked; });
});

async function runRehearse() {
  const ids = Array.from(document.querySelectorAll(".reh-check:checked")).map((cb) => +cb.value);
  const errEl = $("rehearse-error");
  errEl.textContent = "";
  if (!ids.length) { errEl.textContent = "请至少勾选一条可预演会话"; return; }

  const fd = new FormData();
  rehState.anchorFiles.forEach((f) => fd.append("anchors", f));
  ids.forEach((id) => fd.append("session_ids", String(id)));

  const btn = $("btn-run-rehearse");
  btn.disabled = true;
  btn.textContent = "重放中…";
  try {
    const resp = await fetch("/api/rehearse", { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "预演请求失败");
    renderRehearseResults(data);
  } catch (e) {
    errEl.textContent = "错误：" + e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "用替代锚重放所选会话";
  }
}

function shortFp(fp) { return fp ? fp.slice(0, 16) + "…" : "?"; }

function anchorList(items, cls) {
  if (!items || !items.length) return `<div class="none">（无）</div>`;
  return items.map((a) =>
    `<span class="reh-fp ${cls}">${a.fingerprint.slice(0, 20)}…` +
    `<br><span class="asubj">${escapeHtml(a.subject || "")}</span></span>`).join("");
}

function sideBlock(side, view) {
  if (!view) return `<div class="reh-side ${side}"><h5>${side === "base" ? "基线" : "替代"}</h5>
    <div class="none">该叶证书在此侧重放结果中缺失</div></div>`;
  const stateHtml = view.valid
    ? `<span class="state valid">有效</span>`
    : `<span class="state invalid">无效</span>${view.first_failure_rule
        ? ` <span class="lfp">首败 ${view.first_failure_rule}</span>` : ""}`;
  const path = view.selected_subjects && view.selected_subjects.length
    ? view.selected_subjects.map((s) => escapeHtml(s.split(",")[0])).join(" → ")
    : null;
  return `<div class="reh-side ${side}">
      <h5>${side === "base" ? "基线（原锚重放）" : "替代（替代锚重放）"}</h5>
      <div>${stateHtml}</div>
      ${path
        ? `<div class="pathline">选中路径：<br>${path}<br><span class="lfp">[${view.selected_path.map(shortFp).join(" → ")}]</span></div>`
        : `<div class="none">无选中链（无完全有效候选）</div>`}
    </div>`;
}

const OUTCOME_LABELS = {
  validity_flip: ["有效性翻转", "flip"],
  chain_changed: ["选中链变化", "chg"],
  unchanged: ["无变化", "same"],
  baseline_drift: ["基线漂移", "drift"],
};

function renderRehearseResults(data) {
  const box = $("reh-results");
  box.innerHTML = "";
  const sm = data.summary || {};
  const summary = document.createElement("div");
  summary.className = "summary-bar";
  summary.innerHTML =
    `共 <b>${sm.sessions ?? 0}</b> 条会话 · 替代锚 <b>${sm.replacement_anchor_count ?? 0}</b> 本 · ` +
    `有效差异 <b style="color:var(--sel)">${sm.changed ?? 0}</b> · 无变化 <b style="color:var(--ok)">${sm.unchanged ?? 0}</b> · ` +
    `基线漂移 <b style="color:var(--warn)">${sm.baseline_drift ?? 0}</b> · ` +
    `不可预演 <b style="color:var(--bad)">${sm.not_replayable ?? 0}</b>` +
    (sm.errors ? ` · 错误 <b style="color:var(--bad)">${sm.errors}</b>` : "");
  box.appendChild(summary);

  data.sessions.forEach((s) => {
    const card = document.createElement("div");
    let cls = "reh-card";
    if (s.status === "error") cls += " errorcard";
    else if (s.outcome === "changed") cls += " changed";
    else if (s.outcome === "unchanged") cls += " unchanged";
    else if (s.outcome === "baseline_drift") cls += " drift";
    else if (s.outcome === "not_replayable") cls += " notreplayable";
    card.className = cls;

    if (s.status === "error") {
      card.innerHTML = `<div class="reh-card-head"><span class="sid">#${s.session_id}</span>
        <span class="reh-badge norep">${escapeHtml(s.outcome || "错误")}</span></div>
        <p class="reh-sub">${escapeHtml(s.error || "重放失败")}</p>`;
      box.appendChild(card);
      return;
    }
    if (s.outcome === "not_replayable") {
      card.innerHTML = `<div class="reh-card-head"><span class="sid">#${s.session_id}</span>
        <span class="reh-badge norep">不可预演</span></div>
        <p class="reh-sub">${escapeHtml(s.reason || "")}</p>`;
      box.appendChild(card);
      return;
    }

    const head = document.createElement("div");
    head.className = "reh-card-head";
    const p = s.params || {};
    head.innerHTML =
      `<span class="sid">#${s.session_id}</span>` +
      `<span class="reh-badge ${s.outcome === "unchanged" ? "same" : s.outcome === "baseline_drift" ? "drift" : "chg"}">` +
      `${s.outcome === "changed" ? "存在差异" : s.outcome === "baseline_drift" ? "基线漂移" : "无变化"}</span>` +
      `<span class="smeta" style="color:var(--muted);font-size:11.5px">` +
      `校验时间 ${p.verify_time ? p.verify_time.slice(0, 19) : "-"} · dns=${p.dns_name || "-"} · purpose=${p.purpose || "-"}</span>`;
    card.appendChild(head);

    const diff = document.createElement("div");
    diff.className = "reh-anchor-diff";
    diff.innerHTML =
      `<div class="col"><h4 class="added">新增锚（+${(s.anchors_added || []).length}）</h4>${anchorList(s.anchors_added, "added")}</div>` +
      `<div class="col"><h4 class="removed">移除锚（−${(s.anchors_removed || []).length}）</h4>${anchorList(s.anchors_removed, "removed")}</div>`;
    card.appendChild(diff);

    (s.leaves || []).forEach((lf) => {
      const leafDiv = document.createElement("div");
      leafDiv.className = "reh-leaf";
      const [label, badgeCls] = OUTCOME_LABELS[lf.outcome] || [lf.outcome, "drift"];
      leafDiv.innerHTML =
        `<div class="reh-leaf-head"><span class="reh-badge ${badgeCls}">${label}</span>` +
        `<span>${escapeHtml(lf.leaf_subject || "")}</span>` +
        `<span class="lfp">叶指纹 ${shortFp(lf.leaf_fp)}</span></div>`;
      if (lf.outcome === "baseline_drift") {
        leafDiv.insertAdjacentHTML("beforeend",
          `<div class="reh-drift-note">基线重放结论与存档报告不一致（叶指纹集合、有效性或选中链不同），` +
          `差异标记为<b>基线漂移</b>，不归因于本次锚替换。</div>`);
      }
      const sides = document.createElement("div");
      sides.className = "reh-sides";
      sides.innerHTML = sideBlock("base", lf.baseline) + sideBlock("alt", lf.alternative);
      leafDiv.appendChild(sides);
      card.appendChild(leafDiv);
    });

    box.appendChild(card);
  });
}
