# X.509 证书链验证实验台

一个**完全本地、离线**的 X.509 证书链教学/实验平台。上传叶证书、中间证书与本地信任锚，
指定校验时间、DNS 名称与密钥用途，系统会：

1. 在存在**交叉签发、同名主体（同名不同钥）、签发环路**的证书集合中，枚举**无重复**的候选链；
2. 对每条候选链按固定顺序逐节点核验 **签名、有效期、Basic Constraints、Key Usage、
   pathLenConstraint、Name Constraints、EKU、主机名**；
3. 记录每条被淘汰路径的**首个失败节点、违反规则、规范出处与结构化证据**；
4. 按**稳定规则**（有效 → 链最短 → 各节点指纹字典序最先）选出一条有效链；
5. 页面用 Canvas 绘制证书关系图（节点角色、签名失败边、同名虚框、选中链高亮、失败节点红圈）；
6. **信任锚替换预演**：勾选多条历史会话并上传一组替代锚，按每次实验保存的叶证书、
   中间证书、原锚与校验时间/DNS/用途重放「基线」与「替代方案」，按叶证书指纹对齐报告
   有效性翻转、选中链变化或无变化，并列两侧选中路径与新增/移除锚指纹。

> **不做吊销检查，不访问外网**：没有 CRL、OCSP、AIA 抓取，也不加载系统信任库；
> 信任仅来自您本次上传的锚证书。Docker Compose 中还给出了 `network_mode: "none"`
> 的强制断网开关。

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.11 · FastAPI · uvicorn |
| 密码学 | `cryptography`（RSA / RSA-PSS / ECDSA / Ed25519 / Ed448 / DSA 验签） |
| 存储 | SQLite（标准库 `sqlite3`，WAL 模式，保存历史会话、按角色持久化的上传证书与完整结果） |
| 前端 | 原生 HTML / CSS / JavaScript + Canvas，**零第三方 JS、零 CDN** |
| 部署 | Dockerfile + Docker Compose 一键启动 |

## 一键启动（Docker Compose）

```bash
docker compose up --build
```

启动后用浏览器访问：

- **实验台页面**：<http://localhost:8000/>
- OpenAPI 文档：<http://localhost:8000/docs>
- 健康检查：<http://localhost:8000/api/health>

历史会话通过 `/api/sessions` 与 `/api/sessions/{id}` 查看（新会话带 `replayable=true`，
升级前的旧会话为 `false` 且在预演中标为「不可预演」）；SQLite 数据库位于
Docker 卷 `lab-data`（容器内 `/app/data/lab.db`）。

> 想硬性保证容器无任何出站流量：编辑 `docker-compose.yml`，取消 `network_mode: "none"`
> 一行的注释即可（此时仅能通过本机访问映射端口）。

## 本地直接运行（不用 Docker）

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/generate_samples.py          # 生成内置样例证书（离线）
.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

访问 <http://localhost:8000/>。

运行测试：

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

## 使用方式

1. 在左侧分别上传：
   - **叶证书**（一本或多本；PEM 可含多本证书，DER 单本也可）；
   - **中间证书**（把交叉签发、同名主体的候选 CA 全部放进来）；
   - **本地信任锚**（自签名根，或作为信任点的中间 CA —— 支持锚定中间 CA）。
2. 填写校验时间（留空=当前 UTC）、DNS 名称与用途（EKU）。
3. 点击 **开始链验证**。
4. 中间看关系图，右侧查看每条候选链；点击任意节点可查看证书 JSON 详情。
5. 也可以直接点击左下的**内置样例**卡片自动装载材料与建议参数。

## 信任锚替换预演（Trust-Anchor Replacement Rehearsal）

用于回答「**如果这批会话当时信任的是另一组根，结论会怎样变？**」，并且**不污染历史**：

- **入口**：实验台首页左侧第 4 区「**信任锚替换预演**」→ 上传一组**替代锚**
  （不上传任何替代锚即预演「移除全部信任锚」）→ 点击「**选择历史会话并预演**」，
  在弹层中勾选多条历史会话（支持「全选可预演会话」）→「**用替代锚重放所选会话**」。
- **重放方式**：对每条选中会话，用其保存的**叶证书、中间证书、原锚**以及当时的
  **校验时间、DNS 名称、用途（EKU）** 各跑两次核验——基线（原锚）与替代方案（替代锚），
  然后按**叶证书 SHA-256 指纹对齐**两侧结论。
- **差异结果**（按每本叶证书给出）：
  - **有效性翻转**：基线有效 ↔ 替代无效（或反之），并给出替代侧首败规则；
  - **选中链变化**：两侧有效性相同但稳定选中的路径不同（典型：交叉签发下换锚改走另一根）；
  - **无变化**：有效性与选中链指纹序列完全一致。
  - 同时列出**基线 / 替代两侧的选中路径**（主体序列 + 指纹），以及
    **新增锚**（替代侧有、基线无）与**移除锚**（基线有、替代侧无）的 **SHA-256 指纹**。
- **安全语义**：
  - 预演是**只读**操作：**不新增会话、不改写任何已存档报告**，结果仅在弹层中即时展示；
  - **新会话**在分析时按角色（leaf / intermediate / anchor）持久化原始证书（PEM），
    因此可无损重放；
  - **旧会话**（升级前产生、未保存原始证书）在会话列表与预演结果中明确标为
    **「不可预演」**，不参与重放、不做猜测；
  - 若某会话的**基线重放结论与存档报告不一致**（叶指纹集合、有效性或选中链对不上），
    标记为 **「基线漂移」**：表示存档结论本身已无法由当前重放复现，该差异
    **不归因于锚替换**，以避免把环境漂移误报成换锚效果。

> 启动与访问方式不变：`docker compose up --build` 后访问 <http://localhost:8000/>，
> 预演入口就在首页左栏；API 为 `POST /api/rehearse`。

## 内置实验场景（9 个）

样例由 `scripts/generate_samples.py` 完全离线生成于 `data/samples/`：

| 场景 | 教学点 | 预期首败规则 |
|---|---|---|
| `01-standard` | 标准三级链；另附 **DER** 叶证书 | 有效 |
| `02-cross-signed` | 同一 ICA（同主体同公钥）被 RootA/RootB **交叉签发**，枚举 2 条有效链 | 有效（稳定选 1 条） |
| `03-same-name` | 伪造根与信任锚**同名不同钥（不同指纹）** | `SIGNATURE` / `UNTRUSTED_ROOT` |
| `04-loop` | 两个 CA 互相签发形成**环路**，且无锚 | `LOOP` / `UNTRUSTED_ROOT` |
| `05-expired` | 叶证书 2021 年已过期 | `VALIDITY` |
| `06-pathlen` | Root(pathLen=1) 下两层中间 CA | `PATH_LEN` |
| `07-name-constraints` | 允许 `.example.com` 但排除 `evil.example.com` | `NAME_CONSTRAINTS` |
| `08-eku` | 叶仅含 clientAuth，却请求 serverAuth | `EXTENDED_KEY_USAGE` |
| `09-hostname` | SAN 与请求主机名不匹配（含通配规则演示） | `HOSTNAME` |

## 核验规则与固定顺序

为保证「首个失败节点」可复现，每条候选链严格按以下顺序检查（叶 → 根方向），
一旦失败立即记录并终止：

1. **终止性**：候选签发者验签失败（`SIGNATURE`，见下）/ 环路（帧重复）/
   未到达信任锚（含「同名不同钥」专门证据）；
2. **VALIDITY** — `notBefore ≤ 校验时间 ≤ notAfter`（RFC 5280 §6.1.3(a)(2)）；
3. **BASIC CONSTRAINTS** — 叶证书不得 `cA=TRUE`；签发路径上的 CA 必须存在该扩展且
   `cA=TRUE`（§4.2.1.9）；
4. **KEY USAGE** — CA 必须置 `keyCertSign`；TLS 用途下叶需 `digitalSignature`
   或 `keyAgreement`（§4.2.1.3）；
5. **EXTENDED KEY USAGE** — 叶与（若存在 EKU 的）CA 都必须包含请求用途或
   `anyExtendedKeyUsage`（§4.2.1.12）；
6. **HOSTNAME** — RFC 6125：有 SAN 只看 SAN，否则回退 CN；`*` 仅允许出现在最左标签且
   不跨标签匹配（`*.a.com` 不匹配 `x.y.a.com`）；
7. **NAME CONSTRAINTS** — RFC 5280 §4.2.1.10 的 DNS 子树：`excluded` 优先于
   `permitted`；对每个 CA 下方所有证书的 DNS 标识符施加；
8. **PATH LEN** — 自签发证书不计入路径长度（§4.2.1.9 / §6.1.4(m)）；信任锚自身的
   pathLen 不用于约束其上方（锚即终点）。

**签名核验**在「建图」阶段完成：仅当主体 DN 与签发者 DN 匹配**且签名通过**（AKI/SKI
不冲突）时才建立可走边。DN 相同但无法用颁发者公钥验签的候选签发者（典型的
「同名不同钥」伪装/篡改）：

- 在图上画为**红色虚线边**，并在边证据中保留失败原因；
- 在枚举时产生一条**到断边为止的淘汰候选链**：逐链报告以 `SIGNATURE` 规则
  （RFC 5280 §6.1.3(a)）记录**首个签名失败节点**（签名无法被验证的证书）与结构化证据
  （候选签发者指纹与主体、签名算法、验签错误、AKI/SKI 比对结果）；
- 该路径**不计入有效链**；若同时存在可验签并到达信任锚的路径，仍按原稳定规则选出有效链。

### 信任判定

链在某本证书 `C` 处终止当且仅当上传的信任锚中存在 `A`，使得：

- `C.subject == A.subject`（RFC 5280 规范化名称比较：RDN 顺序敏感、RDN 内属性类型
  无序、值 casefold），**并且**
- `C` 的 SubjectPublicKeyInfo 与 `A` 完全一致。

即**同名不同钥不构成信任**（见场景 03）。

### 候选链枚举与去重

- 从每本叶证书出发，在「DN 匹配 + 签名通过」的候选签发者上做 DFS；
- 用路径指纹序列做全局去重，同一路径只输出一次；
- 检测到已在当前路径上的节点 → 输出带 `LOOP` 标记的闭合路径；
- 主体名可相连但验签失败的边 → 输出到该边为止的 `SIGNATURE` 终止候选链
  （断边不可信，不沿其继续向上枚举）；
- 走不到任何签发者 → 输出 `UNTRUSTED_ROOT` 终止路径（仍计入候选，用于展示淘汰证据）；
- 上限：最多 300 条候选链 / 单链 32 跳，防止组合爆炸（超限有明确标记）。

### 选链稳定性

在所有**完全有效**链中，先比较长度（短者优先），长度相同再逐节点比较 SHA-256 指纹的
字典序，取最先者。结果只依赖输入，与文件上传顺序无关。

## API 摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/analyze` | multipart 上传 `leaves`/`intermediates`/`anchors`（可多文件）+ `verify_time`/`dns_name`/`purpose` |
| `GET` | `/api/samples` | 内置样例列表与说明 |
| `GET` | `/api/samples/{场景}/{角色}/{文件名}` | 下载样例 PEM |
| `GET` | `/api/sessions` | 历史会话列表（含 `replayable`：是否保存了可重放证书） |
| `GET` | `/api/sessions/{id}` | 历史会话完整结果（图 + 全部候选链证据） |
| `POST` | `/api/rehearse` | 信任锚替换预演：multipart 上传替代锚 `anchors`（可空）+ 重复字段 `session_ids`；只读重放并返回两侧差异 |
| `GET` | `/api/health` | 健康检查 |

## 目录结构

```
app/
  main.py        # FastAPI 路由 / 上传解析 / 静态托管
  service.py     # 编排：建图 → 枚举 → 逐链核验 → 选链
  chain.py       # 候选图、DFS 无重复枚举、规则核验、证书摘要
  cert_core.py   # PEM/DER 解析、验签、名称规范化、DNS/名称约束匹配
  rehearse.py    # 信任锚替换预演：基线/替代只读重放、按叶指纹对齐、漂移判定
  db.py          # SQLite 会话持久化 + 按角色持久化原始证书（PEM）
static/          # index.html / style.css / app.js（原生 JS）
scripts/generate_samples.py
tests/test_engine.py
tests/test_edge_cases.py
tests/test_rehearse.py
data/samples/    # 生成的 9 个样例场景
```

## 范围说明（实验台的有意取舍）

- 不做 CRL / OCSP / OCSP-stapling / CRLite 等吊销检查（离线实验台）；
- Name Constraints 实现 DNS 子树部分（目录名/URI/IP/email 子树解析保留但不强制）；
- 不做策略 OID（Certificate Policies / policy mapping / inhibitAnyPolicy）与
  explicit-policy 处理；
- 不解析 PKCS#7 / PFX，仅接受裸 X.509 PEM/DER。
