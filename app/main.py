"""FastAPI 入口：证书上传、离线链核验、历史会话、内置样例、静态页面。"""
from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import cert_core as cc
from . import db as database
from . import rehearse as rh
from .service import AnalysisError, analyze

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("LAB_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "lab.db"
SAMPLES_DIR = DATA_DIR / "samples"
# 镜像构建时生成的只读内置样例，作为种子复制到可写数据目录
BUNDLED_SAMPLES = BASE_DIR / "data_bundled" / "samples"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="X.509 证书链验证实验台",
    description="本地离线的证书链枚举与逐链规则核验实验平台（不访问外网）",
    version="1.0.0",
)


@app.on_event("startup")
def _startup():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    database.init_db(DB_PATH)
    # 首次启动（如 Docker 命名卷为空）时把内置样例播种到数据目录
    if BUNDLED_SAMPLES.exists() and not SAMPLES_DIR.exists():
        shutil.copytree(BUNDLED_SAMPLES, SAMPLES_DIR)
    elif not SAMPLES_DIR.exists() and (BASE_DIR / "data" / "samples").exists():
        shutil.copytree(BASE_DIR / "data" / "samples", SAMPLES_DIR)


# ---------------------------------------------------------------- 健康检查
@app.get("/api/health")
def health():
    return {"status": "ok", "offline": True}


# ---------------------------------------------------------------- 样例
@app.get("/api/samples")
def list_samples():
    if not SAMPLES_DIR.exists():
        return {"samples": []}
    out = []
    for scenario in sorted(p for p in SAMPLES_DIR.iterdir() if p.is_dir()):
        meta = {"id": scenario.name, "files": {}}
        readme = scenario / "README.md"
        meta["readme"] = readme.read_text(encoding="utf-8") if readme.exists() else ""
        for role in ("leaf", "intermediates", "anchors"):
            d = scenario / role
            files = []
            if d.exists():
                for f in sorted(d.iterdir()):
                    if f.is_file():
                        files.append(f.name)
            meta["files"][role] = files
        out.append(meta)
    return {"samples": out}


@app.get("/api/samples/{scenario}/{role}/{filename}")
def get_sample_file(scenario: str, role: str, filename: str):
    if role not in ("leaf", "intermediates", "anchors") or "/" in filename:
        raise HTTPException(400, "非法路径")
    path = (SAMPLES_DIR / scenario / role / filename).resolve()
    if not str(path).startswith(str(SAMPLES_DIR.resolve())) or not path.is_file():
        raise HTTPException(404, "文件不存在")
    return FileResponse(path, media_type="application/x-pem-file", filename=filename)


# ---------------------------------------------------------------- 分析
async def _read_certs(files: list[UploadFile], role: str) -> list:
    certs = []
    errors = []
    for f in files or []:
        raw = await f.read()
        try:
            parsed = cc.load_certificates(raw)
        except ValueError as exc:
            errors.append(f"[{role}] {f.filename}: {exc}")
            continue
        for cert in parsed:
            certs.append(cert)
    if errors:
        raise HTTPException(400, "；".join(errors))
    return certs


@app.post("/api/analyze")
async def api_analyze(
    leaves: list[UploadFile] = File(default=[]),
    intermediates: list[UploadFile] = File(default=[]),
    anchors: list[UploadFile] = File(default=[]),
    verify_time: str = Form(default=""),
    dns_name: str = Form(default=""),
    purpose: str = Form(default=""),
):
    leaf_certs = await _read_certs(leaves, "leaf")
    inter_certs = await _read_certs(intermediates, "intermediate")
    anchor_certs = await _read_certs(anchors, "anchor")

    if not leaf_certs:
        raise HTTPException(400, "请至少上传一本叶证书（PEM/DER）")
    # 允许零信任锚：用于演示无锚时全部候选链终止为 UNTRUSTED_ROOT / LOOP

    if verify_time.strip():
        try:
            vt = datetime.fromisoformat(verify_time.strip().replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(400, f"校验时间格式无法解析: {verify_time!r}，请使用 ISO 8601")
    else:
        vt = datetime.now(timezone.utc)

    purpose = purpose.strip() or ""
    dns_name = dns_name.strip() or ""

    try:
        result = analyze(leaf_certs, inter_certs, anchor_certs,
                         verify_time=vt, dns_name=dns_name or None,
                         purpose_key=purpose or None)
    except AnalysisError as exc:
        raise HTTPException(400, str(exc))

    session_id = database.save_session(
        DB_PATH,
        verify_time=result["params"]["verify_time"],
        dns_name=dns_name or None,
        purpose=purpose or None,
        leaf_count=len(leaf_certs),
        intermediate_count=len(inter_certs),
        anchor_count=len(anchor_certs),
        result=result,
        # 新会话按角色持久化可重放证书（PEM），供信任锚替换预演无损重放
        certs={"leaf": leaf_certs, "intermediate": inter_certs, "anchor": anchor_certs},
    )
    return JSONResponse({"session_id": session_id, "result": result})


# ---------------------------------------------------------------- 历史
@app.get("/api/sessions")
def api_sessions():
    return {"sessions": database.list_sessions(DB_PATH)}


@app.get("/api/sessions/{session_id}")
def api_session(session_id: int):
    row = database.get_session(DB_PATH, session_id)
    if row is None:
        raise HTTPException(404, "会话不存在")
    return row


# ---------------------------------------------------------------- 信任锚替换预演
@app.post("/api/rehearse")
async def api_rehearse(
    anchors: list[UploadFile] = File(default=[]),
    session_ids: list[int] = Form(default=[]),
):
    """选择多条历史会话 + 上传一组替代锚，重放基线与替代方案并按叶指纹对齐差异。

    只读操作：不新增会话、不改写任何已存档报告。缺少原始证书的旧会话
    在结果中标记为 not_replayable；基线重放与存档不一致时标记 baseline_drift。
    """
    if not session_ids:
        raise HTTPException(400, "请至少选择一条历史会话")
    replacement = await _read_certs(anchors, "anchor")
    # 允许替代锚为空（用于预演「移除全部锚」）

    report = rh.rehearse(
        lambda sid: database.get_session(DB_PATH, sid),
        lambda sid: database.get_session_certs(DB_PATH, sid),
        session_ids,
        replacement,
    )
    return JSONResponse(report)


# ---------------------------------------------------------------- 前端
@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
