"""
Admin-only FastAPI routes. Gated by X-Admin-Token header.
Public chatbot must never call these endpoints.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

from src.layers.attack_typer import DISPLAY_NAMES, AttackTypeDetector

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
REVIEW_QUEUE = DATA / "review_queue.jsonl"
INCOMING = DATA / "incoming"
VERSIONS = DATA / "versions"
EVALS = ROOT / "logs" / "admin_evals"
JOBS_DIR = ROOT / "logs" / "admin_jobs"
LLM_RUNTIME = ROOT / "configs" / "llm_runtime.json"
LLM_ANALYTICS = ROOT / "logs" / "llm_analytics.jsonl"

router = APIRouter(prefix="/admin", tags=["admin"])

_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()
_runtime_getter = None


def bind_runtime(getter) -> None:
    """Called from app.py so admin routes always see the live pipeline objects."""
    global _runtime_getter
    _runtime_getter = getter


def _admin_token() -> str:
    return (os.getenv("ADMIN_INTERNAL_TOKEN") or "").strip()


def require_admin(x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token")) -> None:
    expected = _admin_token()
    if not expected:
        raise HTTPException(status_code=503, detail="Admin API disabled (no ADMIN_INTERNAL_TOKEN)")
    if not x_admin_token or x_admin_token != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


def get_pipeline():
    """Return live pipeline objects from the running API process."""
    if _runtime_getter is not None:
        pipeline, loaded = _runtime_getter()
        return pipeline, bool(loaded)

    # Fallback for tests / odd import orders
    import importlib
    import sys

    mod = sys.modules.get("src.api.app")
    if mod is None or not hasattr(mod, "pipeline"):
        mod = importlib.import_module("src.api.app")
    if not hasattr(mod, "pipeline"):
        raise RuntimeError("src.api.app module has no pipeline")
    return mod.pipeline, bool(getattr(mod, "pipeline_loaded", False))


def _jsonable(obj: Any) -> Any:
    if obj is None:
        return None
    if is_dataclass(obj):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def _append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _read_jsonl(path: Path, limit: int = 500) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]


def _scenario_timeline(result) -> List[Dict[str, Any]]:
    """Ordered layer story for admin Live Lab."""
    steps: List[Dict[str, Any]] = []
    timings = result.processing_time or {}

    norm = result.normalization or {}
    steps.append({
        "id": "normalize",
        "label": "Text normalization",
        "when_ms": round((timings.get("normalize") or 0) * 1000, 2),
        "verdict": "changed" if norm.get("changed") else "unchanged",
        "detail": {
            "steps": norm.get("steps") or [],
            "normalized_preview": (result.normalized_text or "")[:240],
        },
    })

    l1 = result.layer1
    steps.append({
        "id": "layer1",
        "label": "Layer 1 — Prefilter",
        "when_ms": round((timings.get("layer1") or 0) * 1000, 2),
        "verdict": getattr(l1, "verdict", None) or getattr(l1, "action", "n/a"),
        "detail": _jsonable(l1),
    })

    l2 = result.layer2 or {}
    steps.append({
        "id": "layer2",
        "label": "Layer 2 — Classical classifiers",
        "when_ms": round((timings.get("layer2") or 0) * 1000, 2),
        "verdict": "malicious" if (l2.get("is_malicious") or l2.get("prediction")) else "benign/empty",
        "detail": l2,
    })

    l3 = result.layer3
    steps.append({
        "id": "layer3",
        "label": "Layer 3 — Ensemble",
        "when_ms": round((timings.get("layer3") or 0) * 1000, 2),
        "verdict": (
            "ambiguous" if getattr(l3, "is_ambiguous", False)
            else ("malicious" if getattr(l3, "final_classification", False) else "benign")
        ),
        "detail": _jsonable(l3),
    })

    ret = result.retrieval or {}
    steps.append({
        "id": "retrieval",
        "label": "Attack bank retrieval",
        "when_ms": round((timings.get("retrieval") or 0) * 1000, 2),
        "verdict": "hit" if ret.get("hit") else "miss",
        "detail": ret,
    })

    l2b = result.layer2b or {}
    steps.append({
        "id": "layer2b",
        "label": "Layer 2b — Semantic / transformer",
        "when_ms": round((timings.get("layer2b") or 0) * 1000, 2),
        "verdict": (
            "skipped" if not l2b.get("enabled") and not timings.get("layer2b")
            else ("malicious" if l2b.get("is_malicious") else "benign")
        ),
        "detail": l2b,
    })

    l4 = result.layer4
    steps.append({
        "id": "layer4",
        "label": "Layer 4 — Ambiguity judge",
        "when_ms": round((timings.get("layer4") or 0) * 1000, 2),
        "verdict": getattr(l4, "verdict", "skipped") if l4 else "skipped",
        "detail": _jsonable(l4),
    })

    steps.append({
        "id": "decision",
        "label": "Final decision",
        "when_ms": round((timings.get("total") or 0) * 1000, 2),
        "verdict": result.action,
        "detail": {
            "is_malicious": result.is_malicious,
            "risk_score": result.final_risk_score,
            "attack_type": result.attack_type,
            "attack_display_name": result.attack_display_name,
            "decision_source": result.decision_source,
            "severity": result.severity,
        },
    })
    return steps


class ProbeRequest(BaseModel):
    prompt: str = Field(..., min_length=1)


class LabelSaveRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    attack_type: str = Field(..., min_length=1)
    label: int = Field(1, description="1=attack, 0=benign")
    notes: str = ""
    previous_attack_type: str = "unknown"
    probe_id: Optional[str] = None


class AccuracyRunRequest(BaseModel):
    mode: str = Field("heldout", pattern="^(heldout|ablation|patterns)$")
    limit: int = Field(500, ge=50, le=10000)
    rounds: int = Field(1, ge=1, le=5)


class TrainRequest(BaseModel):
    include_review_queue: bool = True
    rebuild_splits: bool = False


class LlmUpdateRequest(BaseModel):
    model: Optional[str] = None
    api_key: Optional[str] = None
    provider: str = "openrouter"


@router.get("/ping")
async def admin_ping(x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token")):
    require_admin(x_admin_token)
    return {"ok": True, "ts": datetime.now(timezone.utc).isoformat()}


@router.get("/system")
async def admin_system(x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token")):
    require_admin(x_admin_token)
    try:
        pipeline, loaded = get_pipeline()
    except Exception as exc:
        logger.exception("admin_system get_pipeline failed")
        raise HTTPException(status_code=500, detail=f"pipeline bind failed: {exc}") from exc
    layer_cfg = (pipeline.config.get("layers") or {}) if pipeline else {}
    flags = (pipeline.config.get("feature_flags") or {}) if pipeline else {}
    train_file = DATA / "processed" / "train.jsonl"
    review_n = len(_read_jsonl(REVIEW_QUEUE, limit=100000))
    train_cfg = (pipeline.config.get("training") or {}) if pipeline else {}
    return {
        "pipeline_loaded": loaded,
        "version": ((pipeline.config.get("system") or {}).get("version") if pipeline else None),
        "feature_flags": flags,
        "training": {
            "team_sample_weight": float(train_cfg.get("team_sample_weight", 50)),
            "team_sources": train_cfg.get("team_sources") or ["review_queue", "team_train", "inbox_review"],
        },
        "layers": {
            "layer2b": bool((layer_cfg.get("layer2b") or {}).get("enabled", True)),
            "layer4": bool((layer_cfg.get("layer4") or {}).get("enabled", True)),
            "retrieval": bool((layer_cfg.get("retrieval") or {}).get("enabled", True)),
        },
        "paths": {
            "train_exists": train_file.exists(),
            "review_queue_count": review_n,
            "incoming_count": len(list(INCOMING.glob("*"))) if INCOMING.exists() else 0,
            "model_dir": str(ROOT / "models" / "detector"),
        },
        "attack_types": [
            {"id": k, "name": v} for k, v in DISPLAY_NAMES.items()
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/lab/probe")
async def lab_probe(
    body: ProbeRequest,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    pipeline, loaded = get_pipeline()
    if not loaded:
        raise HTTPException(status_code=503, detail="Pipeline not loaded")

    prompt = body.prompt.strip()
    t0 = time.time()
    result = pipeline.process(prompt)

    inbox_case_id = None
    if result.is_malicious:
        try:
            from src.utils.malicious_inbox import ingest_pipeline_result
            case = ingest_pipeline_result(prompt, result, source="admin_probe")
            inbox_case_id = (case or {}).get("id")
        except Exception:
            logger.warning("inbox ingest from probe skipped", exc_info=True)

    # Layer 5 preview only — avoid a second full process_conversational (and double ingest)
    layer5_preview = {}
    try:
        l5 = pipeline.layer5.get_conversation_response(
            prompt, result.attack_type, result.final_risk_score
        )
        formatted = pipeline._format_layer5_result(
            l5, result.attack_type, result.final_risk_score
        )
        layer5_preview = {
            "type": formatted.get("type"),
            "response": formatted.get("response"),
            "suggestion": formatted.get("suggestion"),
            "status": formatted.get("status"),
        }
    except Exception:
        logger.warning("lab probe layer5 preview failed", exc_info=True)

    probe_id = str(uuid.uuid4())
    payload = {
        "probe_id": probe_id,
        "prompt": prompt,  # research mode A: full text, localhost-only admin
        "user_identity": None,  # explicit: never attach user details
        "inbox_case_id": inbox_case_id,
        "elapsed_ms": round((time.time() - t0) * 1000, 2),
        "final": {
            "is_malicious": result.is_malicious,
            "risk_score": result.final_risk_score,
            "attack_type": result.attack_type,
            "attack_display_name": result.attack_display_name,
            "action": result.action,
            "severity": result.severity,
            "decision_source": result.decision_source,
        },
        "scenario": _scenario_timeline(result),
        "explanation": result.explanation,
        "layer5_preview": layer5_preview,
        "timings": result.processing_time,
    }
    _append_jsonl(ROOT / "logs" / "admin_probes.jsonl", {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "probe_id": probe_id,
        "prompt": prompt,
        "attack_type": result.attack_type,
        "risk_score": result.final_risk_score,
        "decision_source": result.decision_source,
        "action": result.action,
        "inbox_case_id": inbox_case_id,
    })
    return payload


class InboxReviewRequest(BaseModel):
    attack_type: str = Field(..., min_length=1)
    label: int = 1
    notes: str = ""
    discard: bool = False


class InboxManualRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    attack_type: str = Field(..., min_length=1)
    label: int = 1
    notes: str = ""


@router.get("/inbox")
async def inbox_list(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
    status: str = "live",
    attack_type: str = "",
    q: str = "",
    limit: int = 200,
    offset: int = 0,
):
    require_admin(x_admin_token)
    from src.utils.malicious_inbox import archive_trained_cases, list_cases
    # Clean up any trained rows left in the inbox file from older builds
    if status == "live":
        archive_trained_cases()
    return list_cases(status=status, attack_type=attack_type, q=q, limit=limit, offset=offset)


@router.post("/inbox/manual")
async def inbox_manual(
    body: InboxManualRequest,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    from src.utils.malicious_inbox import get_case, ingest, review_case
    pipeline, loaded = get_pipeline()
    prompt = body.prompt.strip()
    scenario = []
    timings = {}
    sys_type = body.attack_type.strip()
    display = AttackTypeDetector.display_name(sys_type)
    risk = 0.9 if int(body.label) == 1 else 0.0
    if loaded and pipeline:
        try:
            result = pipeline.process(prompt)
            from src.utils.malicious_inbox import compact_scenario
            scenario = compact_scenario(result)
            timings = result.processing_time or {}
            if int(body.label) == 1:
                sys_type = body.attack_type.strip() or result.attack_type
                display = AttackTypeDetector.display_name(sys_type)
                risk = max(float(result.final_risk_score or 0), 0.75)
        except Exception:
            logger.warning("manual inbox process failed", exc_info=True)
    case = ingest(
        prompt,
        attack_type=sys_type,
        attack_display_name=display,
        risk_score=risk,
        action="BLOCK" if int(body.label) == 1 else "ALLOW",
        decision_source="admin_manual",
        scenario=scenario,
        timings=timings,
        source="manual",
        status="queued",
    )
    row = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt": prompt,
        "attack_type": body.attack_type.strip(),
        "attack_display_name": AttackTypeDetector.display_name(body.attack_type.strip()),
        "label": int(body.label),
        "notes": (body.notes or "")[:500],
        "previous_attack_type": "manual",
        "case_id": (case or {}).get("id"),
        "source": "inbox_manual",
    }
    _append_jsonl(REVIEW_QUEUE, row)
    if case and case.get("id"):
        review_case(
            case["id"],
            attack_type=body.attack_type.strip(),
            label=int(body.label),
            notes=body.notes,
            discard=False,
        )
        case = get_case(case["id"])
    return {"ok": True, "item": case}


@router.get("/inbox/{case_id}")
async def inbox_get(
    case_id: str,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    from src.utils.malicious_inbox import get_case
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/inbox/{case_id}/review")
async def inbox_review(
    case_id: str,
    body: InboxReviewRequest,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    from src.utils.malicious_inbox import review_case
    case = review_case(
        case_id,
        attack_type=body.attack_type.strip(),
        label=int(body.label),
        notes=body.notes,
        discard=body.discard,
    )
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if not body.discard:
        row = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prompt": case.get("prompt") or "",
            "attack_type": body.attack_type.strip(),
            "attack_display_name": AttackTypeDetector.display_name(body.attack_type.strip()),
            "label": int(body.label),
            "notes": (body.notes or "")[:500],
            "previous_attack_type": case.get("system_attack_type") or "unknown",
            "case_id": case_id,
            "source": "inbox_review",
        }
        _append_jsonl(REVIEW_QUEUE, row)
    return {"ok": True, "item": case}



@router.get("/labels")
async def list_labels(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
    limit: int = 200,
):
    require_admin(x_admin_token)
    return {"items": list(reversed(_read_jsonl(REVIEW_QUEUE, limit=limit)))}


@router.post("/labels")
async def save_label(
    body: LabelSaveRequest,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    atype = body.attack_type.strip()
    if atype not in DISPLAY_NAMES and atype != "benign":
        # allow custom research labels but prefer known set
        pass
    row = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt": body.prompt.strip(),
        "attack_type": atype,
        "attack_display_name": AttackTypeDetector.display_name(atype),
        "label": int(body.label),
        "notes": (body.notes or "")[:500],
        "previous_attack_type": body.previous_attack_type,
        "probe_id": body.probe_id,
        # Privacy: no user_id / conversation_id / IP
        "source": "admin_label_studio",
    }
    _append_jsonl(REVIEW_QUEUE, row)
    return {"ok": True, "item": row}


@router.post("/accuracy/run")
async def accuracy_run(
    body: AccuracyRunRequest,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    EVALS.mkdir(parents=True, exist_ok=True)
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    job_id = str(uuid.uuid4())
    out_json = EVALS / f"{body.mode}_{job_id[:8]}.json"
    out_md = EVALS / f"{body.mode}_{job_id[:8]}.md"
    log_path = JOBS_DIR / f"accuracy_{job_id[:8]}.log"

    py = ROOT / ".venv" / "Scripts" / "python.exe"
    if not py.exists():
        py = Path(os.environ.get("PYTHON", "python"))

    cmd = [
        str(py),
        str(ROOT / "scripts" / "Check_Accuracy.py"),
        "--mode", body.mode,
        "--limit", str(body.limit),
    ]
    if body.mode == "patterns":
        cmd.extend(["--rounds", str(body.rounds)])

    env = os.environ.copy()
    env["ADMIN_ACCURACY_OUT_JSON"] = str(out_json)
    env["ADMIN_ACCURACY_OUT_MD"] = str(out_md)

    def _run():
        with _jobs_lock:
            _jobs[job_id]["status"] = "running"
            _jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
        try:
            with log_path.open("w", encoding="utf-8") as logf:
                proc = subprocess.run(
                    cmd,
                    cwd=str(ROOT),
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    env=env,
                    timeout=3600,
                )
            status = "ok" if proc.returncode == 0 else "failed"
            with _jobs_lock:
                _jobs[job_id]["status"] = status
                _jobs[job_id]["exit_code"] = proc.returncode
                _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
                _jobs[job_id]["log_path"] = str(log_path)
                _jobs[job_id]["out_json"] = str(out_json) if out_json.exists() else None
        except Exception as exc:
            with _jobs_lock:
                _jobs[job_id]["status"] = "failed"
                _jobs[job_id]["error"] = str(exc)
                _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

    with _jobs_lock:
        _jobs[job_id] = {
            "id": job_id,
            "kind": "accuracy",
            "mode": body.mode,
            "limit": body.limit,
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    threading.Thread(target=_run, daemon=True).start()
    return {"job_id": job_id, "status": "queued"}


@router.get("/accuracy/jobs/{job_id}")
async def accuracy_job(
    job_id: str,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    result = dict(job)
    out = job.get("out_json")
    if out and Path(out).exists():
        try:
            result["report"] = json.loads(Path(out).read_text(encoding="utf-8"))
        except Exception:
            pass
    log_path = job.get("log_path")
    if log_path and Path(log_path).exists():
        try:
            result["log_tail"] = Path(log_path).read_text(encoding="utf-8")[-8000:]
        except Exception:
            pass
    return result


@router.get("/accuracy/reports")
async def accuracy_reports(x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token")):
    require_admin(x_admin_token)
    EVALS.mkdir(parents=True, exist_ok=True)
    files = sorted(EVALS.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:30]
    items = []
    for f in files:
        items.append({
            "name": f.name,
            "path": str(f),
            "mtime": datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).isoformat(),
            "size": f.stat().st_size,
        })
    return {"items": items}


@router.post("/datasets/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    INCOMING.mkdir(parents=True, exist_ok=True)
    name = Path(file.filename or "upload.jsonl").name
    if not name.endswith((".jsonl", ".json", ".csv", ".txt")):
        raise HTTPException(status_code=400, detail="Allowed: .jsonl .json .csv .txt")
    dest = INCOMING / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{name}"
    content = await file.read()
    dest.write_bytes(content)

    preview = {"lines": 0, "sample_keys": [], "samples": []}
    try:
        text = content.decode("utf-8", errors="replace")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        preview["lines"] = len(lines)
        for ln in lines[:3]:
            if ln.startswith("{"):
                obj = json.loads(ln)
                preview["sample_keys"] = list(obj.keys())
                preview["samples"].append({
                    "text": str(obj.get("text") or obj.get("payload") or "")[:120],
                    "label": obj.get("label"),
                    "attack_type": obj.get("attack_type") or obj.get("categories"),
                })
    except Exception as exc:
        preview["parse_warning"] = str(exc)

    return {"ok": True, "path": str(dest), "preview": preview}


@router.post("/datasets/accept")
async def accept_incoming(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    """Copy incoming files into data/raw for processing."""
    require_admin(x_admin_token)
    raw = DATA / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    INCOMING.mkdir(parents=True, exist_ok=True)
    moved = []
    for f in INCOMING.iterdir():
        if f.is_file():
            dest = raw / f.name
            shutil.copy2(f, dest)
            moved.append(str(dest))
    return {"ok": True, "moved": moved}


@router.post("/datasets/train")
async def train_model(
    body: TrainRequest,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    job_id = str(uuid.uuid4())
    log_path = JOBS_DIR / f"train_{job_id[:8]}.log"

    py = ROOT / ".venv" / "Scripts" / "python.exe"
    if not py.exists():
        py = Path("python")

    def _merge_review_into_attack_bank() -> int:
        if not body.include_review_queue:
            return 0
        bank_path = DATA / "attack_bank.json"
        items = _read_jsonl(REVIEW_QUEUE, limit=100000)
        if not items:
            return 0
        from src.utils.malicious_inbox import fingerprint
        bank: List[Dict[str, Any]] = []
        if bank_path.exists():
            try:
                raw = json.loads(bank_path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    bank = raw
            except Exception:
                bank = []
        seen: Dict[str, int] = {}
        for i, row in enumerate(bank):
            fp = fingerprint(str(row.get("text") or ""))
            if fp:
                seen[fp] = i
        n = 0
        for it in items:
            if int(it.get("label", 1)) != 1:
                continue
            text = (it.get("prompt") or it.get("text") or "").strip()
            if not text:
                continue
            atype = it.get("attack_type") or "unknown"
            fp = fingerprint(text)
            entry = {"text": text, "attack_type": atype, "source": "team_train"}
            if fp in seen:
                bank[seen[fp]] = entry
                n += 1
            else:
                bank.append(entry)
                seen[fp] = len(bank) - 1
                n += 1
        if n:
            bank_path.parent.mkdir(parents=True, exist_ok=True)
            bank_path.write_text(json.dumps(bank, ensure_ascii=False, indent=2), encoding="utf-8")
        return n

    def _merge_review_into_train():
        if not body.include_review_queue:
            return 0
        processed = DATA / "processed"
        processed.mkdir(parents=True, exist_ok=True)
        train_file = processed / "train.jsonl"
        items = _read_jsonl(REVIEW_QUEUE, limit=100000)
        if not items:
            return 0
        n = 0
        with train_file.open("a", encoding="utf-8") as fh:
            for it in items:
                row = {
                    "text": it.get("prompt") or it.get("text") or "",
                    "label": int(it.get("label", 1)),
                    "attack_type": it.get("attack_type") or "unknown",
                    "source": (it.get("source") or "review_queue").strip(),
                    "id": it.get("id"),
                }
                if not row["text"]:
                    continue
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                n += 1
        return n

    def _run():
        with _jobs_lock:
            _jobs[job_id]["status"] = "running"
            _jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
        try:
            merged = _merge_review_into_train()
            bank_added = _merge_review_into_attack_bank()
            override_n = 0
            if body.include_review_queue:
                try:
                    from src.utils.team_overrides import apply_review_items
                    override_n = apply_review_items(_read_jsonl(REVIEW_QUEUE, limit=100000))
                except Exception:
                    logger.warning("team overrides apply failed", exc_info=True)
            with _jobs_lock:
                _jobs[job_id]["merged_review"] = merged
                _jobs[job_id]["attack_bank_added"] = bank_added
                _jobs[job_id]["team_overrides"] = override_n
                try:
                    from src.utils.helpers import load_config
                    tcfg = (load_config(ROOT / "configs" / "config.yaml") or {}).get("training") or {}
                    _jobs[job_id]["team_sample_weight"] = float(tcfg.get("team_sample_weight", 50))
                except Exception:
                    _jobs[job_id]["team_sample_weight"] = 50
            with log_path.open("w", encoding="utf-8") as logf:
                steps = []
                if body.rebuild_splits:
                    steps.append(["--step", "process"])
                steps.append(["--step", "train"])
                code = 0
                for args in steps:
                    proc = subprocess.run(
                        [str(py), str(ROOT / "main.py"), *args],
                        cwd=str(ROOT),
                        stdout=logf,
                        stderr=subprocess.STDOUT,
                        timeout=7200,
                    )
                    code = proc.returncode
                    if code != 0:
                        break
            with _jobs_lock:
                _jobs[job_id]["status"] = "ok" if code == 0 else "failed"
                _jobs[job_id]["exit_code"] = code
                _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
                _jobs[job_id]["log_path"] = str(log_path)
            if code == 0 and body.include_review_queue:
                try:
                    from src.utils.malicious_inbox import mark_queued_trained
                    marked = mark_queued_trained()
                    with _jobs_lock:
                        _jobs[job_id]["inbox_marked_trained"] = marked
                except Exception:
                    logger.warning("inbox trained-mark failed", exc_info=True)
                try:
                    # Archive consumed queue so the next train does not re-merge duplicates
                    if REVIEW_QUEUE.exists() and REVIEW_QUEUE.stat().st_size > 0:
                        archive = DATA / "versions" / f"review_queue_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
                        archive.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(REVIEW_QUEUE), str(archive))
                        with _jobs_lock:
                            _jobs[job_id]["review_queue_archived"] = str(archive)
                except Exception:
                    logger.warning("review queue archive failed", exc_info=True)
            if code == 0:
                # Hot-reload Layer 2 + attack bank into the running API
                try:
                    pipeline, loaded = get_pipeline()
                    reloaded = bool(loaded and pipeline and pipeline.load_models())
                    bank_reloaded = False
                    if loaded and pipeline and getattr(pipeline, "retriever", None):
                        try:
                            pipeline.retriever._build()
                            bank_reloaded = True
                        except Exception:
                            logger.warning("attack bank reload failed", exc_info=True)
                    if loaded and pipeline:
                        try:
                            pipeline._reload_team_overrides()
                        except Exception:
                            logger.warning("team overrides reload failed", exc_info=True)
                    with _jobs_lock:
                        _jobs[job_id]["model_reloaded"] = reloaded
                        _jobs[job_id]["attack_bank_reloaded"] = bank_reloaded
                    if reloaded:
                        logger.info("Live model reloaded after train job %s", job_id[:8])
                    else:
                        logger.warning("Train ok but model reload failed for job %s", job_id[:8])
                except Exception:
                    logger.warning("model hot-reload failed", exc_info=True)
                    with _jobs_lock:
                        _jobs[job_id]["model_reloaded"] = False
        except Exception as exc:
            with _jobs_lock:
                _jobs[job_id]["status"] = "failed"
                _jobs[job_id]["error"] = str(exc)
                _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

    with _jobs_lock:
        _jobs[job_id] = {
            "id": job_id,
            "kind": "train",
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    threading.Thread(target=_run, daemon=True).start()
    return {"job_id": job_id, "status": "queued"}


@router.get("/jobs/{job_id}")
async def get_job(
    job_id: str,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    result = dict(job)
    log_path = job.get("log_path")
    if log_path and Path(log_path).exists():
        try:
            result["log_tail"] = Path(log_path).read_text(encoding="utf-8")[-8000:]
        except Exception:
            pass
    return result


def _mask_key(key: str) -> str:
    key = key or ""
    if len(key) < 8:
        return "••••" if key else ""
    return key[:4] + "••••" + key[-4:]


@router.get("/llm")
async def get_llm(x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token")):
    require_admin(x_admin_token)
    cfg = {
        "provider": "openrouter",
        "model": os.getenv("OPENROUTER_MODEL") or "openai/gpt-4o-mini",
        "api_key_set": bool(os.getenv("OPENROUTER_API_KEY")),
        "api_key_masked": _mask_key(os.getenv("OPENROUTER_API_KEY") or ""),
    }
    if LLM_RUNTIME.exists():
        try:
            disk = json.loads(LLM_RUNTIME.read_text(encoding="utf-8"))
            cfg["provider"] = disk.get("provider") or cfg["provider"]
            cfg["model"] = disk.get("model") or cfg["model"]
            if disk.get("api_key"):
                cfg["api_key_set"] = True
                cfg["api_key_masked"] = _mask_key(disk["api_key"])
        except Exception:
            pass
    analytics = _read_jsonl(LLM_ANALYTICS, limit=500)
    by_model: Dict[str, Dict[str, Any]] = {}
    for row in analytics:
        m = row.get("model") or "unknown"
        slot = by_model.setdefault(m, {
            "model": m,
            "events": 0,
            "switches": 0,
            "probes": 0,
            "errors": 0,
            "latency_sum": 0.0,
            "latency_n": 0,
        })
        slot["events"] += 1
        kind = row.get("kind")
        if kind == "switch":
            slot["switches"] += 1
        elif kind == "probe":
            slot["probes"] += 1
        elif kind == "error":
            slot["errors"] += 1
        if row.get("latency_ms") is not None:
            slot["latency_sum"] += float(row["latency_ms"])
            slot["latency_n"] += 1
    models = []
    for m, s in by_model.items():
        avg = (s["latency_sum"] / s["latency_n"]) if s["latency_n"] else None
        models.append({
            "model": m,
            "events": s["events"],
            "switches": s["switches"],
            "probes": s["probes"],
            "errors": s["errors"],
            "avg_latency_ms": round(avg, 2) if avg is not None else None,
        })
    return {
        "config": cfg,
        "presets": [
            "openai/gpt-4o-mini",
            "openai/gpt-4o",
            "anthropic/claude-3.5-sonnet",
            "meta-llama/llama-3.1-70b-instruct",
            "google/gemini-2.0-flash-exp:free",
            "mistralai/mistral-7b-instruct:free",
        ],
        "analytics": sorted(models, key=lambda x: x["events"], reverse=True),
    }


@router.post("/llm")
async def update_llm(
    body: LlmUpdateRequest,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)
    LLM_RUNTIME.parent.mkdir(parents=True, exist_ok=True)
    current = {}
    if LLM_RUNTIME.exists():
        try:
            current = json.loads(LLM_RUNTIME.read_text(encoding="utf-8"))
        except Exception:
            current = {}

    if body.model:
        current["model"] = body.model.strip()
        os.environ["OPENROUTER_MODEL"] = current["model"]
    if body.api_key is not None and body.api_key.strip():
        current["api_key"] = body.api_key.strip()
        os.environ["OPENROUTER_API_KEY"] = current["api_key"]
    current["provider"] = body.provider or current.get("provider") or "openrouter"
    current["updated_at"] = datetime.now(timezone.utc).isoformat()
    LLM_RUNTIME.write_text(json.dumps(current, indent=2), encoding="utf-8")

    # Soft-update .env model line (never echo key back)
    _patch_dotenv_model(current.get("model"), current.get("api_key") if body.api_key else None)

    _append_jsonl(LLM_ANALYTICS, {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": "switch",
        "model": current.get("model"),
        "provider": current.get("provider"),
        "key_updated": bool(body.api_key and body.api_key.strip()),
    })
    return {
        "ok": True,
        "config": {
            "provider": current.get("provider"),
            "model": current.get("model"),
            "api_key_set": bool(current.get("api_key") or os.getenv("OPENROUTER_API_KEY")),
            "api_key_masked": _mask_key(current.get("api_key") or os.getenv("OPENROUTER_API_KEY") or ""),
        },
    }


def _patch_dotenv_model(model: Optional[str], api_key: Optional[str]) -> None:
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    try:
        text = env_path.read_text(encoding="utf-8")
    except Exception:
        return
    lines = text.splitlines()
    out = []
    seen_model = False
    seen_key = False
    for line in lines:
        if model and line.startswith("OPENROUTER_MODEL="):
            out.append(f"OPENROUTER_MODEL={model}")
            seen_model = True
        elif api_key and line.startswith("OPENROUTER_API_KEY="):
            out.append(f"OPENROUTER_API_KEY={api_key}")
            seen_key = True
        else:
            out.append(line)
    if model and not seen_model:
        out.append(f"OPENROUTER_MODEL={model}")
    if api_key and not seen_key:
        out.append(f"OPENROUTER_API_KEY={api_key}")
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
