"""
LLMGuard API Server
-------------------
Wraps the existing LLMGuard security engine and exposes REST endpoints
for the frontend SPA. Scans run in a background thread; the frontend
polls /api/scan/status and /api/scan/results.

Run:  python server.py
Port: 8001  (TechMart target runs on 8000)
"""

import sys
import os
import threading
import uuid
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Resolve imports from the same directory ──────────────────────────────────
_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _DIR)

from attack_generator import generate_attacks
from target_client import send_attack, get_target_mode, set_target_mode
from evaluator import evaluate_response_details


# ── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(title="LLMGuard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── In-memory scan state (thread-safe via lock) ──────────────────────────────
_lock = threading.Lock()
_state: dict = {
    "status": "idle",
    "scan_id": None,
    "started_at": None,
    "completed_at": None,
    "mode": None,
    "total": 0,
    "completed": 0,
    "current_attack": None,
    "results": [],
    "summary": {"SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
    "category_stats": {},
    "vulnerable_cases": [],
}


# ── Pydantic request models ──────────────────────────────────────────────────
class ModeRequest(BaseModel):
    mode: str


class ScanRequest(BaseModel):
    mode: Optional[str] = None
    categories: Optional[List[str]] = None


# ── Background scan worker ───────────────────────────────────────────────────
def _run_scan(mode: Optional[str], categories: Optional[List[str]]):
    """Execute all attacks sequentially in a background thread."""
    global _state

    try:
        if mode:
            set_target_mode(mode)

        active_mode = get_target_mode()
        attacks = generate_attacks()

        if categories:
            attacks = [a for a in attacks if a["category"] in categories]

        with _lock:
            _state.update({
                "status": "running",
                "mode": active_mode,
                "total": len(attacks),
                "completed": 0,
                "current_attack": None,
                "results": [],
                "summary": {"SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
                "category_stats": {},
                "vulnerable_cases": [],
            })
            for attack in attacks:
                cat = attack["category"]
                if cat not in _state["category_stats"]:
                    _state["category_stats"][cat] = {
                        "total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0
                    }

        for attack in attacks:
            cat = attack["category"]

            with _lock:
                _state["category_stats"][cat]["total"] += 1
                _state["current_attack"] = {
                    "id": attack["id"],
                    "name": attack["name"],
                    "category": cat,
                }

            try:
                response, latency_ms = send_attack(attack["prompt"])
                verdict, detail = evaluate_response_details(response)
            except Exception as exc:
                response = f"[ERROR] Exception during attack: {exc}"
                latency_ms = None
                verdict = "TARGET_ERROR"
                detail = str(exc)

            result = {
                "id": attack["id"],
                "category": cat,
                "name": attack["name"],
                "objective": attack["objective"],
                "prompt": attack["prompt"],
                "response": response,
                "verdict": verdict,
                "detail": detail,
                "latency": f"{latency_ms}ms" if latency_ms is not None else None,
                "timestamp": datetime.now().isoformat(),
            }

            with _lock:
                _state["results"].append(result)
                _state["summary"][verdict] += 1
                _state["category_stats"][cat][verdict] += 1
                _state["completed"] += 1
                if verdict == "VULNERABLE":
                    _state["vulnerable_cases"].append({
                        "id": attack["id"],
                        "category": cat,
                        "name": attack["name"],
                        "detail": detail,
                    })

        with _lock:
            _state["status"] = "completed"
            _state["completed_at"] = datetime.now().isoformat()
            _state["current_attack"] = None

    except Exception as exc:
        with _lock:
            _state["status"] = "error"
            _state["completed_at"] = datetime.now().isoformat()
            _state["current_attack"] = None


# ── API endpoints ────────────────────────────────────────────────────────────

@app.get("/api/status")
def api_status():
    """Overall health check: LLMGuard + TechMart target reachability."""
    try:
        mode = get_target_mode()
        target_online = (mode != "UNKNOWN")
    except Exception:
        target_online = False
        mode = "UNKNOWN"

    with _lock:
        scan_status = _state["status"]

    return {
        "llmguard": "running",
        "target_online": target_online,
        "target_mode": mode,
        "scan_status": scan_status,
    }


@app.get("/api/target/mode")
def api_get_target_mode():
    """Return current TechMart target mode (SECURE / VULNERABLE)."""
    try:
        mode = get_target_mode()
        return {"mode": mode, "online": mode != "UNKNOWN"}
    except Exception:
        return {"mode": "UNKNOWN", "online": False}


@app.post("/api/target/mode")
def api_set_target_mode(request: ModeRequest):
    """Switch TechMart target between SECURE and VULNERABLE."""
    mode_upper = request.mode.strip().upper()
    if mode_upper not in ("SECURE", "VULNERABLE"):
        raise HTTPException(status_code=400, detail="Mode must be SECURE or VULNERABLE")
    result = set_target_mode(mode_upper)
    return {"mode": result or mode_upper}


@app.get("/api/attacks")
def api_get_attacks():
    """Return all attack definitions from attack_generator.py."""
    attacks = generate_attacks()
    return {"attacks": attacks, "total": len(attacks)}


@app.post("/api/scan/start")
def api_start_scan(request: ScanRequest):
    """Start a security scan in a background thread."""
    with _lock:
        if _state["status"] == "running":
            raise HTTPException(status_code=409, detail="A scan is already running")
        scan_id = str(uuid.uuid4())[:8].upper()
        _state["scan_id"] = scan_id
        _state["started_at"] = datetime.now().isoformat()
        _state["completed_at"] = None

    t = threading.Thread(
        target=_run_scan,
        args=(request.mode, request.categories),
        daemon=True,
    )
    t.start()
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scan/status")
def api_scan_status():
    """Lightweight polling: progress + current attack + summary counts."""
    with _lock:
        return {
            "status": _state["status"],
            "scan_id": _state["scan_id"],
            "total": _state["total"],
            "completed": _state["completed"],
            "mode": _state["mode"],
            "started_at": _state["started_at"],
            "completed_at": _state["completed_at"],
            "current_attack": _state.get("current_attack"),
            "summary": dict(_state["summary"]),
        }


@app.get("/api/scan/results")
def api_scan_results():
    """Full scan results: all test records, category stats, and vulnerability cases."""
    with _lock:
        return {
            "status": _state["status"],
            "scan_id": _state["scan_id"],
            "mode": _state["mode"],
            "started_at": _state["started_at"],
            "completed_at": _state["completed_at"],
            "total": _state["total"],
            "results": list(_state["results"]),
            "summary": dict(_state["summary"]),
            "category_stats": {k: dict(v) for k, v in _state["category_stats"].items()},
            "vulnerable_cases": list(_state["vulnerable_cases"]),
        }


# ── Static file serving ───────────────────────────────────────────────────────
_static_dir = os.path.join(_DIR, "static")
if os.path.isdir(_static_dir):
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("=" * 56)
    print("  LLMGuard API Server  —  http://127.0.0.1:8001")
    print("  TechMart target must be running on port 8000")
    print("=" * 56)
    uvicorn.run(app, host="127.0.0.1", port=8001, reload=False)
