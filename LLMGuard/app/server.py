"""
LLMGuard API Server
-------------------
Wraps the LLMGuard security engine and exposes REST endpoints for:
- Multi-provider target configuration (Gemini, OpenAI, Anthropic, OpenRouter, Custom REST, TechMart)
- Secure credential management (server-side encryption, masking)
- Target connectivity testing
- Background adversarial security scans with active target routing
- Scan status, telemetry, and detailed vulnerability reporting

Run:  python server.py
Port: 8001  (TechMart target runs on 8000)
"""

import sys
import os
import json
import copy
import logging
import sqlite3
import time
import threading
import uuid
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Path, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ── Resolve imports from the same directory ──────────────────────────────────
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

_logger = logging.getLogger(__name__)

from attack_generator import generate_attacks, generate_runtime_suite, normalize_prompt_for_dedup
from evaluator import evaluate_response_details
from adapters.factory import create_adapter
import target_storage
from adapters.ssrf import validate_url_ssrf
from scan_history import scan_history_store
from scan_analytics import analytics_categories, analytics_overview, analytics_trends, compare_scans


# ── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="LLMGuard API Server",
    version="2.0.0",
    description="Multi-provider LLM Security & Adversarial Testing Engine"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── In-memory scan state (thread-safe via lock) ──────────────────────────────
_SCAN_STORAGE_FILE = os.path.join(_DIR, "data", "latest_scan.json")
_lock = threading.Lock()
_scan_stop_event = threading.Event()
_scan_finalizing = False
_state: dict = {
    "status": "idle",
    "scan_id": None,
    "started_at": None,
    "completed_at": None,
    "error": None,
    "stop_requested": False,
    "target_info": None,
    "mode": None,
    "total": 0,
    "completed": 0,
    "current_attack": None,
    "results": [],
    "summary": {"SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
    "category_stats": {},
    "generation_stats": {
        "predefined": {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
        "template": {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
        "mutation": {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
        "llm": {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
    },
    "vulnerable_cases": [],
}


def _persist_scan_state() -> None:
    """Atomically persist the latest scan without target credentials."""
    with _lock:
        scan_state = copy.deepcopy(_state)

    scan_state.pop("current_attack", None)
    target_info = scan_state.get("target_info")
    if isinstance(target_info, dict):
        target_info.pop("api_key", None)
        target_info.pop("encrypted_api_key", None)
        target_info.pop("headers", None)

    os.makedirs(os.path.dirname(_SCAN_STORAGE_FILE) or ".", exist_ok=True)
    temp_path = f"{_SCAN_STORAGE_FILE}.tmp.{os.getpid()}.{threading.get_ident()}"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(scan_state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, _SCAN_STORAGE_FILE)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def _redact_scan_secrets(value: Any, secrets: List[str]) -> Any:
    """Redact configured credentials from values that may be returned or persisted."""
    if isinstance(value, str):
        redacted = value
        for secret in secrets:
            if secret:
                redacted = redacted.replace(secret, "[REDACTED_API_KEY]")
        return redacted
    if isinstance(value, dict):
        return {key: _redact_scan_secrets(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_scan_secrets(item, secrets) for item in value]
    return value


# ── Pydantic Request Models ──────────────────────────────────────────────────
class ModeRequest(BaseModel):
    mode: str


class ScanRequest(BaseModel):
    scan_name: Optional[str] = Field(default=None, max_length=120)
    target_id: Optional[str] = None
    mode: Optional[str] = None
    categories: Optional[List[str]] = None
    include_baseline: Optional[bool] = True
    enable_runtime_generation: Optional[bool] = True
    enable_templates: Optional[bool] = True
    enable_mutations: Optional[bool] = True
    enable_llm_generation: Optional[bool] = False
    generator_target_id: Optional[str] = None
    max_candidates: Optional[int] = 30
    max_requests: Optional[int] = 40
    timeout_seconds: Optional[int] = 180



class TargetCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    provider: str
    model: Optional[str] = ""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    system_prompt: Optional[str] = None
    canaries: Optional[List[str]] = None
    headers: Optional[Any] = None
    request_template: Optional[Any] = None
    response_path: Optional[str] = None
    allow_local_network: Optional[bool] = False
    authorization_confirmed: bool = Field(
        ...,
        description="User confirmation that they own or have explicit authorization to test this target."
    )


class TargetUpdateRequest(BaseModel):
    name: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    system_prompt: Optional[str] = None
    canaries: Optional[List[str]] = None
    headers: Optional[Any] = None
    request_template: Optional[Any] = None
    response_path: Optional[str] = None
    allow_local_network: Optional[bool] = None
    authorization_confirmed: Optional[bool] = None
    is_active: Optional[bool] = None


# ── Provider Metadata ────────────────────────────────────────────────────────
SUPPORTED_PROVIDERS = [
    {
        "id": "gemini",
        "name": "Google Gemini",
        "description": "Google Gemini models via Google GenAI SDK or AI Studio REST API.",
        "default_model": "gemini-3.5-flash-lite",
        "recommended_models": ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-flash-latest"],

        "default_base_url": "https://generativelanguage.googleapis.com",
        "requires_api_key": True,
        "supports_system_prompt": True,
        "supports_custom_base_url": False,
    },
    {
        "id": "openai",
        "name": "OpenAI",
        "description": "Official OpenAI models via Chat Completions endpoint.",
        "default_model": "gpt-4o-mini",
        "recommended_models": ["gpt-4o-mini", "gpt-4o", "o3-mini", "gpt-4-turbo"],
        "default_base_url": "https://api.openai.com/v1",
        "requires_api_key": True,
        "supports_system_prompt": True,
        "supports_custom_base_url": True,
    },
    {
        "id": "anthropic",
        "name": "Anthropic Claude",
        "description": "Anthropic Claude models via Messages API.",
        "default_model": "claude-3-5-sonnet-20241022",
        "recommended_models": ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-haiku-20240307"],
        "default_base_url": "https://api.anthropic.com/v1",
        "requires_api_key": True,
        "supports_system_prompt": True,
        "supports_custom_base_url": True,
    },
    {
        "id": "openrouter",
        "name": "OpenRouter",
        "description": "Multi-provider AI Gateway (OpenAI-compatible protocol).",
        "default_model": "openai/gpt-4o-mini",
        "recommended_models": ["openai/gpt-4o-mini", "anthropic/claude-3.5-sonnet", "google/gemini-2.5-flash", "deepseek/deepseek-chat"],
        "default_base_url": "https://openrouter.ai/api/v1",
        "requires_api_key": True,
        "supports_system_prompt": True,
        "supports_custom_base_url": True,
    },
    {
        "id": "openai_compatible",
        "name": "OpenAI-Compatible / Local",
        "description": "Self-hosted vLLM, Ollama, LocalAI, Together, Groq, or custom gateways.",
        "default_model": "llama3",
        "recommended_models": ["llama3", "mistral", "qwen2.5-7b", "custom"],
        "default_base_url": "http://localhost:11434/v1",
        "requires_api_key": False,
        "supports_system_prompt": True,
        "supports_custom_base_url": True,
    },
    {
        "id": "custom",
        "name": "Custom REST API Endpoint",
        "description": "Arbitrary HTTP service with configurable payload template and response extraction path.",
        "default_model": "custom-service",
        "recommended_models": ["custom-service"],
        "default_base_url": "https://api.example.com/v1/chat",
        "requires_api_key": False,
        "supports_system_prompt": True,
        "supports_custom_base_url": True,
    },
    {
        "id": "techmart",
        "name": "TechMart Customer Support (Demo)",
        "description": "Existing local demonstration target on port 8000 with live SECURE / VULNERABLE switching.",
        "default_model": "gemini-3.5-flash-lite",
        "recommended_models": ["gemini-3.5-flash-lite"],
        "default_base_url": "http://127.0.0.1:8000",
        "requires_api_key": False,
        "supports_system_prompt": False,
        "supports_custom_base_url": True,
    },
]


# ── Background scan worker ───────────────────────────────────────────────────
def _run_scan(
    target_id: Optional[str] = None,
    mode: Optional[str] = None,
    categories: Optional[List[str]] = None,
    include_baseline: bool = True,
    enable_runtime_generation: bool = True,
    enable_templates: bool = True,
    enable_mutations: bool = True,
    enable_llm_generation: bool = False,
    generator_target_id: Optional[str] = None,
    max_candidates: int = 30,
    max_requests: int = 40,
    timeout_seconds: int = 180,
):
    """Execute adversarial attacks sequentially against the chosen target adapter with budget enforcement."""
    global _state, _scan_finalizing
    sensitive_values: List[str] = []

    try:
        # Retrieve target with decrypted secret for backend scanning
        target_dict = None
        if target_id:
            target_dict = target_storage.get_target_by_id(target_id, include_secrets=True)
        if not target_dict:
            target_dict = target_storage.get_active_target(include_secrets=True)

        if not target_dict:
            raise RuntimeError("No target configuration available to scan.")

        # Enforce target authorization restriction (Requirement 10)
        if not target_dict.get("authorization_confirmed", False):
            raise RuntimeError(f"Target '{target_dict.get('name')}' is not authorized for testing.")

        for secret_field in ("api_key", "encrypted_api_key"):
            secret = target_dict.get(secret_field)
            if isinstance(secret, str) and secret:
                sensitive_values.append(secret)
        configured_headers = target_dict.get("headers")
        if isinstance(configured_headers, dict):
            sensitive_values.extend(
                value for value in configured_headers.values()
                if isinstance(value, str) and value
            )

        adapter = create_adapter(target_dict)

        # If target supports mode switching (TechMart) and mode specified
        if mode and hasattr(adapter, "set_mode"):
            adapter.set_mode(mode)

        active_mode = getattr(adapter, "get_mode", lambda: "STANDARD")()

        # Optional attack-generation LLM adapter
        generator_adapter = None
        if enable_runtime_generation and enable_llm_generation and generator_target_id:
            gen_target_dict = target_storage.get_target_by_id(generator_target_id, include_secrets=True)
            if gen_target_dict:
                try:
                    for secret_field in ("api_key", "encrypted_api_key"):
                        secret = gen_target_dict.get(secret_field)
                        if isinstance(secret, str) and secret:
                            sensitive_values.append(secret)
                    generator_headers = gen_target_dict.get("headers")
                    if isinstance(generator_headers, dict):
                        sensitive_values.extend(
                            value for value in generator_headers.values()
                            if isinstance(value, str) and value
                        )
                    generator_adapter = create_adapter(gen_target_dict)
                except Exception:
                    generator_adapter = None

        attacks = generate_runtime_suite(
            categories=categories,
            include_baseline=include_baseline,
            enable_templates=enable_runtime_generation and enable_templates,
            enable_mutations=enable_runtime_generation and enable_mutations,
            enable_llm=enable_runtime_generation and enable_llm_generation and (generator_adapter is not None),
            llm_adapter=generator_adapter,
            target_id=target_dict["id"],
            max_candidates=max_candidates,
            max_requests=max_requests,
        )

        scan_configuration = {
            "categories": categories,
            "include_baseline": include_baseline,
            "enable_runtime_generation": enable_runtime_generation,
            "enable_templates": enable_templates,
            "enable_mutations": enable_mutations,
            "enable_llm_generation": enable_llm_generation,
            "max_candidates": max_candidates,
            "max_requests": max_requests,
            "timeout_seconds": timeout_seconds,
            "target_revision": target_dict.get("updated_at"),
            "baseline_tests_planned": sum(
                attack.get("generation_method") == "predefined" for attack in attacks
            ),
            "mutations_planned": sum(
                attack.get("generation_method") == "mutation" for attack in attacks
            ),
            "mutation_operators": sorted({
                attack["mutation_operator"]
                for attack in attacks
                if attack.get("mutation_operator")
            }),
        }

        target_summary_info = {
            "id": target_dict["id"],
            "name": target_dict["name"],
            "provider": target_dict["provider"],
            "model": target_dict.get("model", ""),
            "base_url": _redact_scan_secrets(target_dict.get("base_url", ""), sensitive_values),
            "canaries": [
                canary for canary in (target_dict.get("canaries") or [])
                if canary not in sensitive_values
            ],
            "target_revision": target_dict.get("updated_at"),
        }
        scan_history_store.update_scan_metadata(
            _state.get("scan_id"),
            target_summary_info,
            active_mode,
            scan_configuration,
        )

        with _lock:
            _state.update({
                "status": "running",
                "error": None,
                "target_info": target_summary_info,
                "mode": active_mode,
                "total": len(attacks),
                "completed": 0,
                "current_attack": None,
                "results": [],
                "summary": {"SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
                "category_stats": {},
                "generation_stats": {
                    "predefined": {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
                    "template": {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
                    "mutation": {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
                    "llm": {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
                },
                "vulnerable_cases": [],
            })
            for attack in attacks:
                cat = attack["category"]
                if cat not in _state["category_stats"]:
                    _state["category_stats"][cat] = {
                        "total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0
                    }

        target_canaries = target_dict.get("canaries") or []
        scan_start_time = time.time()
        executed_test_ids = set()

        for attack in attacks:
            # Enforce execution time budget (Requirement 5)
            if _scan_stop_event.is_set():
                break
            if time.time() - scan_start_time > timeout_seconds:
                break

            test_id = attack.get("id")
            if not test_id or test_id in executed_test_ids:
                _logger.warning("Skipping duplicate or missing test ID in scan %s", _state.get("scan_id"))
                continue
            executed_test_ids.add(test_id)

            cat = attack["category"]
            gen_method = attack.get("generation_method", "predefined")

            with _lock:
                _state["category_stats"][cat]["total"] += 1
                if gen_method in _state["generation_stats"]:
                    _state["generation_stats"][gen_method]["total"] += 1
                _state["current_attack"] = {
                    "id": attack["id"],
                    "parent_test_id": attack.get("parent_test_id"),
                    "name": attack["name"],
                    "category": cat,
                    "generation_method": gen_method,
                    "mutation_operator": attack.get("mutation_operator"),
                    "is_generated": attack.get("is_generated", False),
                }

            try:
                response, latency_ms = adapter.send_message(attack["prompt"])
                verdict, detail = evaluate_response_details(response, canaries=target_canaries)
            except Exception as exc:
                clean_err = adapter.sanitize_error(exc)
                response = f"[ERROR] Exception during attack execution: {clean_err}"
                latency_ms = None
                verdict = "TARGET_ERROR"
                detail = clean_err

            result = {
                "id": attack["id"],
                "test_id": attack["id"],
                "parent_test_id": attack.get("parent_test_id"),
                "category": cat,
                "name": attack["name"],
                "objective": attack["objective"],
                "prompt": attack["prompt"],
                "normalized_hash": normalize_prompt_for_dedup(attack["prompt"]),
                "generation_method": gen_method,
                "mutation_operator": attack.get("mutation_operator"),
                "is_generated": attack.get("is_generated", False),
                "target_id": target_dict["id"],
                "target_name": target_dict["name"],
                "response": response,
                "verdict": verdict,
                "detail": detail,
                "latency": f"{latency_ms}ms" if latency_ms is not None else None,
                "timestamp": datetime.now().isoformat(),
            }
            result = _redact_scan_secrets(result, sensitive_values)
            if not scan_history_store.add_execution(_state.get("scan_id"), result):
                _logger.warning(
                    "Ignoring duplicate persisted test execution %s for scan %s",
                    test_id,
                    _state.get("scan_id"),
                )
                continue

            with _lock:
                _state["results"].append(result)
                _state["summary"][verdict] += 1
                _state["category_stats"][cat][verdict] += 1
                if gen_method in _state["generation_stats"]:
                    _state["generation_stats"][gen_method][verdict] += 1
                _state["completed"] += 1
                if verdict == "VULNERABLE":
                    _state["vulnerable_cases"].append({
                        "id": attack["id"],
                        "parent_test_id": attack.get("parent_test_id"),
                        "category": cat,
                        "name": attack["name"],
                        "generation_method": gen_method,
                        "mutation_operator": attack.get("mutation_operator"),
                        "is_generated": attack.get("is_generated", False),
                        "detail": detail,
                    })

        with _lock:
            cancelled = _scan_stop_event.is_set()
            _scan_finalizing = True
            _state["current_attack"] = None
            completed_at = datetime.now().isoformat()

        from comparison import analyze_comparison_records, save_comparison_report
        baseline_recs = [r for r in _state["results"] if r.get("generation_method") == "predefined"]
        mutation_recs = [r for r in _state["results"] if r.get("generation_method") == "mutation"]
        comp_report = analyze_comparison_records(
            baseline_records=baseline_recs,
            mutation_records=mutation_recs,
            target_info=_state.get("target_info"),
        )
        comp_report["scan_id"] = _state.get("scan_id")
        planned_prompts = [
            normalize_prompt_for_dedup(attack["prompt"])
            for attack in attacks
            if isinstance(attack.get("prompt"), str) and attack["prompt"].strip()
        ]
        executed_prompts = [
            result["normalized_hash"]
            for result in _state["results"]
            if result.get("normalized_hash")
        ]
        summary = {
            "total_executed": len(_state["results"]),
            "expected_executions": len(attacks),
            "incomplete_executions": max(0, len(attacks) - len(_state["results"])),
            "unique_prompts_executed": len(set(executed_prompts)),
            "duplicate_prompt_executions": len(executed_prompts) - len(set(executed_prompts)),
            "unique_prompts_planned": len(set(planned_prompts)),
            "confirmed_findings": len(comp_report.get("findings", [])),
            "SAFE": _state["summary"].get("SAFE", 0),
            "VULNERABLE": _state["summary"].get("VULNERABLE", 0),
            "TARGET_ERROR": _state["summary"].get("TARGET_ERROR", 0),
            "baseline_tests": sum(
                result.get("generation_method") == "predefined"
                for result in _state["results"]
            ),
            "mutation_tests": sum(
                result.get("generation_method") == "mutation"
                for result in _state["results"]
            ),
            "mutation_operators": scan_configuration["mutation_operators"],
            "novel_findings": comp_report.get("novel_findings_count", 0),
            "outcome_shifts": comp_report.get("distinct_outcomes_count", 0),
        }
        scan_history_store.finish_scan(
            _state.get("scan_id"),
            "CANCELLED" if cancelled else "COMPLETED",
            summary,
            comp_report,
            completed_at=completed_at,
        )
        save_comparison_report(comp_report)
        with _lock:
            _state["status"] = "cancelled" if cancelled else "completed"
            _state["completed_at"] = completed_at
            _state["stop_requested"] = False
            _scan_finalizing = False
        _persist_scan_state()

    except Exception as exc:
        error_message = str(exc)
        error_message = _redact_scan_secrets(error_message, sensitive_values)
        _logger.error("LLMGuard scan failed: %s", error_message)
        with _lock:
            _scan_finalizing = True
            _state["error"] = error_message
            _state["current_attack"] = None
            completed_at = datetime.now().isoformat()
        try:
            scan_history_store.fail_scan(
                _state.get("scan_id"),
                error_message,
                completed_at=completed_at,
            )
        except Exception:
            _logger.exception("Failed to persist failed scan history")
        with _lock:
            _state["status"] = "error"
            _state["completed_at"] = completed_at
            _state["stop_requested"] = False
            _scan_finalizing = False
        try:
            _persist_scan_state()
        except (OSError, TypeError, ValueError):
            _logger.exception("Failed to persist scan state after scan failure")


# ── Providers Endpoints ───────────────────────────────────────────────────────
@app.get("/api/providers")
def api_get_providers():
    """List all supported LLM providers and configuration schemas."""
    return {"providers": SUPPORTED_PROVIDERS}


# ── Targets CRUD Endpoints ───────────────────────────────────────────────────
@app.get("/api/targets")
def api_get_targets():
    """List all configured targets with masked secrets."""
    targets = target_storage.get_all_targets(include_secrets=False)
    active = target_storage.get_active_target(include_secrets=False)
    return {
        "targets": targets,
        "active_target_id": active["id"] if active else None,
        "total": len(targets),
    }


@app.get("/api/targets/active")
def api_get_active_target():
    """Retrieve the currently active target with masked secrets."""
    active = target_storage.get_active_target(include_secrets=False)
    if not active:
        raise HTTPException(status_code=404, detail="No active target configured")
    return active


@app.post("/api/targets")
def api_create_target(req: TargetCreateRequest):
    """Add a new target configuration with server-side credential encryption."""
    if not req.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="You must confirm authorization to perform security testing on this target."
        )

    # SSRF verification on custom URLs
    if req.base_url and req.provider in ("custom", "openai", "openrouter", "anthropic"):
        valid, err = validate_url_ssrf(req.base_url, allow_local_network=bool(req.allow_local_network))
        if not valid:
            raise HTTPException(status_code=400, detail=f"Target URL rejected by SSRF protection: {err}")

    # Key requirement check
    prov = req.provider.lower()
    if prov in ("gemini", "openai", "anthropic") and not req.api_key:
        raise HTTPException(status_code=400, detail=f"API key is required for provider '{req.provider}'")

    dump_data = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    created = target_storage.save_target(dump_data)
    return created


@app.put("/api/targets/{target_id}")
def api_update_target(target_id: str, req: TargetUpdateRequest):
    """Update target configuration (keeps existing encrypted key if omitted)."""
    existing = target_storage.get_target_by_id(target_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Target not found")

    if req.base_url:
        allow_loc = req.allow_local_network if req.allow_local_network is not None else existing.get("allow_local_network", False)
        valid, err = validate_url_ssrf(req.base_url, allow_local_network=bool(allow_loc))
        if not valid:
            raise HTTPException(status_code=400, detail=f"Target URL rejected by SSRF protection: {err}")

    dump_updates = (
        req.model_dump(exclude_unset=True)
        if hasattr(req, "model_dump")
        else req.dict(exclude_unset=True)
    )
    updated = target_storage.update_target(target_id, dump_updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Target update failed")
    return updated


@app.delete("/api/targets/{target_id}")
def api_delete_target(target_id: str):
    """Delete a target configuration."""
    deleted = target_storage.delete_target(target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"success": True, "deleted_id": target_id}


@app.post("/api/targets/{target_id}/select")
def api_select_target(target_id: str):
    """Set the specified target as active for scans and telemetry."""
    selected = target_storage.set_active_target(target_id)
    if not selected:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"success": True, "active_target": selected}


@app.post("/api/targets/{target_id}/test")
def api_test_target_connection(target_id: str):
    """Test connectivity and credential validity for a specific target."""
    target_dict = target_storage.get_target_by_id(target_id, include_secrets=True)
    if not target_dict:
        raise HTTPException(status_code=404, detail="Target not found")

    adapter = create_adapter(target_dict)
    success, message, latency_ms = adapter.test_connection()

    new_status = "connected" if success else "error"
    target_storage.update_target(target_id, {
        "status": new_status,
        "last_tested": datetime.now().isoformat()
    })

    return {
        "target_id": target_id,
        "target_name": target_dict["name"],
        "provider": target_dict["provider"],
        "success": success,
        "status": new_status,
        "message": message,
        "latency_ms": latency_ms,
    }


# ── System Health & Status ───────────────────────────────────────────────────
@app.get("/api/status")
def api_status():
    """Overall health check: LLMGuard engine + Active target connectivity status."""
    active_target = target_storage.get_active_target(include_secrets=True)
    target_online = False
    target_mode = "UNKNOWN"
    target_name = "None"
    provider = "None"

    if active_target:
        target_name = active_target["name"]
        provider = active_target["provider"]
        try:
            adapter = create_adapter(active_target)
            if hasattr(adapter, "get_mode"):
                mode = adapter.get_mode()
                target_online = (mode != "UNKNOWN")
                target_mode = mode
            else:
                # For external targets, use last known status or quick check
                target_online = active_target.get("status") == "connected"
                target_mode = "ONLINE" if target_online else "UNTESTED"
        except Exception:
            target_online = False
            target_mode = "UNKNOWN"

    with _lock:
        scan_status = _state["status"]

    return {
        "llmguard": "running",
        "target_online": target_online,
        "target_mode": target_mode,
        "active_target": {
            "id": active_target["id"] if active_target else None,
            "name": target_name,
            "provider": provider,
            "model": active_target.get("model") if active_target else None,
        } if active_target else None,
        "scan_status": scan_status,
    }


# ── TechMart Target Mode Compatibility Endpoints ─────────────────────────────
@app.get("/api/target/mode")
def api_get_target_mode():
    """Return active target mode (SECURE / VULNERABLE for TechMart, or provider status)."""
    active_target = target_storage.get_active_target(include_secrets=True)
    if not active_target:
        return {"mode": "UNKNOWN", "online": False}

    adapter = create_adapter(active_target)
    if hasattr(adapter, "get_mode"):
        mode = adapter.get_mode()
        return {"mode": mode, "online": mode != "UNKNOWN"}

    status = active_target.get("status", "untested")
    return {"mode": "EXTERNAL", "online": (status == "connected")}


@app.post("/api/target/mode")
def api_set_target_mode(request: ModeRequest):
    """Switch TechMart target between SECURE and VULNERABLE."""
    active_target = target_storage.get_active_target(include_secrets=True)
    if not active_target:
        raise HTTPException(status_code=404, detail="No active target")

    adapter = create_adapter(active_target)
    if hasattr(adapter, "set_mode"):
        mode_upper = request.mode.strip().upper()
        if mode_upper not in ("SECURE", "VULNERABLE"):
            raise HTTPException(status_code=400, detail="Mode must be SECURE or VULNERABLE")
        result = adapter.set_mode(mode_upper)
        return {"mode": result or mode_upper}

    return {"mode": "N/A", "message": "Active target does not support synthetic mode switching"}


# ── Attacks & Scan Execution Endpoints ───────────────────────────────────────
@app.get("/api/attacks")
def api_get_attacks():
    """Return all adversarial attack probe definitions."""
    attacks = generate_attacks()
    return {"attacks": attacks, "total": len(attacks)}


@app.post("/api/scan/start")
def api_start_scan(request: ScanRequest):
    """Start an adversarial security scan in a background worker thread."""
    global _scan_finalizing
    target_public = (
        target_storage.get_target_by_id(request.target_id, include_secrets=False)
        if request.target_id else target_storage.get_active_target(include_secrets=False)
    )
    initial_target = {
        key: target_public.get(key)
        for key in ("id", "name", "provider", "model", "updated_at")
    } if target_public else {}
    with _lock:
        if _state["status"] == "running":
            raise HTTPException(status_code=409, detail="A security scan is already running")
        scan_id = str(uuid.uuid4())[:8].upper()
        try:
            scan_history_store.create_scan(
                scan_id=scan_id,
                scan_name=request.scan_name,
                target_info=initial_target,
                mode=request.mode,
                configuration=request.dict(exclude={"scan_name"}),
                created_at=datetime.now().isoformat(),
            )
        except Exception as exc:
            _logger.exception("Could not create scan history record")
            raise HTTPException(
                status_code=500,
                detail=f"Could not create scan history record: {exc}",
            ) from exc
        _state["scan_id"] = scan_id
        _state["started_at"] = datetime.now().isoformat()
        _state["completed_at"] = None
        _state["error"] = None
        _state["stop_requested"] = False
        _state["status"] = "running"
        _state["total"] = 0
        _state["completed"] = 0
        _state["current_attack"] = None
        _state["target_info"] = None
        _state["mode"] = None
        _state["results"] = []
        _state["summary"] = {"SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0}
        _state["category_stats"] = {}
        _state["vulnerable_cases"] = []
        _scan_stop_event.clear()
        _scan_finalizing = False

    try:
        _persist_scan_state()
    except Exception:
        _logger.exception("Could not update latest-scan compatibility file at start")

    t = threading.Thread(
        target=_run_scan,
        kwargs={
            "target_id": request.target_id,
            "mode": request.mode,
            "categories": request.categories,
            "include_baseline": request.include_baseline if request.include_baseline is not None else True,
            "enable_runtime_generation": request.enable_runtime_generation if request.enable_runtime_generation is not None else True,
            "enable_templates": request.enable_templates if request.enable_templates is not None else False,
            "enable_mutations": request.enable_mutations if request.enable_mutations is not None else True,
            "enable_llm_generation": request.enable_llm_generation if request.enable_llm_generation is not None else False,
            "generator_target_id": request.generator_target_id,
            "max_candidates": request.max_candidates or 30,
            "max_requests": request.max_requests or 40,
            "timeout_seconds": request.timeout_seconds or 180,
        },
        daemon=True,
    )
    try:
        t.start()
    except RuntimeError as exc:
        scan_history_store.fail_scan(scan_id, f"Could not start scan worker: {exc}")
        with _lock:
            _state["status"] = "error"
            _state["error"] = "Could not start scan worker."
            _state["completed_at"] = datetime.now().isoformat()
        raise HTTPException(status_code=500, detail="Could not start scan worker") from exc
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scan/status")
def api_scan_status():
    """Lightweight polling: progress + current attack + summary counts."""
    with _lock:
        return {
            "status": _state["status"],
            "scan_id": _state["scan_id"],
            "error": _state.get("error"),
            "stop_requested": _state.get("stop_requested", False),
            "finalizing": _scan_finalizing,
            "target_info": _state.get("target_info"),
            "total": _state["total"],
            "completed": _state["completed"],
            "mode": _state["mode"],
            "started_at": _state["started_at"],
            "completed_at": _state["completed_at"],
            "current_attack": _state.get("current_attack"),
            "summary": dict(_state["summary"]),
            "target_errors": [
                {
                    "test_id": result.get("test_id") or result.get("id"),
                    "detail": result.get("detail"),
                }
                for result in _state["results"]
                if result.get("verdict") == "TARGET_ERROR"
            ][:5],
        }


@app.post("/api/scan/stop")
def api_stop_scan():
    """Request cooperative cancellation after the in-flight target request returns."""
    with _lock:
        if _state["status"] != "running" or _scan_finalizing:
            raise HTTPException(status_code=409, detail="No security scan is currently running")
        _scan_stop_event.set()
        _state["stop_requested"] = True
        return {
            "scan_id": _state.get("scan_id"),
            "status": "stop_requested",
            "message": "The scan will stop after its current target request completes.",
        }


@app.get("/api/scan/results")
def api_scan_results():
    """Full scan results: all test records, category stats, and vulnerability cases."""
    with _lock:
        if _state["results"] or _state["status"] == "running":
            return {
                "status": _state["status"],
                "scan_id": _state["scan_id"],
                "error": _state.get("error"),
                "target_info": _state.get("target_info"),
                "mode": _state["mode"],
                "started_at": _state["started_at"],
                "completed_at": _state["completed_at"],
                "total": _state["total"],
                "results": list(_state["results"]),
                "summary": dict(_state["summary"]),
                "category_stats": {k: dict(v) for k, v in _state["category_stats"].items()},
                "vulnerable_cases": list(_state["vulnerable_cases"]),
            }

    # SQLite is authoritative across restarts; the compatibility JSON may be stale.
    try:
        history = scan_history_store.list_scans(page=1, page_size=1)
        if history["scans"]:
            scan = scan_history_store.get_scan(history["scans"][0]["scan_id"])
            if scan is not None:
                results = scan["results"]
                summary = scan["summary"]
                category_stats = {}
                generation_stats = {}
                for record in results:
                    category = record.get("category") or "Uncategorized"
                    category_counts = category_stats.setdefault(
                        category,
                        {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0, "INCONCLUSIVE": 0},
                    )
                    generation = record.get("generation_method") or "predefined"
                    generation_counts = generation_stats.setdefault(
                        generation,
                        {"total": 0, "SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0, "INCONCLUSIVE": 0},
                    )
                    category_counts["total"] += 1
                    generation_counts["total"] += 1
                    verdict = record.get("verdict")
                    if verdict in category_counts:
                        category_counts[verdict] += 1
                        generation_counts[verdict] += 1

                status = {
                    "RUNNING": "running",
                    "COMPLETED": "completed",
                    "FAILED": "error",
                    "CANCELLED": "cancelled",
                }[scan["status"]]
                return {
                    "status": status,
                    "scan_id": scan["scan_id"],
                    "error": scan["error"],
                    "target_info": scan["target_info"],
                    "mode": scan["mode"],
                    "started_at": scan["created_at"],
                    "completed_at": scan["completed_at"],
                    "total": summary.get("expected_executions", len(results)),
                    "completed": len(results),
                    "results": results,
                    "summary": summary,
                    "category_stats": category_stats,
                    "generation_stats": generation_stats,
                    "vulnerable_cases": [
                        {
                            "id": finding["test_id"],
                            "parent_test_id": finding.get("parent_test_id"),
                            "category": finding.get("category"),
                            "name": finding.get("name"),
                            "generation_method": finding.get("generation_method"),
                            "mutation_operator": finding.get("mutation_operator"),
                            "detail": finding.get("reason"),
                        }
                        for finding in scan["findings"]
                    ],
                }
    except sqlite3.Error as exc:
        _logger.exception("Could not load persisted scan history")
        raise HTTPException(status_code=500, detail="Could not load persisted scan history") from exc

    # Keep compatibility with installations that predate SQLite scan history.
    if os.path.exists(_SCAN_STORAGE_FILE):
        try:
            with open(_SCAN_STORAGE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            _logger.exception("Could not load persisted scan results")
            raise HTTPException(
                status_code=500,
                detail=f"Could not load persisted scan results: {exc}",
            ) from exc

    with _lock:
        return {
            "status": _state["status"],
            "scan_id": _state["scan_id"],
            "error": _state.get("error"),
            "target_info": _state.get("target_info"),
            "mode": _state["mode"],
            "started_at": _state["started_at"],
            "completed_at": _state["completed_at"],
            "total": _state["total"],
            "results": list(_state["results"]),
            "summary": dict(_state["summary"]),
            "category_stats": {k: dict(v) for k, v in _state["category_stats"].items()},
            "vulnerable_cases": list(_state["vulnerable_cases"]),
        }


@app.get("/api/scan/comparison")
def api_scan_comparison():
    """Generates an in-depth baseline vs mutation comparison analysis from the latest scan or disk."""
    with _lock:
        results = list(_state["results"])
        target_info = _state.get("target_info") or {}
        scan_id = _state.get("scan_id")
        scan_status = _state.get("status")

    baseline_records = [r for r in results if r.get("generation_method") == "predefined"]
    mutation_records = [r for r in results if r.get("generation_method") == "mutation"]

    from comparison import analyze_comparison_records, save_comparison_report, load_latest_comparison_report
    if baseline_records or mutation_records:
        report = analyze_comparison_records(
            baseline_records=baseline_records,
            mutation_records=mutation_records,
            target_info=target_info
        )
        report["scan_id"] = scan_id
        save_comparison_report(report)
        return report

    # Fallback to disk persistence if available
    if scan_status == "idle":
        persisted = load_latest_comparison_report()
        if persisted:
            return persisted

    empty_report = analyze_comparison_records(
        baseline_records=[],
        mutation_records=[],
        target_info=target_info
    )
    empty_report["scan_id"] = scan_id
    empty_report["scan_status"] = scan_status
    return empty_report


@app.get("/api/scans")
def api_list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, pattern="^(RUNNING|COMPLETED|FAILED|CANCELLED)$"),
    target_id: Optional[str] = Query(None, max_length=128),
    scan_id_search: Optional[str] = Query(None, max_length=128),
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
):
    """Return a paginated, filterable history of persisted scan records."""
    if start_date and end_date and end_date < start_date:
        raise HTTPException(status_code=422, detail="end_date must be on or after start_date")
    try:
        return scan_history_store.list_scans(
            page=page,
            page_size=page_size,
            status=status,
            target_id=target_id,
            scan_id_search=scan_id_search,
            start_date=datetime.combine(start_date, datetime_time.min).isoformat() if start_date else None,
            end_date_exclusive=(
                datetime.combine(end_date + timedelta(days=1), datetime_time.min).isoformat()
                if end_date else None
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        _logger.exception("Could not retrieve scan history")
        raise HTTPException(status_code=500, detail="Could not retrieve scan history") from exc


@app.get("/api/scans/compare")
def api_compare_scans(
    baseline_id: str = Query(..., min_length=1, max_length=128),
    current_id: str = Query(..., min_length=1, max_length=128),
):
    """Compare two saved scans without treating missing findings as remediation."""
    baseline = scan_history_store.get_scan(baseline_id)
    current = scan_history_store.get_scan(current_id)
    if baseline is None:
        raise HTTPException(status_code=404, detail=f"Baseline scan '{baseline_id}' was not found")
    if current is None:
        raise HTTPException(status_code=404, detail=f"Current scan '{current_id}' was not found")
    return compare_scans(baseline, current)


@app.get("/api/scans/{scan_id}/findings")
def api_scan_findings(scan_id: str):
    findings = scan_history_store.list_findings(scan_id)
    if findings is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' was not found")
    return {"scan_id": scan_id, "findings": findings, "total": len(findings)}


@app.get("/api/scans/{scan_id}")
def api_get_scan(scan_id: str):
    scan = scan_history_store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' was not found")
    return scan


@app.get("/api/analytics/overview")
def api_analytics_overview():
    try:
        return analytics_overview(scan_history_store)
    except sqlite3.Error as exc:
        _logger.exception("Could not build scan analytics overview")
        raise HTTPException(status_code=500, detail="Could not build scan analytics overview") from exc


@app.get("/api/analytics/trends")
def api_analytics_trends():
    try:
        return analytics_trends(scan_history_store)
    except sqlite3.Error as exc:
        _logger.exception("Could not build scan trend analytics")
        raise HTTPException(status_code=500, detail="Could not build scan trend analytics") from exc


@app.get("/api/analytics/categories")
def api_analytics_categories():
    try:
        return analytics_categories(scan_history_store)
    except sqlite3.Error as exc:
        _logger.exception("Could not build category analytics")
        raise HTTPException(status_code=500, detail="Could not build category analytics") from exc


# ── Static file serving ───────────────────────────────────────────────────────
_static_dir = os.path.join(_DIR, "static")
if os.path.isdir(_static_dir):
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  LLMGuard API Server v2.0  —  http://127.0.0.1:8001")
    print("  Multi-Provider Adversarial Testing & Security Suite")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8001, reload=False)
