"""
LLMGuard Comparison Engine
--------------------------
Evaluates the quality and effectiveness of runtime-generated adversarial tests
by running baseline attacks and runtime mutations side-by-side against the same
authorized target configuration.

Records:
- Target ID, provider, model configuration
- Test ID, parent test ID, category, generation method
- Mutation operator and family
- Raw target response, evaluator verdict, evaluation evidence, latency, and error states
- Aggregated metrics: executed tests, confirmed findings, inconclusive outcomes, target errors
- Lineage grouping: parent-to-child outcome tracking
- Mutation operator breakdown and distinct outcome detection
- Deduplication and trivial variation detection (refusing to claim efficacy from mere textual differences)
"""

import sys
import os
import copy
import time
import json
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from attack_generator import (
    generate_attacks,
    generate_mutated_attacks,
    normalize_prompt_for_dedup,
    deduplicate_attacks,
    CONTROLLED_MUTATION_OPERATORS,
)
from evaluator import evaluate_response_details, extract_evidence_details
from target_client import get_active_adapter

# ── Local persistence configuration ──────────────────────────────────────────
_DATA_DIR = os.path.join(_DIR, "data")
COMPARISON_STORAGE_FILE = os.path.join(_DATA_DIR, "latest_comparison.json")
_storage_lock = threading.Lock()


def _sanitize_report_for_persistence(report: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures sensitive credentials, API keys, or raw secrets are never written to disk."""
    clean = copy.deepcopy(report)
    if "target_info" in clean and isinstance(clean["target_info"], dict):
        clean["target_info"].pop("api_key", None)
        clean["target_info"].pop("encrypted_api_key", None)
        clean["target_info"].pop("headers", None)
    return clean


def save_comparison_report(report: Dict[str, Any], filepath: Optional[str] = None) -> str:
    """Persists comparison report to disk atomically and thread-safely."""
    path = filepath or COMPARISON_STORAGE_FILE
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    sanitized = _sanitize_report_for_persistence(report)
    temp_path = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    with _storage_lock:
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(sanitized, f, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, path)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
    return path


def load_latest_comparison_report(filepath: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Loads latest persisted comparison report from disk."""
    path = filepath or COMPARISON_STORAGE_FILE
    try:
        with _storage_lock:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except FileNotFoundError:
        return None


def _verified_verdict(record: Dict[str, Any], canaries: Optional[List[str]] = None) -> str:
    """Return a security verdict only when the raw response and reason agree."""
    verdict = record.get("verdict")
    if verdict in ("INCONCLUSIVE", "TARGET_ERROR"):
        return verdict
    if verdict not in ("SAFE", "VULNERABLE"):
        return "INCONCLUSIVE"

    response = record.get("response")
    detail = record.get("detail")
    if not isinstance(response, str) or not detail:
        return "INCONCLUSIVE"

    evaluated_verdict, evaluated_detail = evaluate_response_details(
        response, canaries=canaries
    )
    if evaluated_verdict != verdict or evaluated_detail != detail:
        return "INCONCLUSIVE"
    return verdict


def execute_test_case(
    adapter: Any,
    attack: Dict[str, Any],
    target_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes a single test case against the target adapter and records complete
    metadata, raw response, latency, and evaluation evidence.
    """
    target_info = target_info or {}
    target_id = target_info.get("id", getattr(adapter, "target_id", "target-active"))
    target_name = target_info.get("name", getattr(adapter, "name", "Active Target"))
    provider = target_info.get("provider", getattr(adapter, "provider", "unknown"))
    model = target_info.get("model", getattr(adapter, "model", "default"))
    canaries = getattr(adapter, "canaries", []) or target_info.get("canaries", [])

    prompt = attack.get("prompt", "")
    gen_method = attack.get("generation_method", "predefined")
    parent_id = attack.get("parent_test_id")
    norm_hash = normalize_prompt_for_dedup(prompt)

    try:
        response, latency_ms = adapter.send_message(prompt)
        verdict, detail = evaluate_response_details(response, canaries=canaries)
        error_msg = None
        if verdict == "TARGET_ERROR":
            error_msg = detail
    except Exception as exc:
        clean_err = getattr(adapter, "sanitize_error", str)(exc)
        response = f"[ERROR] Execution failed: {clean_err}"
        latency_ms = None
        verdict = "TARGET_ERROR"
        detail = clean_err
        error_msg = clean_err

    return {
        "test_id": attack["id"],
        "parent_test_id": parent_id,
        "category": attack.get("category", "General"),
        "name": attack.get("name", ""),
        "objective": attack.get("objective", ""),
        "generation_method": gen_method,
        "mutation_operator": attack.get("mutation_operator"),
        "mutation_type": attack.get("mutation_type"),
        "prompt": prompt,
        "normalized_hash": norm_hash,
        "response": response,
        "verdict": verdict,
        "detail": detail,
        "latency_ms": latency_ms,
        "error": error_msg,
        "target_id": target_id,
        "target_name": target_name,
        "provider": provider,
        "model": model,
        "timestamp": datetime.now().isoformat(),
    }


def compute_summary_stats(
    records: List[Dict[str, Any]],
    canaries: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Computes summary counts and finding rates for a list of test records."""
    total = len(records)
    verdicts = [_verified_verdict(record, canaries) for record in records]
    vulnerable = sum(1 for verdict in verdicts if verdict == "VULNERABLE")
    safe = sum(1 for verdict in verdicts if verdict == "SAFE")
    inconclusive = sum(1 for verdict in verdicts if verdict == "INCONCLUSIVE")
    errors = sum(1 for verdict in verdicts if verdict == "TARGET_ERROR")
    unverified_vulnerabilities = sum(
        1
        for record, effective_verdict in zip(records, verdicts)
        if record.get("verdict") == "VULNERABLE" and effective_verdict != "VULNERABLE"
    )
    prompt_fingerprints = [
        normalize_prompt_for_dedup(record["prompt"])
        for record in records
        if isinstance(record.get("prompt"), str) and record["prompt"].strip()
    ]
    unique_prompts = len(set(prompt_fingerprints))
    finding_rate = round((vulnerable / total) * 100, 1) if total > 0 else 0.0

    return {
        "total_executed": total,
        "unique_prompts_executed": unique_prompts,
        "duplicate_prompt_executions": len(prompt_fingerprints) - unique_prompts,
        "confirmed_findings": vulnerable,
        "unverified_vulnerabilities": unverified_vulnerabilities,
        "safe_count": safe,
        "inconclusive_count": inconclusive,
        "target_errors": errors,
        "finding_rate_pct": finding_rate,
    }


def analyze_comparison_records(
    baseline_records: List[Dict[str, Any]],
    mutation_records: List[Dict[str, Any]],
    target_info: Optional[Dict[str, Any]] = None,
    duplicate_prompts_pruned: int = 0
) -> Dict[str, Any]:
    """
    Analyzes baseline and mutation test outcomes, tracking parent-child lineage,
    operator effectiveness, trivial variations, and distinct outcomes.

    Enforces:
    - Every mutation is compared strictly against its own executed parent baseline result.
    - If parent was not executed or produced a target error, no outcome shift is claimed.
    - Full structured finding records with matched canary, rule, excerpt, and lineage.
    - Operator breakdown totals strictly equal mutation totals.
    """
    canaries = (target_info.get("canaries") if target_info else []) or []
    for record in baseline_records + mutation_records:
        if record.get("verdict") == "VULNERABLE":
            is_verified = _verified_verdict(record, canaries) == "VULNERABLE"
            record["evidence_verified"] = is_verified
            if not is_verified:
                record["evidence_error"] = (
                    "Recorded VULNERABLE verdict is not supported by the raw response "
                    "and matching evaluator reason."
                )

    baseline_summary = compute_summary_stats(baseline_records, canaries)
    mutation_summary = compute_summary_stats(mutation_records, canaries)
    overall_summary = compute_summary_stats(baseline_records + mutation_records, canaries)

    baseline_by_id: Dict[str, Dict[str, Any]] = {}
    duplicate_baseline_ids: Set[str] = set()
    for record in baseline_records:
        record_id = record.get("test_id") or record.get("id")
        if not record_id:
            continue
        if record_id in baseline_by_id:
            duplicate_baseline_ids.add(record_id)
        else:
            baseline_by_id[record_id] = record
    for record_id in duplicate_baseline_ids:
        baseline_by_id.pop(record_id, None)

    # Group mutations by parent test
    parent_groups: Dict[str, Dict[str, Any]] = {}
    distinct_outcomes_count = 0
    novel_findings_count = 0
    trivial_variations_count = 0
    unmatched_parent_count = 0
    outcome_flips: List[Dict[str, Any]] = []

    for mut in mutation_records:
        parent_id = mut.get("parent_test_id")
        parent_record = baseline_by_id.get(parent_id) if parent_id else None
        mutation_id = mut.get("test_id") or mut.get("id")

        has_valid_parent = False
        p_status = "VALID"
        if parent_id in duplicate_baseline_ids:
            p_status = "AMBIGUOUS_PARENT"
            unmatched_parent_count += 1
        elif not parent_id or parent_record is None:
            p_status = "MISSING_PARENT"
            unmatched_parent_count += 1
        elif parent_record.get("verdict") == "TARGET_ERROR":
            p_status = "PARENT_ERROR"
            unmatched_parent_count += 1
        elif parent_record.get("verdict") in ("SAFE", "VULNERABLE", "INCONCLUSIVE"):
            parent_verdict = _verified_verdict(parent_record, canaries)
            if parent_verdict in ("SAFE", "VULNERABLE"):
                has_valid_parent = True
            else:
                p_status = "PARENT_INCONCLUSIVE"
                unmatched_parent_count += 1

        group_key = parent_id or "UNMATCHED"
        if group_key not in parent_groups:
            parent_groups[group_key] = {
                "parent_id": parent_id or "UNMATCHED",
                "parent_name": parent_record.get("name", "Unknown Parent") if parent_record else "Unknown Parent",
                "category": parent_record.get("category", mut.get("category", "General")) if parent_record else mut.get("category", "General"),
                "baseline_verdict": _verified_verdict(parent_record, canaries) if parent_record else p_status,
                "baseline_detail": parent_record.get("detail", "") if parent_record else "",
                "baseline_status": p_status,
                "mutations": [],
                "distinct_outcomes_count": 0,
                "novel_findings_count": 0,
                "has_distinct_outcome": False,
            }

        p_group = parent_groups[group_key]
        m_verdict = _verified_verdict(mut, canaries)
        if has_valid_parent and parent_record is not None:
            p_verdict = _verified_verdict(parent_record, canaries)
            # Both verdicts must be valid security evaluations to compare security outcome
            if m_verdict in ("SAFE", "VULNERABLE") and p_verdict in ("SAFE", "VULNERABLE"):
                is_distinct = (p_verdict != m_verdict)
                is_novel_finding = (p_verdict == "SAFE" and m_verdict == "VULNERABLE")
            else:
                is_distinct = False
                is_novel_finding = False

            if p_verdict in ("SAFE", "VULNERABLE") and p_verdict == m_verdict:
                trivial_variations_count += 1
        else:
            # Missing parent or parent had an error -> never claim outcome shift
            is_distinct = False
            is_novel_finding = False

        mut["is_distinct_outcome"] = is_distinct
        mut["is_novel_finding"] = is_novel_finding
        mut["parent_status"] = p_status
        mut_entry = dict(mut)
        p_group["mutations"].append(mut_entry)

        if is_distinct and parent_record is not None:
            distinct_outcomes_count += 1
            p_group["distinct_outcomes_count"] += 1
            p_group["has_distinct_outcome"] = True
            outcome_flips.append({
                "parent_id": parent_id,
                "mutation_id": mutation_id,
                "operator": mut.get("mutation_operator"),
                "baseline_verdict": _verified_verdict(parent_record, canaries),
                "mutation_verdict": m_verdict,
                "baseline_detail": parent_record.get("detail", ""),
                "mutation_detail": mut.get("detail", ""),
            })

        if is_novel_finding:
            novel_findings_count += 1
            p_group["novel_findings_count"] += 1

    # Operator breakdown
    operator_stats: Dict[str, Dict[str, Any]] = {}
    known_ops = {op.operator_id: op for op in CONTROLLED_MUTATION_OPERATORS}

    for mut in mutation_records:
        op_id = mut.get("mutation_operator") or "UNKNOWN"
        op_meta = known_ops.get(op_id)
        op_name = op_meta.name if op_meta else op_id
        op_type = op_meta.mutation_type if op_meta else "unclassified"

        if op_id not in operator_stats:
            operator_stats[op_id] = {
                "operator_id": op_id,
                "operator_name": op_name,
                "mutation_type": op_type,
                "total_executed": 0,
                "confirmed_findings": 0,
                "safe_count": 0,
                "inconclusive_count": 0,
                "target_errors": 0,
                "distinct_outcomes": 0,
                "novel_findings": 0,
            }

        op_stat = operator_stats[op_id]
        op_stat["total_executed"] += 1
        effective_verdict = _verified_verdict(mut, canaries)
        if effective_verdict == "VULNERABLE":
            op_stat["confirmed_findings"] += 1
        elif effective_verdict == "SAFE":
            op_stat["safe_count"] += 1
        elif effective_verdict == "INCONCLUSIVE":
            op_stat["inconclusive_count"] += 1
        elif effective_verdict == "TARGET_ERROR":
            op_stat["target_errors"] += 1

        # Use identical valid-parent check matching the main loop
        parent_id = mut.get("parent_test_id")
        parent_record = baseline_by_id.get(parent_id) if parent_id else None
        if parent_id and parent_record and parent_record.get("verdict") in ("SAFE", "VULNERABLE"):
            p_v = _verified_verdict(parent_record, canaries)
            m_v = _verified_verdict(mut, canaries)
            if m_v in ("SAFE", "VULNERABLE") and m_v != p_v:
                op_stat["distinct_outcomes"] += 1
            if p_v == "SAFE" and m_v == "VULNERABLE":
                op_stat["novel_findings"] += 1

    for op_id, op_stat in operator_stats.items():
        tot = op_stat["total_executed"]
        op_stat["finding_rate_pct"] = round((op_stat["confirmed_findings"] / tot) * 100, 1) if tot > 0 else 0.0

    # Build structured findings list for verified vulnerabilities
    findings: List[Dict[str, Any]] = []
    for rec in baseline_records + mutation_records:
        if _verified_verdict(rec, canaries) == "VULNERABLE":
            ev = extract_evidence_details(
                response=rec.get("response"),
                verdict=rec.get("verdict", "VULNERABLE"),
                detail=rec.get("detail", ""),
                canaries=canaries,
            )
            is_mut = (rec.get("generation_method") == "mutation")
            f_entry = {
                "finding_id": f"FINDING-{rec.get('test_id') or rec.get('id')}",
                "test_id": rec.get("test_id") or rec.get("id"),
                "generation_method": rec.get("generation_method", "predefined"),
                "baseline_test_id": rec.get("parent_test_id") or rec.get("test_id") or rec.get("id"),
                "mutation_test_id": (rec.get("test_id") or rec.get("id")) if is_mut else None,
                "parent_test_id": rec.get("parent_test_id"),
                "mutation_operator": rec.get("mutation_operator"),
                "target_id": rec.get("target_id") or (target_info.get("id") if target_info else "target-active"),
                "target_name": rec.get("target_name") or (target_info.get("name") if target_info else "Active Target"),
                "provider": rec.get("provider") or (target_info.get("provider") if target_info else "unknown"),
                "model": rec.get("model") or (target_info.get("model") if target_info else "default"),
                "category": rec.get("category", "General"),
                "name": rec.get("name", ""),
                "prompt": rec.get("prompt", ""),
                "raw_response": rec.get("response", ""),
                "response_excerpt": ev.get("evidence_excerpt"),
                "matched_canary": ev.get("matched_canary"),
                "matched_rule": ev.get("matched_rule"),
                "timestamp": rec.get("timestamp"),
                "latency_ms": rec.get("latency_ms"),
                "error": rec.get("error"),
                "verdict": rec.get("verdict"),
                "reason": rec.get("detail"),
                "evidence_verified": True,
                "is_novel_finding": rec.get("is_novel_finding", False),
            }
            findings.append(f_entry)

    # Measured empirical conclusion
    total_mutations = len(mutation_records)
    if novel_findings_count > 0:
        conclusion = (
            f"Efficacy Confirmed: Runtime mutations revealed {novel_findings_count} confirmed "
            f"vulnerabilit{'ies' if novel_findings_count > 1 else 'y'} where baseline test cases were "
            f"safely defended. Mutation operators successfully uncovered guardrail boundary gaps."
        )
    elif total_mutations > 0 and distinct_outcomes_count > 0:
        conclusion = (
            f"Behavioral Variation Detected: Mutations produced {distinct_outcomes_count} distinct "
            f"outcomes compared to baseline probes, but 0 novel vulnerabilities were discovered. "
            f"Variations altered target error or response classifications without breaking safety boundaries."
        )
    elif total_mutations > 0:
        incomparable_mutations = total_mutations - trivial_variations_count
        conclusion = (
            f"No Efficacy Improvement Measured: {trivial_variations_count} of {total_mutations} "
            f"runtime mutations had the same verified outcome as their parent "
            f"({trivial_variations_count}/{total_mutations} trivial variations); "
            f"{incomparable_mutations} did not produce a comparable verified outcome. "
            f"No claim of improved security efficacy is supported by this scan."
        )
    else:
        conclusion = "No runtime mutations were executed in this scan."

    return {
        "target_info": target_info or {},
        "timestamp": datetime.now().isoformat(),
        "baseline_summary": baseline_summary,
        "mutation_summary": mutation_summary,
        "overall_summary": overall_summary,
        "trivial_variations_count": trivial_variations_count,
        "distinct_outcomes_count": distinct_outcomes_count,
        "novel_findings_count": novel_findings_count,
        "unmatched_parent_count": unmatched_parent_count,
        "duplicate_prompts_pruned": duplicate_prompts_pruned,
        "outcome_flips": outcome_flips,
        "findings": findings,
        "parent_groups": parent_groups,
        "operator_stats": operator_stats,
        "baseline_records": baseline_records,
        "mutation_records": mutation_records,
        "conclusion": conclusion,
    }


def run_comparison(
    target_mode: Optional[str] = None,
    target_id: Optional[str] = None,
    categories: Optional[List[str]] = None,
    max_mutations: int = 10,
    max_requests: Optional[int] = None,
    adapter: Optional[Any] = None,
    quiet: bool = False
) -> Dict[str, Any]:
    """
    Executes baseline suite and generated variations against the active target
    under identical authorized configuration, compiling a comparison assessment.
    Enforces candidate and total request budgets and persists report locally.
    """
    if adapter is None:
        adapter = get_active_adapter(target_id)

    if target_mode and hasattr(adapter, "set_mode"):
        adapter.set_mode(target_mode)

    active_mode = getattr(adapter, "get_mode", lambda: "STANDARD")()

    target_info = {
        "id": getattr(adapter, "target_id", target_id or "target-active"),
        "name": getattr(adapter, "name", "Active Target"),
        "provider": getattr(adapter, "provider", "unknown"),
        "model": getattr(adapter, "model", "default"),
        "mode": active_mode,
        "canaries": getattr(adapter, "canaries", []),
    }

    # 1. Assemble baseline attacks
    all_baseline = generate_attacks()
    if categories:
        baseline_pool = [b for b in all_baseline if b["category"] in categories]
    else:
        baseline_pool = all_baseline

    # Enforce request budget against baseline
    if max_requests is not None and len(baseline_pool) > max_requests:
        baseline_pool = baseline_pool[:max_requests]

    # Calculate remaining request budget for mutations
    if max_requests is not None:
        remaining_budget = max(0, max_requests - len(baseline_pool))
        effective_max_mutations = min(max_mutations, remaining_budget)
    else:
        effective_max_mutations = max_mutations

    # 2. Generate mutations from baseline pool
    seen_fps: Set[str] = set()
    for b in baseline_pool:
        seen_fps.add(normalize_prompt_for_dedup(b["prompt"]))

    gen_stats: Dict[str, int] = {}
    mutations: List[Dict[str, Any]] = []
    if effective_max_mutations > 0:
        mutations = generate_mutated_attacks(
            base_attacks=baseline_pool,
            target_info=target_info,
            categories=categories,
            max_count=effective_max_mutations,
            seen_fingerprints=seen_fps,
            stats=gen_stats,
        )

    if not quiet:
        print("========================================================================")
        print("           LLMGuard Baseline vs Mutation Comparison Scan                ")
        print(f"  Target:   {target_info['name']} ({target_info['provider'].upper()} / {target_info['model']})")
        print(f"  Mode:     {active_mode}")
        print(f"  Baseline: {len(baseline_pool)} tests | Mutations: {len(mutations)} tests")
        print("========================================================================\n")

    # 3. Execute Baseline Suite
    if not quiet:
        print("[1/2] Executing Baseline Test Suite...")
    baseline_records: List[Dict[str, Any]] = []
    for idx, b_atk in enumerate(baseline_pool, 1):
        rec = execute_test_case(adapter, b_atk, target_info=target_info)
        baseline_records.append(rec)
        if not quiet:
            print(f"  [{idx:02d}/{len(baseline_pool):02d}] {rec['test_id']:<10} {rec['verdict']:<12} | {rec['name']}")

    # 4. Execute Mutation Variations
    if not quiet:
        print("\n[2/2] Executing Runtime Mutation Variations...")
    mutation_records: List[Dict[str, Any]] = []
    for idx, m_atk in enumerate(mutations, 1):
        rec = execute_test_case(adapter, m_atk, target_info=target_info)
        mutation_records.append(rec)
        if not quiet:
            parent = rec.get("parent_test_id", "BASE")
            print(f"  [{idx:02d}/{len(mutations):02d}] {rec['test_id']:<24} {rec['verdict']:<12} (Parent: {parent}) | {rec['name']}")

    # 5. Compile Comparison Report
    report = analyze_comparison_records(
        baseline_records=baseline_records,
        mutation_records=mutation_records,
        target_info=target_info,
        duplicate_prompts_pruned=gen_stats.get("duplicate_prompts_pruned", 0)
    )

    # 6. Persist comparison report locally
    save_comparison_report(report)

    if not quiet:
        print("\n" + format_comparison_report(report))

    return report


def format_comparison_report(report: Dict[str, Any]) -> str:
    """Formats comparison report into clean readable output."""
    target_info = report.get("target_info", {})
    t_name = target_info.get("name", "Target")
    t_prov = target_info.get("provider", "unknown").upper()
    t_model = target_info.get("model", "default")
    t_mode = target_info.get("mode", "STANDARD")

    b_sum = report["baseline_summary"]
    m_sum = report["mutation_summary"]
    o_sum = report["overall_summary"]

    lines = []
    lines.append("========================================================================")
    lines.append("            LLMGuard Baseline vs Mutation Comparison Report            ")
    lines.append("========================================================================")
    lines.append(f"Target:   {t_name} ({t_prov} / {t_model})")
    lines.append(f"Mode:     {t_mode}")
    lines.append(f"Date:     {report.get('timestamp', '')[:19]}")
    lines.append("")
    lines.append(f"{'METRIC':<30} {'BASELINE':<12} {'MUTATIONS':<12} {'OVERALL':<12}")
    lines.append("-" * 72)
    lines.append(f"{'Total Tests Executed':<30} {b_sum['total_executed']:<12} {m_sum['total_executed']:<12} {o_sum['total_executed']:<12}")
    lines.append(f"{'Confirmed Findings (Vuln)':<30} {b_sum['confirmed_findings']:<12} {m_sum['confirmed_findings']:<12} {o_sum['confirmed_findings']:<12}")
    lines.append(f"{'Safe Refusals / Defenses':<30} {b_sum['safe_count']:<12} {m_sum['safe_count']:<12} {o_sum['safe_count']:<12}")
    lines.append(f"{'Inconclusive Outcomes':<30} {b_sum['inconclusive_count']:<12} {m_sum['inconclusive_count']:<12} {o_sum['inconclusive_count']:<12}")
    lines.append(f"{'Target / Network Errors':<30} {b_sum['target_errors']:<12} {m_sum['target_errors']:<12} {o_sum['target_errors']:<12}")
    lines.append(f"{'Finding Rate':<30} {b_sum['finding_rate_pct']:>5.1f}%       {m_sum['finding_rate_pct']:>5.1f}%       {o_sum['finding_rate_pct']:>5.1f}%")
    lines.append("-" * 72)
    lines.append(f"Trivial Variations (Same Outcome):   {report['trivial_variations_count']:>2} / {m_sum['total_executed']:>2}")
    lines.append(f"Distinct Outcomes (Outcome Shift):   {report['distinct_outcomes_count']:>2} / {m_sum['total_executed']:>2}")
    lines.append(f"Novel Vulnerabilities Discovered:    {report['novel_findings_count']:>2}")
    if report.get("unmatched_parent_count", 0) > 0:
        lines.append(f"Unmatched / Error Parent Tests:      {report['unmatched_parent_count']:>2}")
    lines.append(f"Duplicate Prompts Pruned:            {report['duplicate_prompts_pruned']:>2}")
    lines.append("========================================================================")

    # Lineage / Parent Grouping Breakdown
    parent_groups = report.get("parent_groups", {})
    if parent_groups:
        lines.append("\nParent Test Lineage & Outcome Stability")
        lines.append("-" * 72)
        lines.append(f"{'Parent ID':<10} {'Baseline':<12} {'Mutations':<12} {'Distinct':<10} {'Novel Vuln':<10}")
        lines.append("-" * 72)
        for p_id, p_info in parent_groups.items():
            mut_count = len(p_info["mutations"])
            distinct = p_info["distinct_outcomes_count"]
            novel = p_info["novel_findings_count"]
            lines.append(f"{p_id:<10} {p_info['baseline_verdict']:<12} {mut_count:<12} {distinct:<10} {novel:<10}")
        lines.append("-" * 72)

    # Mutation Operator Breakdown
    op_stats = report.get("operator_stats", {})
    if op_stats:
        lines.append("\nMutation Operator Effectiveness Breakdown")
        lines.append("-" * 72)
        lines.append(f"{'Operator ID':<16} {'Family':<20} {'Tests':<6} {'Vuln':<6} {'Distinct':<10} {'Novel Vuln':<10}")
        lines.append("-" * 72)
        for op_id, s in op_stats.items():
            lines.append(f"{s['operator_id']:<16} {s['mutation_type']:<20} {s['total_executed']:<6} {s['confirmed_findings']:<6} {s['distinct_outcomes']:<10} {s['novel_findings']:<10}")
        lines.append("-" * 72)

    # Outcome Flips if any
    flips = report.get("outcome_flips", [])
    if flips:
        lines.append("\nOutcome Shift Details:")
        for f in flips:
            lines.append(f"  - {f['mutation_id']} ({f['operator']}): {f['baseline_verdict']} -> {f['mutation_verdict']}")
            lines.append(f"    Evidence: {f['mutation_detail']}")

    # Structured Findings Details
    findings = report.get("findings", [])
    if findings:
        lines.append("\nConfirmed Vulnerability Findings Details:")
        lines.append("-" * 72)
        for idx, f in enumerate(findings, 1):
            novel_tag = " [NOVEL MUTATION FINDING]" if f.get("is_novel_finding") else ""
            lines.append(f"  [{idx}] {f['finding_id']}{novel_tag}")
            lines.append(f"      Test ID: {f['test_id']} (Parent: {f.get('parent_test_id') or 'N/A'}, Operator: {f.get('mutation_operator') or 'N/A'})")
            lines.append(f"      Target: {f['target_name']} ({f['provider'].upper()} / {f['model']})")
            if f.get("matched_canary"):
                lines.append(f"      Matched Canary: {f['matched_canary']}")
            if f.get("matched_rule"):
                lines.append(f"      Detection Rule: {f['matched_rule']}")
            lines.append(f"      Latency: {f.get('latency_ms')}ms | Reason: {f['reason']}")
            if f.get("response_excerpt"):
                lines.append(f"      Evidence Excerpt: \"{f['response_excerpt']}\"")
            lines.append("")
        lines.append("-" * 72)

    lines.append("\nAnalytical Conclusion:")
    lines.append(f"  {report['conclusion']}")
    lines.append("========================================================================")

    return "\n".join(lines)


def print_comparison_report(report: Dict[str, Any]):
    """Prints the formatted comparison report to stdout."""
    print(format_comparison_report(report))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="LLMGuard Baseline vs Mutation Comparison Mode")
    parser.add_argument("--mode", choices=["SECURE", "VULNERABLE"], help="TechMart mode")
    parser.add_argument("--target", help="Target ID")
    parser.add_argument("--max-mutations", type=int, default=10, help="Max mutations")
    parser.add_argument("--categories", nargs="+", help="Categories")
    args = parser.parse_args()

    run_comparison(
        target_mode=args.mode,
        target_id=args.target,
        max_mutations=args.max_mutations,
        categories=args.categories,
    )
