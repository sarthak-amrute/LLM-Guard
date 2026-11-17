"""Comparison and aggregate metrics derived exclusively from persisted scans."""

from typing import Any, Dict, List, Optional, Tuple
import re

from comparison import _verified_verdict
from scan_history import ScanHistoryStore


def _record_id(record: Dict[str, Any]) -> Optional[str]:
    value = record.get("test_id") or record.get("id")
    return str(value) if value else None


def _test_signature(record: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        record.get("category"),
        record.get("generation_method", "predefined"),
        record.get("parent_test_id"),
        record.get("mutation_operator"),
        record.get("normalized_hash") or record.get("prompt"),
    )


def _prompt_key(record: Dict[str, Any]) -> Optional[str]:
    fingerprint = record.get("normalized_hash")
    if isinstance(fingerprint, str) and fingerprint:
        return fingerprint
    prompt = record.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return None
    return re.sub(r"[^a-z0-9]", "", prompt.casefold())


def _findings_by_test(scan: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(finding.get("test_id")): finding
        for finding in scan.get("findings", [])
        if finding.get("test_id")
    }


def compare_scans(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    baseline_canaries = baseline.get("target_info", {}).get("canaries")
    current_canaries = current.get("target_info", {}).get("canaries")

    def baseline_verdict(record: Optional[Dict[str, Any]]) -> str:
        return _verified_verdict(record, baseline_canaries) if record else "MISSING_PARENT"

    def current_verdict(record: Optional[Dict[str, Any]]) -> str:
        return _verified_verdict(record, current_canaries) if record else "MISSING_PARENT"

    baseline_target = {
        "target_id": baseline.get("target_id"),
        "provider": baseline.get("provider"),
        "model": baseline.get("model"),
        "mode": baseline.get("mode"),
        "target_revision": baseline.get("configuration", {}).get("target_revision"),
    }
    current_target = {
        "target_id": current.get("target_id"),
        "provider": current.get("provider"),
        "model": current.get("model"),
        "mode": current.get("mode"),
        "target_revision": current.get("configuration", {}).get("target_revision"),
    }
    context_matches = baseline_target == current_target and baseline_target["target_id"] is not None
    before = {
        _record_id(record): record
        for record in baseline.get("results", [])
        if _record_id(record)
    }
    after = {
        _record_id(record): record
        for record in current.get("results", [])
        if _record_id(record)
    }
    before_findings = _findings_by_test(baseline)
    after_findings = _findings_by_test(current)

    comparable_tests: List[str] = []
    not_comparable: List[Dict[str, Any]] = []
    outcome_changes: List[Dict[str, Any]] = []
    category_stats: Dict[str, Dict[str, int]] = {}
    mutation_totals = {"baseline": {"successful": 0, "comparable": 0}, "current": {"successful": 0, "comparable": 0}}

    if context_matches:
        for test_id in sorted(set(before) & set(after)):
            old_record, new_record = before[test_id], after[test_id]
            if _test_signature(old_record) != _test_signature(new_record):
                not_comparable.append({"test_id": test_id, "reason": "test_definition_changed"})
                continue
            old_verdict = baseline_verdict(old_record)
            new_verdict = current_verdict(new_record)
            if old_verdict not in ("SAFE", "VULNERABLE") or new_verdict not in ("SAFE", "VULNERABLE"):
                not_comparable.append({
                    "test_id": test_id,
                    "reason": "inconclusive_or_error",
                    "baseline_verdict": old_verdict,
                    "current_verdict": new_verdict,
                })
                continue
            comparable_tests.append(test_id)
            category = new_record.get("category") or "Uncategorized"
            stats = category_stats.setdefault(category, {
                "comparable_tests": 0,
                "baseline_safe": 0,
                "current_safe": 0,
                "baseline_vulnerable": 0,
                "current_vulnerable": 0,
            })
            stats["comparable_tests"] += 1
            stats[f"baseline_{old_verdict.lower()}"] += 1
            stats[f"current_{new_verdict.lower()}"] += 1
            if old_verdict != new_verdict:
                outcome_changes.append({
                    "test_id": test_id,
                    "category": category,
                    "baseline_verdict": old_verdict,
                    "current_verdict": new_verdict,
                })

            if new_record.get("generation_method") == "mutation":
                parent = before.get(str(new_record.get("parent_test_id")))
                current_parent = after.get(str(new_record.get("parent_test_id")))
                old_parent_verdict = baseline_verdict(parent)
                new_parent_verdict = current_verdict(current_parent)
                if (
                    old_parent_verdict in ("SAFE", "VULNERABLE")
                    and new_parent_verdict in ("SAFE", "VULNERABLE")
                    and old_verdict in ("SAFE", "VULNERABLE")
                    and new_verdict in ("SAFE", "VULNERABLE")
                ):
                    mutation_totals["baseline"]["comparable"] += 1
                    mutation_totals["current"]["comparable"] += 1
                    mutation_totals["baseline"]["successful"] += int(old_parent_verdict == "SAFE" and old_verdict == "VULNERABLE")
                    mutation_totals["current"]["successful"] += int(new_parent_verdict == "SAFE" and new_verdict == "VULNERABLE")

    persistent_findings: List[Dict[str, Any]] = []
    not_reproduced_findings: List[Dict[str, Any]] = []
    not_tested_findings: List[Dict[str, Any]] = []
    for test_id, old_finding in before_findings.items():
        old_record, new_record = before.get(test_id), after.get(test_id)
        if not context_matches or not new_record:
            not_tested_findings.append({
                "finding": old_finding,
                "reason": "target_context_changed" if not context_matches else "test_not_present",
            })
            continue
        if _test_signature(old_record) != _test_signature(new_record):
            not_tested_findings.append({"finding": old_finding, "reason": "test_definition_changed"})
            continue
        new_verdict = current_verdict(new_record)
        if new_verdict == "VULNERABLE":
            new_finding = after_findings.get(test_id)
            if new_finding and (
                old_finding.get("matched_rule"), old_finding.get("matched_canary")
            ) == (
                new_finding.get("matched_rule"), new_finding.get("matched_canary")
            ):
                persistent_findings.append({
                    "baseline_finding": old_finding,
                    "current_finding": new_finding,
                })
            else:
                not_reproduced_findings.append({
                    "finding": old_finding,
                    "reason": "finding_signature_changed",
                })
        elif new_verdict == "SAFE":
            not_reproduced_findings.append({
                "finding": old_finding,
                "reason": "equivalent_test_safe_on_current_run",
            })
        else:
            not_tested_findings.append({"finding": old_finding, "reason": "current_test_error_or_inconclusive"})

    new_findings: List[Dict[str, Any]] = []
    current_only_findings = []
    for test_id, finding in after_findings.items():
        if test_id in before_findings:
            if not any(item.get("current_finding") == finding for item in persistent_findings):
                old_record, new_record = before.get(test_id), after.get(test_id)
                if context_matches and old_record and new_record and _test_signature(old_record) == _test_signature(new_record):
                    if baseline_verdict(old_record) == "SAFE" and current_verdict(new_record) == "VULNERABLE":
                        new_findings.append({"finding": finding, "basis": "equivalent_test_outcome_changed"})
            continue
        current_only_findings.append(finding)
        new_findings.append({
            "finding": finding,
            "basis": "new_test_coverage" if test_id not in before else "incomparable_test",
        })

    before_ids, after_ids = set(before), set(after)
    common_coverage = set(comparable_tests)
    baseline_prompt_coverage = {
        key for record in before.values() if (key := _prompt_key(record)) is not None
    }
    current_prompt_coverage = {
        key for record in after.values() if (key := _prompt_key(record)) is not None
    }
    comparable_prompt_coverage = {
        key for test_id in comparable_tests
        if (key := _prompt_key(after[test_id])) is not None
    }
    baseline_rate = (
        mutation_totals["baseline"]["successful"] / mutation_totals["baseline"]["comparable"] * 100
        if mutation_totals["baseline"]["comparable"] else None
    )
    current_rate = (
        mutation_totals["current"]["successful"] / mutation_totals["current"]["comparable"] * 100
        if mutation_totals["current"]["comparable"] else None
    )

    return {
        "baseline_id": baseline.get("scan_id"),
        "current_id": current.get("scan_id"),
        "target_context_matches": context_matches,
        "target_context": {"baseline": baseline_target, "current": current_target},
        "security_posture_conclusion": "NOT_DETERMINED",
        "interpretation_note": (
            "A finding that is not reproduced is not proof that the vulnerability was fixed. "
            "Only equivalent, successfully evaluated tests are compared."
        ),
        "totals": {
            "baseline_findings": len(baseline.get("findings", [])),
            "current_findings": len(current.get("findings", [])),
            "baseline_executions": len(before),
            "current_executions": len(after),
            "comparable_executions": len(comparable_tests),
        },
        "new_findings": new_findings,
        "persistent_findings": persistent_findings,
        "not_reproduced_findings": not_reproduced_findings,
        "resolved_findings": [],
        "not_tested_findings": not_tested_findings,
        "outcome_changes": outcome_changes,
        "category_changes": category_stats,
        "coverage": {
            "baseline_tests": len(before_ids),
            "current_tests": len(after_ids),
            "comparable_tests": len(common_coverage),
            "added_tests": sorted(after_ids - before_ids),
            "removed_tests": sorted(before_ids - after_ids),
            "not_comparable_tests": not_comparable,
            "baseline_unique_prompts": len(baseline_prompt_coverage),
            "current_unique_prompts": len(current_prompt_coverage),
            "comparable_unique_prompts": len(comparable_prompt_coverage),
        },
        "mutation_effectiveness": {
            "baseline": {
                **mutation_totals["baseline"],
                "success_rate_pct": round(baseline_rate, 1) if baseline_rate is not None else None,
            },
            "current": {
                **mutation_totals["current"],
                "success_rate_pct": round(current_rate, 1) if current_rate is not None else None,
            },
        },
        "errors": {
            "baseline": sum(record.get("verdict") == "TARGET_ERROR" for record in before.values()),
            "current": sum(record.get("verdict") == "TARGET_ERROR" for record in after.values()),
            "incomplete_baseline_tests": max(0, baseline.get("summary", {}).get("expected_executions", len(before)) - len(before)),
            "incomplete_current_tests": max(0, current.get("summary", {}).get("expected_executions", len(after)) - len(after)),
        },
    }


def analytics_overview(store: ScanHistoryStore) -> Dict[str, Any]:
    scans = store.all_scans()
    completed = [scan for scan in scans if scan["status"] == "COMPLETED"]
    total_executions = 0
    unique_prompt_executions = 0
    confirmed_findings = 0
    safe = vulnerable = errors = inconclusive = 0
    mutation_successful = mutation_comparable = 0
    categories: Dict[str, Dict[str, int]] = {}
    for scan in scans:
        details = store.get_scan(scan["scan_id"])
        if not details:
            continue
        records = details.get("results", [])
        total_executions += len(records)
        unique_prompt_executions += len({
            key for record in records if (key := _prompt_key(record)) is not None
        })
        for record in records:
            verdict = _verified_verdict(record, details.get("target_info", {}).get("canaries"))
            if verdict == "SAFE":
                safe += 1
            elif verdict == "VULNERABLE":
                vulnerable += 1
            elif verdict == "TARGET_ERROR":
                errors += 1
            else:
                inconclusive += 1
            category = record.get("category") or "Uncategorized"
            stat = categories.setdefault(category, {"executions": 0, "safe": 0, "vulnerable": 0, "errors": 0, "inconclusive": 0})
            stat["executions"] += 1
            stat[verdict.lower() if verdict != "TARGET_ERROR" else "errors"] += 1
        confirmed_findings += len(details.get("findings", []))
        canaries = details.get("target_info", {}).get("canaries")
        for group in details.get("comparison", {}).get("parent_groups", {}).values():
            parent_verdict = group.get("baseline_verdict")
            if parent_verdict not in ("SAFE", "VULNERABLE"):
                continue
            for mutation in group.get("mutations", []):
                verdict = _verified_verdict(mutation, canaries)
                if verdict in ("SAFE", "VULNERABLE"):
                    mutation_comparable += 1
                    mutation_successful += int(parent_verdict == "SAFE" and verdict == "VULNERABLE")

    latest = scans[-1] if scans else None
    average_findings = (
        sum(scan.get("finding_count", 0) for scan in completed) / len(completed)
        if completed else None
    )
    return {
        "total_scans": len(scans),
        "completed_scans": len(completed),
        "total_executions": total_executions,
        "unique_prompt_executions": unique_prompt_executions,
        "confirmed_vulnerabilities": confirmed_findings,
        "latest_scan_status": latest.get("status") if latest else None,
        "latest_scan_id": latest.get("scan_id") if latest else None,
        "average_findings_per_completed_scan": round(average_findings, 2) if average_findings is not None else None,
        "outcomes": {"safe": safe, "vulnerable": vulnerable, "errors": errors, "inconclusive": inconclusive},
        "execution_success_rate_pct": round((safe + vulnerable) / total_executions * 100, 1) if total_executions else None,
        "mutation_effectiveness": {
            "successful": mutation_successful,
            "comparable": mutation_comparable,
            "success_rate_pct": round(mutation_successful / mutation_comparable * 100, 1) if mutation_comparable else None,
        },
        "categories": categories,
    }


def analytics_trends(store: ScanHistoryStore) -> Dict[str, Any]:
    scans = store.all_scans()
    points = []
    for scan in scans:
        if scan["status"] != "COMPLETED":
            continue
        details = store.get_scan(scan["scan_id"])
        if not details:
            continue
        results = details.get("results", [])
        summary = details.get("summary", {})
        canaries = details.get("target_info", {}).get("canaries")
        points.append({
            "scan_id": scan["scan_id"],
            "created_at": scan["created_at"],
            "target_id": scan["target_id"],
            "findings": len(details.get("findings", [])),
            "executions": len(results),
            "unique_prompts": len({
                key for record in results if (key := _prompt_key(record)) is not None
            }),
            "safe": sum(_verified_verdict(record, canaries) == "SAFE" for record in results),
            "vulnerable": sum(_verified_verdict(record, canaries) == "VULNERABLE" for record in results),
            "errors": sum(record.get("verdict") == "TARGET_ERROR" for record in results),
            "expected_executions": summary.get("expected_executions", len(results)),
        })
    return {
        "trend_available": len(points) >= 2,
        "insufficient_data_message": None if len(points) >= 2 else "Not enough completed scans to calculate a security trend.",
        "scans": points,
    }


def analytics_categories(store: ScanHistoryStore) -> Dict[str, Any]:
    overview = analytics_overview(store)
    return {"categories": overview["categories"]}
