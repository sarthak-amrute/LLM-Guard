"""Regression tests for SQLite scan history, comparisons, and analytics."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from comparison import analyze_comparison_records
from scan_analytics import analytics_overview, compare_scans
from scan_history import ScanHistoryStore
import server


CANARY = "TM-SECRET-938472"
SAFE_RESPONSE = "I cannot disclose confidential information."
SAFE_REASON = "Target model issued an explicit safety refusal to the adversarial directive."
VULNERABLE_RESPONSE = f"The protected value is {CANARY}."
VULNERABLE_REASON = f"Confirmed canary token disclosed: {CANARY}"


def execution(test_id, verdict="SAFE", generation_method="predefined", parent_test_id=None, prompt=None):
    response = SAFE_RESPONSE if verdict == "SAFE" else VULNERABLE_RESPONSE
    detail = SAFE_REASON if verdict == "SAFE" else VULNERABLE_REASON
    if verdict == "TARGET_ERROR":
        response, detail = "[ERROR] Provider timeout", "Infrastructure / Target error: Provider timeout"
    return {
        "id": test_id,
        "test_id": test_id,
        "parent_test_id": parent_test_id,
        "category": "Direct Prompt Injection",
        "name": test_id,
        "generation_method": generation_method,
        "mutation_operator": "WORD_FORMAL" if generation_method == "mutation" else None,
        "prompt": prompt or f"Prompt for {test_id}",
        "normalized_hash": f"hash-{test_id}",
        "response": response,
        "verdict": verdict,
        "detail": detail,
        "timestamp": "2026-10-30T10:00:00",
    }


def completed_scan(store, scan_id, records, model="fixture-v1", mode="SECURE", created_at="2026-10-30T10:00:00", target_revision="rev-1"):
    target_info = {
        "id": "target-1",
        "name": "Fixture Target",
        "provider": "fixture",
        "model": model,
        "mode": mode,
        "target_revision": target_revision,
        "canaries": [CANARY],
    }
    store.create_scan(
        scan_id,
        target_info=target_info,
        mode=mode,
        configuration={"target_revision": target_revision},
        created_at=created_at,
    )
    store.update_scan_metadata(
        scan_id,
        target_info,
        mode,
        {"target_revision": target_revision, "categories": ["Direct Prompt Injection"]},
    )
    for record in records:
        store.add_execution(scan_id, record)
    baselines = [record for record in records if record["generation_method"] == "predefined"]
    mutations = [record for record in records if record["generation_method"] == "mutation"]
    report = analyze_comparison_records(
        baselines,
        mutations,
        target_info=target_info,
    )
    report["scan_id"] = scan_id
    summary = {
        "total_executed": len(records),
        "expected_executions": len(records),
        "incomplete_executions": 0,
        "confirmed_findings": len(report["findings"]),
        "SAFE": sum(record["verdict"] == "SAFE" for record in records),
        "VULNERABLE": sum(record["verdict"] == "VULNERABLE" for record in records),
        "TARGET_ERROR": sum(record["verdict"] == "TARGET_ERROR" for record in records),
    }
    store.finish_scan(scan_id, "COMPLETED", summary, report, completed_at=created_at)
    return store.get_scan(scan_id)


class TestScanHistoryStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.temp_dir.name, "history.sqlite3")
        self.store = ScanHistoryStore(self.database)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_multiple_scans_roundtrip_after_reopening_database(self):
        first = completed_scan(self.store, "SCAN-001", [execution("DPI-001")])
        completed_scan(self.store, "SCAN-002", [
            execution("DPI-001"),
            execution("DPI-001-MUT-WORD_FORMAL", "VULNERABLE", "mutation", "DPI-001"),
        ])
        reopened = ScanHistoryStore(self.database)
        history = reopened.list_scans(page=1, page_size=10)
        self.assertEqual(history["total"], 2)
        self.assertEqual(first["scan_id"], "SCAN-001")
        second = reopened.get_scan("SCAN-002")
        self.assertEqual(second["status"], "COMPLETED")
        self.assertEqual(len(second["findings"]), 1)
        self.assertEqual(second["findings"][0]["parent_test_id"], "DPI-001")

    def test_duplicate_executions_are_ignored_and_completed_scans_are_immutable(self):
        self.store.create_scan("SCAN-DEDUP")
        record = execution("DPI-001")
        self.assertTrue(self.store.add_execution("SCAN-DEDUP", record))
        self.assertFalse(self.store.add_execution("SCAN-DEDUP", record))
        self.assertTrue(self.store.finish_scan("SCAN-DEDUP", "COMPLETED", {}, {}))
        self.assertFalse(self.store.add_execution("SCAN-DEDUP", execution("DPI-002")))
        self.assertFalse(self.store.finish_scan("SCAN-DEDUP", "FAILED", {}, {}))
        self.assertEqual(len(self.store.get_scan("SCAN-DEDUP")["results"]), 1)

    def test_running_and_failed_scans_remain_identifiable(self):
        self.store.create_scan("SCAN-RUNNING")
        self.assertEqual(self.store.get_scan("SCAN-RUNNING")["status"], "RUNNING")
        self.store.create_scan("SCAN-FAILED")
        self.assertTrue(self.store.fail_scan("SCAN-FAILED", "Provider unavailable"))
        failed = self.store.get_scan("SCAN-FAILED")
        self.assertEqual(failed["status"], "FAILED")
        self.assertIn("Provider unavailable", failed["error"])
        self.assertEqual(self.store.recover_interrupted_scans(), 1)
        self.assertEqual(self.store.get_scan("SCAN-RUNNING")["status"], "FAILED")

    def test_credentials_are_redacted_from_scan_payloads(self):
        self.store.create_scan(
            "SCAN-SECRET",
            configuration={"api_key": "do-not-store", "safe_setting": True},
            target_info={"id": "t1", "authorization": "token-do-not-store"},
        )
        self.store.add_execution("SCAN-SECRET", {
            **execution("DPI-001"),
            "request_headers": {"Authorization": "token-do-not-store"},
        })
        stored = self.store.get_scan("SCAN-SECRET")
        serialized = json.dumps(stored)
        self.assertNotIn("do-not-store", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_completion_does_not_persist_a_finding_without_matching_execution_evidence(self):
        self.store.create_scan("SCAN-UNVERIFIED")
        record = execution("DPI-001")
        self.store.add_execution("SCAN-UNVERIFIED", record)
        forged_finding = {
            "finding_id": "FINDING-DPI-001",
            "test_id": "DPI-001",
            "generation_method": "predefined",
            "parent_test_id": None,
            "raw_response": record["response"],
            "reason": VULNERABLE_REASON,
            "matched_canary": CANARY,
            "matched_rule": "plaintext_canary_disclosure",
            "evidence_verified": True,
        }
        self.assertTrue(self.store.finish_scan(
            "SCAN-UNVERIFIED",
            "COMPLETED",
            {},
            {"target_info": {"canaries": [CANARY]}, "findings": [forged_finding]},
        ))
        self.assertEqual(self.store.get_scan("SCAN-UNVERIFIED")["findings"], [])

    def test_duplicate_prompts_count_once_for_unique_history_coverage(self):
        first = execution("DPI-101")
        second = execution("DPI-102")
        first["normalized_hash"] = second["normalized_hash"] = "same-normalized-prompt"
        baseline = completed_scan(self.store, "SCAN-DUP-OLD", [first, second])
        current = completed_scan(self.store, "SCAN-DUP-NEW", [first, second])
        comparison = compare_scans(baseline, current)
        overview = analytics_overview(self.store)
        self.assertEqual(comparison["totals"]["comparable_executions"], 2)
        self.assertEqual(comparison["coverage"]["comparable_unique_prompts"], 1)
        self.assertEqual(overview["total_executions"], 4)
        self.assertEqual(overview["unique_prompt_executions"], 2)

    def test_pagination_and_filters(self):
        completed_scan(self.store, "SCAN-OLD", [execution("DPI-001")], created_at="2026-10-28T10:00:00")
        completed_scan(self.store, "SCAN-NEW", [execution("DPI-001")], created_at="2026-10-30T10:00:00")
        page = self.store.list_scans(page=1, page_size=1, status="COMPLETED", target_id="target-1")
        self.assertEqual(page["total"], 2)
        self.assertEqual(page["scans"][0]["scan_id"], "SCAN-NEW")
        date_page = self.store.list_scans(start_date="2026-10-29T00:00:00")
        self.assertEqual(date_page["total"], 1)
        search_page = self.store.list_scans(scan_id_search="new")
        self.assertEqual([scan["scan_id"] for scan in search_page["scans"]], ["SCAN-NEW"])
        wildcard_page = self.store.list_scans(scan_id_search="%")
        self.assertEqual(wildcard_page["total"], 0)


class TestScanHistoryApi(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = ScanHistoryStore(os.path.join(self.temp_dir.name, "api.sqlite3"))
        self.patch_store = patch.object(server, "scan_history_store", self.store)
        self.patch_store.start()
        self.client = TestClient(server.app)
        completed_scan(self.store, "API-OLD", [
            execution("DPI-001"),
            execution("DPI-001-MUT-WORD_FORMAL", "SAFE", "mutation", "DPI-001"),
        ], created_at="2026-10-29T10:00:00")
        completed_scan(self.store, "API-NEW", [
            execution("DPI-001"),
            execution("DPI-001-MUT-WORD_FORMAL", "VULNERABLE", "mutation", "DPI-001"),
        ], created_at="2026-10-30T10:00:00")

    def tearDown(self):
        self.patch_store.stop()
        self.temp_dir.cleanup()

    def test_history_pagination_and_status_filter(self):
        response = self.client.get("/api/scans?page=1&page_size=1&status=COMPLETED")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 2)
        self.assertEqual(response.json()["scans"][0]["scan_id"], "API-NEW")
        self.assertEqual(
            self.client.get("/api/scans?status=INVALID").status_code,
            422,
        )
        searched = self.client.get("/api/scans?scan_id_search=NEW")
        self.assertEqual([scan["scan_id"] for scan in searched.json()["scans"]], ["API-NEW"])

    def test_stop_scan_endpoint_requests_cooperative_cancellation(self):
        state = dict(server._state)
        state.update({"status": "running", "scan_id": "API-RUNNING", "stop_requested": False})
        server._scan_stop_event.clear()
        try:
            with patch.object(server, "_state", state):
                response = self.client.post("/api/scan/stop")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["status"], "stop_requested")
                self.assertTrue(server._scan_stop_event.is_set())
                status = self.client.get("/api/scan/status").json()
                self.assertTrue(status["stop_requested"])
            with patch.object(server, "_state", {**state, "status": "idle"}):
                self.assertEqual(self.client.post("/api/scan/stop").status_code, 409)
        finally:
            server._scan_stop_event.clear()

    def test_scan_results_after_restart_prefer_recovered_history_over_stale_json(self):
        running_store = ScanHistoryStore(os.path.join(self.temp_dir.name, "restart.sqlite3"))
        running_store.create_scan(
            "RESTART-01",
            target_info={"id": "target-1", "name": "Fixture Target", "provider": "fixture"},
        )
        running_store.add_execution("RESTART-01", execution("DPI-001"))
        stale_file = os.path.join(self.temp_dir.name, "latest_scan.json")
        with open(stale_file, "w", encoding="utf-8") as file:
            json.dump({"status": "running", "scan_id": "STALE", "results": []}, file)
        running_store.recover_interrupted_scans()
        idle_state = {
            "status": "idle", "scan_id": None, "started_at": None,
            "completed_at": None, "target_info": None, "mode": None,
            "total": 0, "completed": 0, "current_attack": None,
            "results": [], "summary": {"SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
            "category_stats": {}, "generation_stats": {}, "vulnerable_cases": [],
        }
        with patch.object(server, "scan_history_store", running_store):
            with patch.object(server, "_state", idle_state):
                with patch.object(server, "_SCAN_STORAGE_FILE", stale_file):
                    response = self.client.get("/api/scan/results")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scan_id"], "RESTART-01")
        self.assertEqual(response.json()["status"], "error")
        self.assertEqual(response.json()["results"][0]["test_id"], "DPI-001")
        self.assertEqual(running_store.get_scan("RESTART-01")["status"], "FAILED")

    def test_details_findings_and_invalid_scan(self):
        detail = self.client.get("/api/scans/API-NEW")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["results"][1]["parent_test_id"], "DPI-001")
        findings = self.client.get("/api/scans/API-NEW/findings")
        self.assertEqual(findings.status_code, 200)
        self.assertEqual(findings.json()["total"], 1)
        self.assertEqual(findings.json()["findings"][0]["parent_test_id"], "DPI-001")
        self.assertEqual(self.client.get("/api/scans/missing-scan").status_code, 404)
        self.assertEqual(self.client.get("/api/scans/missing-scan/findings").status_code, 404)

    def test_compare_api_uses_history_and_marks_safe_as_not_reproduced(self):
        response = self.client.get(
            "/api/scans/compare?baseline_id=API-NEW&current_id=API-OLD"
        )
        self.assertEqual(response.status_code, 200)
        comparison = response.json()
        self.assertTrue(comparison["target_context_matches"])
        self.assertEqual(len(comparison["not_reproduced_findings"]), 1)
        self.assertEqual(comparison["resolved_findings"], [])
        self.assertIn("not proof", comparison["interpretation_note"])
        self.assertEqual(self.client.get("/api/scans/compare?baseline_id=missing&current_id=API-OLD").status_code, 404)

    def test_analytics_are_derived_from_saved_scans(self):
        overview = self.client.get("/api/analytics/overview").json()
        trends = self.client.get("/api/analytics/trends").json()
        categories = self.client.get("/api/analytics/categories").json()
        self.assertEqual(overview["total_scans"], 2)
        self.assertEqual(overview["total_executions"], 4)
        self.assertEqual(overview["confirmed_vulnerabilities"], 1)
        self.assertEqual(overview["outcomes"]["vulnerable"], 1)
        self.assertEqual(len(trends["scans"]), 2)
        self.assertTrue(trends["trend_available"])
        self.assertEqual(categories["categories"]["Direct Prompt Injection"]["executions"], 4)

    def test_invalid_date_range_is_rejected(self):
        response = self.client.get("/api/scans?start_date=2026-10-30&end_date=2026-10-29")
        self.assertEqual(response.status_code, 422)


class TestScanCancellation(unittest.TestCase):
    def test_worker_stops_after_current_request_and_persists_partial_scan(self):
        temp_dir = tempfile.TemporaryDirectory()
        store = ScanHistoryStore(os.path.join(temp_dir.name, "cancel.sqlite3"))
        scan_id = "CANCEL-01"
        store.create_scan(scan_id, target_info={"id": "cancel-target"})
        state = dict(server._state)
        state.update({
            "status": "running",
            "scan_id": scan_id,
            "results": [],
            "summary": {"SAFE": 0, "VULNERABLE": 0, "TARGET_ERROR": 0},
            "category_stats": {},
            "generation_stats": {},
            "vulnerable_cases": [],
        })

        class FixtureAdapter:
            target_id = "cancel-target"
            name = "Cancellation Fixture"
            provider = "fixture"
            model = "fixture-v1"
            canaries = []

            def get_mode(self):
                return "SECURE"

            def send_message(self, _prompt):
                server.api_stop_scan()
                return SAFE_RESPONSE, 1

        target = {
            "id": "cancel-target",
            "name": "Cancellation Fixture",
            "provider": "fixture",
            "model": "fixture-v1",
            "authorization_confirmed": True,
            "canaries": [],
        }
        attacks = [
            {
                "id": "BASE-001",
                "category": "Fixture",
                "name": "First request",
                "objective": "Test cooperative stop.",
                "prompt": "first",
                "generation_method": "predefined",
            },
            {
                "id": "BASE-002",
                "category": "Fixture",
                "name": "Next request",
                "objective": "Must not run.",
                "prompt": "second",
                "generation_method": "predefined",
            },
        ]
        server._scan_stop_event.clear()
        try:
            with patch.object(server, "scan_history_store", store):
                with patch.object(server, "_state", state):
                    with patch.object(server.target_storage, "get_active_target", return_value=target):
                        with patch.object(server, "create_adapter", return_value=FixtureAdapter()):
                            with patch.object(server, "generate_runtime_suite", return_value=attacks):
                                with patch.object(server, "_persist_scan_state"):
                                    with patch("comparison.save_comparison_report"):
                                        server._run_scan()
            self.assertEqual(state["status"], "cancelled")
            self.assertEqual([item["test_id"] for item in state["results"]], ["BASE-001"])
            persisted = store.get_scan(scan_id)
            self.assertEqual(persisted["status"], "CANCELLED")
            self.assertEqual(len(persisted["results"]), 1)
            self.assertEqual(persisted["summary"]["incomplete_executions"], 1)
        finally:
            server._scan_stop_event.clear()
            temp_dir.cleanup()


class TestHistoricalComparisonSemantics(unittest.TestCase):
    def test_custom_canary_is_verified_using_each_scan_target_context(self):
        custom_canary = "CUSTOM-SECRET-57"
        parent = execution("DPI-001")
        baseline_mutation = execution("MUT-CUSTOM", "SAFE", "mutation", "DPI-001")
        current_mutation = execution("MUT-CUSTOM", "VULNERABLE", "mutation", "DPI-001")
        current_mutation.update({
            "response": f"The protected value is {custom_canary}.",
            "detail": f"Confirmed canary token disclosed: {custom_canary}",
        })
        baseline = {
            "scan_id": "OLD",
            "target_id": "t1",
            "provider": "fixture",
            "model": "fixture-v1",
            "mode": "SECURE",
            "target_info": {"canaries": [custom_canary]},
            "configuration": {"target_revision": "rev-1"},
            "results": [parent, baseline_mutation],
            "findings": [],
        }
        current = {
            **baseline,
            "scan_id": "NEW",
            "results": [parent, current_mutation],
            "findings": [],
        }
        comparison = compare_scans(baseline, current)
        self.assertEqual(
            next(change for change in comparison["outcome_changes"] if change["test_id"] == "MUT-CUSTOM")["current_verdict"],
            "VULNERABLE",
        )

    def test_different_model_or_configuration_revision_is_incomparable(self):
        baseline = {
            "scan_id": "OLD",
            "target_id": "t1",
            "provider": "fixture",
            "model": "model-a",
            "mode": "SECURE",
            "configuration": {"target_revision": "rev-1"},
            "results": [execution("DPI-001", "VULNERABLE")],
            "findings": [{"test_id": "DPI-001", "finding_id": "FINDING-DPI-001"}],
        }
        current = {
            **baseline,
            "scan_id": "NEW",
            "model": "model-b",
            "results": [execution("DPI-001", "SAFE")],
            "findings": [],
        }
        comparison = compare_scans(baseline, current)
        self.assertFalse(comparison["target_context_matches"])
        self.assertEqual(comparison["resolved_findings"], [])
        self.assertEqual(comparison["not_tested_findings"][0]["reason"], "target_context_changed")

    def test_finding_is_only_resolved_after_no_reproduction_is_reported_as_unconfirmed(self):
        baseline = {
            "scan_id": "OLD",
            "target_id": "t1",
            "provider": "fixture",
            "model": "fixture-v1",
            "mode": "SECURE",
            "configuration": {"target_revision": "rev-1"},
            "results": [execution("DPI-001", "VULNERABLE")],
            "findings": [{"test_id": "DPI-001", "finding_id": "FINDING-DPI-001"}],
        }
        current = {
            **baseline,
            "scan_id": "NEW",
            "results": [execution("DPI-001", "SAFE")],
            "findings": [],
        }
        comparison = compare_scans(baseline, current)
        self.assertEqual(comparison["resolved_findings"], [])
        self.assertEqual(len(comparison["not_reproduced_findings"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
