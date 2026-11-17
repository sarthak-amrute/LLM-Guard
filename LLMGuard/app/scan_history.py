"""SQLite persistence for immutable LLMGuard scan history."""

import json
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from .evaluator import evaluate_response_details, extract_evidence_details
except ImportError:
    from evaluator import evaluate_response_details, extract_evidence_details


_APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATABASE_PATH = os.path.join(_APP_DIR, "data", "scan_history.sqlite3")
_SECRET_FIELD = re.compile(r"(api[_-]?key|authorization|access[_-]?token|secret|password)", re.I)
_VALID_STATUSES = {"RUNNING", "COMPLETED", "FAILED", "CANCELLED"}
_VALID_VERDICTS = {"SAFE", "VULNERABLE", "TARGET_ERROR", "INCONCLUSIVE"}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SECRET_FIELD.search(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _json_dump(value: Any) -> str:
    return json.dumps(_redact(value), separators=(",", ":"), ensure_ascii=False)


def _json_load(value: Optional[str], expected_type: type, default: Any) -> Any:
    if value is None:
        return default
    try:
        result = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default
    return result if isinstance(result, expected_type) else default


def _safe_id(scan_id: str) -> bool:
    return isinstance(scan_id, str) and 1 <= len(scan_id) <= 128 and bool(
        re.fullmatch(r"[A-Za-z0-9._-]+", scan_id)
    )


class ScanHistoryStore:
    """Parameterized SQLite repository; each operation uses its own connection."""

    def __init__(self, database_path: str = DEFAULT_DATABASE_PATH):
        self.database_path = database_path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(database_path) or ".", exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _session(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._lock, self._session() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    scan_name TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL CHECK(status IN ('RUNNING','COMPLETED','FAILED','CANCELLED')),
                    target_id TEXT,
                    target_name TEXT,
                    provider TEXT,
                    model TEXT,
                    mode TEXT,
                    configuration_json TEXT NOT NULL DEFAULT '{}',
                    summary_json TEXT NOT NULL DEFAULT '{}',
                    comparison_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT
                );
                CREATE TABLE IF NOT EXISTS scan_executions (
                    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                    test_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    verdict TEXT NOT NULL CHECK(verdict IN ('SAFE','VULNERABLE','TARGET_ERROR','INCONCLUSIVE')),
                    category TEXT,
                    generation_method TEXT,
                    mutation_operator TEXT,
                    parent_test_id TEXT,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(scan_id, test_id)
                );
                CREATE TABLE IF NOT EXISTS scan_findings (
                    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                    finding_id TEXT NOT NULL,
                    test_id TEXT NOT NULL,
                    parent_test_id TEXT,
                    finding_json TEXT NOT NULL,
                    PRIMARY KEY(scan_id, finding_id)
                );
                CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_executions_category ON scan_executions(category);
                """
            )

    def recover_interrupted_scans(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._session() as connection:
            cursor = connection.execute(
                """UPDATE scans SET status = 'FAILED', completed_at = ?,
                   error = 'Worker stopped before the scan completed.'
                   WHERE status = 'RUNNING'""",
                (now,),
            )
            return cursor.rowcount

    def create_scan(
        self,
        scan_id: str,
        configuration: Optional[Dict[str, Any]] = None,
        scan_name: Optional[str] = None,
        target_info: Optional[Dict[str, Any]] = None,
        mode: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> None:
        if not _safe_id(scan_id):
            raise ValueError("Invalid scan ID")
        target = _redact(target_info or {})
        with self._lock, self._session() as connection:
            connection.execute(
                """INSERT INTO scans (
                    scan_id, scan_name, created_at, status, target_id, target_name,
                    provider, model, mode, configuration_json
                ) VALUES (?, ?, ?, 'RUNNING', ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    scan_name,
                    created_at or datetime.now(timezone.utc).isoformat(),
                    target.get("id"),
                    target.get("name"),
                    target.get("provider"),
                    target.get("model"),
                    mode or target.get("mode"),
                    _json_dump(configuration or {}),
                ),
            )

    def update_scan_metadata(
        self,
        scan_id: str,
        target_info: Optional[Dict[str, Any]],
        mode: Optional[str],
        configuration: Optional[Dict[str, Any]] = None,
    ) -> None:
        target = _redact(target_info or {})
        with self._lock, self._session() as connection:
            connection.execute(
                """UPDATE scans SET target_id = ?, target_name = ?, provider = ?,
                   model = ?, mode = ?, configuration_json = ?
                   WHERE scan_id = ? AND status = 'RUNNING'""",
                (
                    target.get("id"),
                    target.get("name"),
                    target.get("provider"),
                    target.get("model"),
                    mode or target.get("mode"),
                    _json_dump(configuration or {}),
                    scan_id,
                ),
            )

    def add_execution(self, scan_id: str, record: Dict[str, Any]) -> bool:
        test_id = record.get("test_id") or record.get("id")
        verdict = record.get("verdict")
        if not _safe_id(scan_id) or not _safe_id(test_id):
            raise ValueError("Invalid scan or test ID")
        if verdict not in _VALID_VERDICTS:
            raise ValueError("Invalid execution verdict")
        with self._lock, self._session() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO scan_executions (
                    scan_id, test_id, ordinal, verdict, category, generation_method,
                    mutation_operator, parent_test_id, record_json
                )
                SELECT ?, ?,
                    (SELECT COALESCE(MAX(ordinal), 0) + 1
                     FROM scan_executions WHERE scan_id = ?),
                    ?, ?, ?, ?, ?, ?
                WHERE EXISTS (
                      SELECT 1 FROM scans WHERE scan_id = ? AND status = 'RUNNING'
                  )""",
                (
                    scan_id,
                    test_id,
                    scan_id,
                    verdict,
                    record.get("category"),
                    record.get("generation_method"),
                    record.get("mutation_operator"),
                    record.get("parent_test_id"),
                    _json_dump(record),
                    scan_id,
                ),
            )
            return cursor.rowcount == 1

    def finish_scan(
        self,
        scan_id: str,
        status: str,
        summary: Dict[str, Any],
        comparison: Dict[str, Any],
        completed_at: Optional[str] = None,
        error: Optional[str] = None,
    ) -> bool:
        if status not in _VALID_STATUSES - {"RUNNING"}:
            raise ValueError("Final scan status must be COMPLETED, FAILED, or CANCELLED")
        comparison = _redact(comparison)
        findings = comparison.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        with self._lock, self._session() as connection:
            cursor = connection.execute(
                """UPDATE scans SET status = ?, completed_at = ?, summary_json = ?,
                   comparison_json = ?, error = ?
                   WHERE scan_id = ? AND status = 'RUNNING'""",
                (
                    status,
                    completed_at or datetime.now(timezone.utc).isoformat(),
                    _json_dump(summary),
                    _json_dump(comparison),
                    _redact(error) if error else None,
                    scan_id,
                ),
            )
            if cursor.rowcount != 1:
                return False
            canaries = comparison.get("target_info", {}).get("canaries", [])
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                finding_id = finding.get("finding_id")
                test_id = finding.get("test_id")
                execution_row = connection.execute(
                    """SELECT record_json FROM scan_executions
                       WHERE scan_id = ? AND test_id = ?""",
                    (scan_id, str(test_id)) if test_id else (scan_id, ""),
                ).fetchone()
                if not finding_id or not test_id or not execution_row:
                    continue
                record = _json_load(execution_row["record_json"], dict, {})
                evaluated_verdict, evaluated_reason = evaluate_response_details(
                    record.get("response"), canaries=canaries
                )
                evidence = extract_evidence_details(
                    record.get("response"),
                    evaluated_verdict,
                    evaluated_reason,
                    canaries=canaries,
                )
                if (
                    finding.get("evidence_verified") is not True
                    or finding_id != f"FINDING-{test_id}"
                    or finding.get("parent_test_id") != record.get("parent_test_id")
                    or finding.get("generation_method") != record.get("generation_method")
                    or finding.get("raw_response") != record.get("response")
                    or record.get("verdict") != "VULNERABLE"
                    or evaluated_verdict != "VULNERABLE"
                    or evaluated_reason != record.get("detail")
                    or finding.get("reason") != evaluated_reason
                    or finding.get("matched_canary") != evidence.get("matched_canary")
                    or finding.get("matched_rule") != evidence.get("matched_rule")
                ):
                    continue
                connection.execute(
                    """INSERT OR IGNORE INTO scan_findings (
                        scan_id, finding_id, test_id, parent_test_id, finding_json
                    ) VALUES (?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        str(finding_id),
                        str(test_id),
                        finding.get("parent_test_id"),
                        _json_dump(finding),
                    ),
                )
            return True

    def fail_scan(self, scan_id: str, error: str, completed_at: Optional[str] = None) -> bool:
        return self.finish_scan(
            scan_id,
            "FAILED",
            {},
            {},
            completed_at=completed_at,
            error=error,
        )

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if not _safe_id(scan_id):
            return None
        with self._lock, self._session() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                return None
            executions = connection.execute(
                """SELECT record_json FROM scan_executions
                   WHERE scan_id = ? ORDER BY ordinal""",
                (scan_id,),
            ).fetchall()
            findings = connection.execute(
                """SELECT finding_json FROM scan_findings
                   WHERE scan_id = ? ORDER BY finding_id""",
                (scan_id,),
            ).fetchall()
        result = self._scan_summary(row)
        comparison = _json_load(row["comparison_json"], dict, {})
        result.update(
            {
                "configuration": _json_load(row["configuration_json"], dict, {}),
                "summary": _json_load(row["summary_json"], dict, {}),
                "comparison": comparison,
                "target_info": comparison.get("target_info") or {
                    "id": row["target_id"],
                    "name": row["target_name"],
                    "provider": row["provider"],
                    "model": row["model"],
                    "mode": row["mode"],
                },
                "results": [
                    record for item in executions
                    if isinstance((record := _json_load(item["record_json"], dict, None)), dict)
                ],
                "findings": [
                    finding for item in findings
                    if isinstance((finding := _json_load(item["finding_json"], dict, None)), dict)
                ],
                "error": row["error"],
            }
        )
        return result

    @staticmethod
    def _scan_summary(row: sqlite3.Row) -> Dict[str, Any]:
        summary = _json_load(row["summary_json"], dict, {})
        configuration = _json_load(row["configuration_json"], dict, {})
        comparison = _json_load(row["comparison_json"], dict, {})
        return {
            "scan_id": row["scan_id"],
            "scan_name": row["scan_name"],
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
            "status": row["status"],
            "target_id": row["target_id"],
            "target_name": row["target_name"],
            "provider": row["provider"],
            "model": row["model"],
            "mode": row["mode"],
            "configuration": configuration,
            "summary": summary,
            "execution_count": summary.get("total_executed", 0),
            "finding_count": summary.get("confirmed_findings", 0),
            "comparison_summary": {
                "novel_findings_count": comparison.get("novel_findings_count", 0),
                "distinct_outcomes_count": comparison.get("distinct_outcomes_count", 0),
            },
            "error": row["error"],
        }

    def list_scans(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
        target_id: Optional[str] = None,
        scan_id_search: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date_exclusive: Optional[str] = None,
    ) -> Dict[str, Any]:
        if page < 1 or not 1 <= page_size <= 100:
            raise ValueError("Invalid pagination values")
        if status is not None and status not in _VALID_STATUSES:
            raise ValueError("Invalid scan status")
        clauses: List[str] = []
        values: List[Any] = []
        for column, value, operator in (
            ("status", status, "="),
            ("target_id", target_id, "="),
            ("created_at", start_date, ">="),
            ("created_at", end_date_exclusive, "<"),
        ):
            if value is not None:
                clauses.append(f"{column} {operator} ?")
                values.append(value)
        if scan_id_search:
            clauses.append("scan_id LIKE ? ESCAPE '\\'")
            escaped_search = (
                scan_id_search.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            values.append(f"%{escaped_search}%")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        offset = (page - 1) * page_size
        with self._lock, self._session() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM scans{where}", values
            ).fetchone()[0]
            rows = connection.execute(
                f"""SELECT * FROM scans{where}
                    ORDER BY created_at DESC, scan_id DESC LIMIT ? OFFSET ?""",
                [*values, page_size, offset],
            ).fetchall()
        return {
            "scans": [self._scan_summary(row) for row in rows],
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size,
        }

    def list_findings(self, scan_id: str) -> Optional[List[Dict[str, Any]]]:
        if not _safe_id(scan_id):
            return None
        with self._lock, self._session() as connection:
            exists = connection.execute(
                "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if exists is None:
                return None
            rows = connection.execute(
                "SELECT finding_json FROM scan_findings WHERE scan_id = ? ORDER BY finding_id",
                (scan_id,),
            ).fetchall()
        return [
            finding for row in rows
            if isinstance((finding := _json_load(row["finding_json"], dict, None)), dict)
        ]

    def executions_for(self, scan_id: str) -> List[Dict[str, Any]]:
        scan = self.get_scan(scan_id)
        return scan["results"] if scan else []

    def all_scans(self) -> List[Dict[str, Any]]:
        with self._lock, self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY created_at ASC, scan_id ASC"
            ).fetchall()
        return [self._scan_summary(row) for row in rows]

    def count_scans(self) -> int:
        with self._lock, self._session() as connection:
            return connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]


scan_history_store = ScanHistoryStore()
scan_history_store.recover_interrupted_scans()
