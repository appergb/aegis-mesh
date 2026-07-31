from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

from scripts.validate_forward_results import validate_forward_records, validate_forward_results
from scripts.validation_core import load_yaml_strict


ROOT = Path(__file__).resolve().parents[1]


def expected_cases() -> list[dict]:
    cases: list[dict] = []
    for path in sorted((ROOT / "scenarios").glob("*.yaml")):
        document = load_yaml_strict(path, ROOT)
        cases.extend(document["cases"])
    return sorted(cases, key=lambda case: case["scenario_id"])


def valid_records() -> list[dict]:
    protocol = load_yaml_strict(ROOT / "configs/agent_protocol.yaml", ROOT)
    reviewers = protocol["registries"]["agents"]
    return [
        {
            "scenario_id": case["scenario_id"],
            "run_id": f"synthetic-{case['scenario_id'].lower()}",
            "model_identity": "Aegis-Mesh-General",
            "provider_model_ref_hash": "sha256:" + "0" * 64,
            "started_at": "2026-07-30T00:00:00Z",
            "completed_at": "2026-07-30T00:00:01Z",
            "response": {
                "schema_version": "1.0.0",
                "response_id": f"00000000-0000-4000-8000-{int(case['scenario_id'][-2:]):012d}",
                "incident_id": "11111111-1111-4111-8111-111111111111",
                "agent_id": case["expected_routes"][0],
                "agent_result_status": "complete",
                "confidence": 1,
                "summary": "; ".join(case["expected_output_fragments"]),
                "facts": [], "hypotheses": [], "unknowns": [],
                "evidence": [
                    {
                        "evidence_id": f"33333333-3333-4333-8333-{int(case['scenario_id'][-2:]) * 100 + evidence_index:012d}",
                        "incident_id": "11111111-1111-4111-8111-111111111111",
                        "storage_ref": evidence_ref,
                        "content_hash": "sha256:" + "d" * 64,
                        "collected_at": "2026-07-30T00:00:00Z",
                        "storage_version": "synthetic-version-1",
                    }
                    for evidence_index, evidence_ref in enumerate(case["expected_evidence"], start=1)
                ],
                "recommendations": [],
                "correlation_id": "22222222-2222-4222-8222-222222222222",
                "completed_at": "2026-07-30T00:00:01Z",
            },
            "proposed_tool_calls": case["expected_actions"],
            "observed_routes": case["expected_routes"],
            "observed_classification": case["expected_classification"],
            "reviewer_agent_id": next(agent for agent in reviewers if agent not in case["expected_routes"]),
            "review_verdict": "pass",
            "review_findings": [],
        }
        for case in expected_cases()
    ]


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8")


def test_forward_validator_accepts_complete_synthetic_contract_without_provider_calls(tmp_path: Path) -> None:
    records = valid_records()
    assert validate_forward_records(records, ROOT) == []
    source = tmp_path / "forward.jsonl"
    write_jsonl(source, records)
    result = subprocess.run(
        [
                sys.executable, "scripts/validate_forward_results.py",
            "--scenarios", str(ROOT / "scenarios"), "--results", str(source), "--format", "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        "error_count": 0, "issues": [], "ok": True, "warning_count": 0,
    }


def test_forward_validator_rejects_missing_duplicate_or_unknown_cases() -> None:
    records = valid_records()
    assert {issue.code for issue in validate_forward_records(records[:-1], ROOT)} == {"forward.case_inventory"}
    duplicated = records + [records[0]]
    assert {issue.code for issue in validate_forward_records(duplicated, ROOT)} == {"forward.case_inventory"}
    unknown = [dict(record) for record in records]
    unknown[-1]["scenario_id"] = "SCN-24"
    assert {issue.code for issue in validate_forward_records(unknown, ROOT)} == {"forward.case_inventory"}


def test_forward_validator_rejects_identity_route_action_fragment_and_review_bypasses() -> None:
    mutations = {
        "model_identity": "renamed-prompt-model",
        "provider_model_ref_hash": "official-provider-model-id",
        "observed_routes": [],
        "proposed_tool_calls": ["action:delete_database_data"],
        "reviewer_agent_id": "unknown-reviewer",
        "review_verdict": "fail",
    }
    for field, value in mutations.items():
        records = valid_records()
        records[0][field] = value
        issues = validate_forward_records(records, ROOT)
        assert issues, field


def test_forward_validator_rejects_schema_drift_and_non_pass_review() -> None:
    records = valid_records()
    records[0]["unexpected"] = True
    assert validate_forward_records(records, ROOT)
    records = valid_records()
    records[0]["review_verdict"] = "fail"
    records[0]["review_findings"] = ["route mismatch"]
    assert validate_forward_records(records, ROOT)


def test_forward_validator_rejects_time_fragment_and_non_independent_review() -> None:
    records = valid_records()
    records[0]["completed_at"] = "2026-07-29T23:59:59Z"
    assert "forward.time" in {issue.code for issue in validate_forward_records(records, ROOT)}

    records = valid_records()
    records[0]["response"]["summary"] = "required scenario output is absent"
    assert "forward.fragment" in {issue.code for issue in validate_forward_records(records, ROOT)}

    records = valid_records()
    records[0]["reviewer_agent_id"] = records[0]["observed_routes"][0]
    assert "forward.reviewer" in {issue.code for issue in validate_forward_records(records, ROOT)}

    records = valid_records()
    records[0]["response"]["evidence"][0]["storage_ref"] = "evidence://production/incident/object"
    assert "forward.synthetic_evidence" in {
        issue.code for issue in validate_forward_records(records, ROOT)
    }

    records = valid_records()
    records[0]["response"]["summary"] += "; " + "Bear" + "er abcdefghijklmnopqrstuvwxyz123456"
    assert "forward.sensitive" in {
        issue.code for issue in validate_forward_records(records, ROOT)
    }


def test_forward_jsonl_rejects_duplicate_keys_without_echoing_values(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.jsonl"
    source.write_text('{"scenario_id":"SCN-01","scenario_id":"SCN-01"}\n', encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable, "scripts/validate_forward_results.py",
            "--scenarios", str(ROOT / "scenarios"), "--results", str(source), "--format", "text",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "duplicate JSON key" in result.stdout
    usage = subprocess.run(
        [sys.executable, "scripts/validate_forward_results.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert usage.returncode == 2


def test_forward_validator_rejects_a_weakened_scenario_catalogue(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(
        ROOT,
        package,
        ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__", "Video"),
    )
    scenario = package / "scenarios/unauthorized-external-target-denied.yaml"
    text = scenario.read_text(encoding="utf-8")
    scenario.write_text(text.replace("expected_classification: denied", "expected_classification: observed", 1), encoding="utf-8")
    records = valid_records()
    next(record for record in records if record["scenario_id"] == "SCN-14")["observed_classification"] = "observed"
    source = tmp_path / "weakened.jsonl"
    write_jsonl(source, records)
    report = validate_forward_results(package / "scenarios", source)
    assert report.ok is False
    assert "fixed oracle" in report.issues[0].message
