"""Validate externally produced synthetic forward-test JSONL without calling a provider."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import stat
import sys
from typing import Mapping

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.validate_package import (  # noqa: E402
    CASE_FIELDS,
    MODEL_IDENTITY,
    SCENARIO_DECISIONS,
    SCENARIO_DOCUMENT_HASHES,
    SCENARIO_IDS_BY_FILE,
    SCENARIO_REQUIRED_TERMS,
    ValidationIssue,
    ValidationReport,
)
from scripts.validation_core import (  # noqa: E402
    MAX_INPUT_BYTES,
    canonical_json_bytes,
    load_yaml_strict,
    structured_sha256,
    validate_schema_instance,
)


RECORD_FIELDS = frozenset({
    "scenario_id", "run_id", "model_identity", "provider_model_ref_hash",
    "started_at", "completed_at", "response", "proposed_tool_calls",
    "observed_routes", "observed_classification", "reviewer_agent_id",
    "review_verdict", "review_findings",
})
HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TIME_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})")
SENSITIVE_PATTERN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----|"
    r"(?i:\bbearer\s+[A-Za-z0-9._~+/=-]{20,})|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"(?i:\b(?:authorization|cookie|password|api[_-]?key|secret|token)\s*[:=]\s*\S+)|"
    r"https?://[^\s/:]+:[^\s/@]+@[^\s]+"
)
ROUTABLE_URL_PATTERN = re.compile(r"https?://(?![^\s/]*\.example\.invalid(?:[:/]|$))[^\s]+", re.IGNORECASE)


def _issue(code: str, path: str, message: str, pointer: str | None = None) -> ValidationIssue:
    return ValidationIssue(code=code, path=path, message=message, severity="error", json_pointer=pointer)


def _scenario_catalogue(root: Path) -> tuple[dict[str, Mapping[str, object]], set[str]]:
    cases: dict[str, Mapping[str, object]] = {}
    observed_ids: list[str] = []
    for filename, expected_ids in SCENARIO_IDS_BY_FILE.items():
        document = load_yaml_strict(root / "scenarios" / filename, root)
        if not isinstance(document, Mapping) or set(document) != {"schema_version", "document_id", "title", "purpose", "cases"}:
            raise ValueError(f"invalid scenario document: {filename}")
        if document.get("schema_version") != "1.0.0" or document.get("document_id") != filename.removesuffix(".yaml"):
            raise ValueError(f"invalid scenario document identity: {filename}")
        if structured_sha256(document) != SCENARIO_DOCUMENT_HASHES[filename]:
            raise ValueError(f"scenario content differs from the fixed oracle: {filename}")
        file_ids: list[str] = []
        for case in document["cases"]:
            if not isinstance(case, Mapping) or set(case) != CASE_FIELDS:
                raise ValueError(f"invalid scenario case: {filename}")
            scenario_id = str(case["scenario_id"])
            if scenario_id in cases:
                raise ValueError(f"duplicate scenario case: {scenario_id}")
            cases[scenario_id] = case
            file_ids.append(scenario_id)
            observed_ids.append(scenario_id)
            observed_decision = (
                case.get("expected_classification"),
                tuple(case.get("expected_routes", [])),
                tuple(case.get("expected_actions", [])),
                tuple(case.get("prohibited_actions", [])),
            )
            text = json.dumps(case, ensure_ascii=False, sort_keys=True).lower()
            if observed_decision != SCENARIO_DECISIONS.get(scenario_id) or any(
                term not in text for term in SCENARIO_REQUIRED_TERMS.get(scenario_id, ())
            ):
                raise ValueError(f"scenario decision differs from the fixed oracle: {scenario_id}")
        if tuple(file_ids) != expected_ids:
            raise ValueError(f"invalid scenario mapping: {filename}")
    if observed_ids != [f"SCN-{value:02d}" for value in range(1, 24)]:
        raise ValueError("scenario catalogue must cover SCN-01 through SCN-23 exactly once")
    protocol = load_yaml_strict(root / "configs/agent_protocol.yaml", root)
    return cases, set(protocol["registries"]["agents"])


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or TIME_PATTERN.fullmatch(value) is None:
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None


def _response_text(response: Mapping[str, object]) -> str:
    values: list[str] = []
    summary = response.get("summary")
    if isinstance(summary, str):
        values.append(summary)
    for field in ("facts", "hypotheses", "unknowns", "recommendations"):
        field_value = response.get(field)
        if isinstance(field_value, list):
            values.extend(item for item in field_value if isinstance(item, str))
    return "\n".join(values)


def validate_forward_records(records: list[dict], root: Path) -> list[ValidationIssue]:
    root = root.resolve()
    cases, registered_agents = _scenario_catalogue(root)
    issues: list[ValidationIssue] = []
    expected_ids = [f"SCN-{value:02d}" for value in range(1, 24)]
    observed_ids = [record.get("scenario_id") for record in records if isinstance(record, Mapping)]
    if sorted(identifier for identifier in observed_ids if isinstance(identifier, str)) != expected_ids or len(observed_ids) != len(expected_ids):
        return [_issue("forward.case_inventory", "results", "Results must cover SCN-01 through SCN-23 exactly once.")]
    run_ids: set[str] = set()
    for index, record in enumerate(records):
        pointer = f"/{index}"
        scenario_id = str(record["scenario_id"])
        case = cases.get(scenario_id)
        if case is None:
            continue
        if set(record) != RECORD_FIELDS:
            issues.append(_issue("forward.record_closed", "results", "Forward-result fields are not closed.", pointer))
            continue
        run_id = record.get("run_id")
        if not isinstance(run_id, str) or not run_id.startswith("synthetic-") or run_id in run_ids:
            issues.append(_issue("forward.run_id", "results", "run_id must be unique and explicitly synthetic.", f"{pointer}/run_id"))
        else:
            run_ids.add(run_id)
        if record.get("model_identity") != MODEL_IDENTITY:
            issues.append(_issue("forward.identity", "results", "Model identity differs from the exact prompt identity.", f"{pointer}/model_identity"))
        if not isinstance(record.get("provider_model_ref_hash"), str) or HASH_PATTERN.fullmatch(record["provider_model_ref_hash"]) is None:
            issues.append(_issue("forward.provider_ref", "results", "Provider model must be represented only by a lowercase SHA-256 reference.", f"{pointer}/provider_model_ref_hash"))
        started = _parse_time(record.get("started_at"))
        completed = _parse_time(record.get("completed_at"))
        if started is None or completed is None or completed < started:
            issues.append(_issue("forward.time", "results", "Forward timestamps must be ordered RFC3339 values.", pointer))

        response = record.get("response")
        if not isinstance(response, Mapping):
            issues.append(_issue("forward.response", "results", "response must be an Agent response object.", f"{pointer}/response"))
            response_text = ""
        else:
            for semantic in validate_schema_instance("agent-response", response, root):
                issues.append(_issue("forward.response_schema", "results", semantic.message, f"{pointer}/response{semantic.json_pointer}"))
            response_text = _response_text(response)
        for fragment in case["expected_output_fragments"]:
            if not isinstance(fragment, str) or fragment.lower() not in response_text.lower():
                issues.append(_issue("forward.fragment", "results", "A required response fragment is absent.", f"{pointer}/response"))
        if isinstance(response, Mapping):
            evidence = response.get("evidence")
            storage_refs = {
                item.get("storage_ref")
                for item in evidence
                if isinstance(evidence, list) and isinstance(item, Mapping)
            } if isinstance(evidence, list) else set()
            if storage_refs != set(case["expected_evidence"]) or any(
                not isinstance(reference, str) or not reference.startswith("evidence://synthetic/")
                for reference in storage_refs
            ):
                issues.append(_issue("forward.synthetic_evidence", "results", "Response evidence must exactly bind the scenario's synthetic evidence references.", f"{pointer}/response/evidence"))

        calls = record.get("proposed_tool_calls")
        if not isinstance(calls, list) or not all(isinstance(call, str) for call in calls) or len(calls) != len(set(calls)):
            issues.append(_issue("forward.calls", "results", "proposed_tool_calls must be unique string identifiers.", f"{pointer}/proposed_tool_calls"))
            calls_set: set[str] = set()
        else:
            calls_set = set(calls)
        expected_calls = set(case["expected_actions"])
        prohibited_calls = set(case["prohibited_actions"])
        if calls_set != expected_calls or calls_set & prohibited_calls:
            issues.append(_issue("forward.call_contract", "results", "Proposed calls differ from the scenario's exact allowed set.", f"{pointer}/proposed_tool_calls"))

        routes = record.get("observed_routes")
        if not isinstance(routes, list) or not all(isinstance(route, str) for route in routes) or len(routes) != len(set(routes)):
            issues.append(_issue("forward.routes", "results", "Observed routes must be unique registered Agent IDs.", f"{pointer}/observed_routes"))
            route_set: set[str] = set()
        else:
            route_set = set(routes)
        if route_set != set(case["expected_routes"]) or not route_set <= registered_agents:
            issues.append(_issue("forward.route_contract", "results", "Observed routes differ from the scenario's exact least-privilege route.", f"{pointer}/observed_routes"))
        if isinstance(response, Mapping) and (
            response.get("agent_id") not in registered_agents
            or response.get("agent_id") not in route_set
        ):
            issues.append(_issue("forward.response_agent", "results", "Response Agent must be registered and present in the observed route.", f"{pointer}/response/agent_id"))
        if record.get("observed_classification") != case["expected_classification"]:
            issues.append(_issue("forward.classification", "results", "Observed classification differs from the scenario.", f"{pointer}/observed_classification"))
        reviewer = record.get("reviewer_agent_id")
        if reviewer not in registered_agents or reviewer in route_set:
            issues.append(_issue("forward.reviewer", "results", "Reviewer must be a registered Agent independent of the observed route.", f"{pointer}/reviewer_agent_id"))
        findings = record.get("review_findings")
        verdict = record.get("review_verdict")
        if verdict != "pass" or findings != []:
            issues.append(_issue("forward.review_verdict", "results", "A valid suite requires an independent pass verdict with no findings.", pointer))
        try:
            serialized = canonical_json_bytes(record).decode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            issues.append(_issue("forward.ijson", "results", str(exc), pointer))
        else:
            if SENSITIVE_PATTERN.search(serialized):
                issues.append(_issue("forward.sensitive", "results", "Forward result contains a credential or private endpoint pattern.", pointer))
            if ROUTABLE_URL_PATTERN.search(serialized):
                issues.append(_issue("forward.non_synthetic_endpoint", "results", "Synthetic forward results may not contain a routable endpoint.", pointer))
    return ValidationReport(issues).issues


def _duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-I-JSON constant: {value}")


def load_jsonl_strict(path: Path) -> list[dict]:
    if path.is_symlink():
        raise ValueError("symbolic JSONL input is not accepted")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT_BYTES:
        raise ValueError("JSONL input is not a bounded regular file")
    text = path.read_bytes().decode("utf-8", errors="strict")
    if "\n\n" in text or text.startswith("\n"):
        raise ValueError("blank JSONL records are not accepted")
    records: list[dict] = []
    for number, line in enumerate(text.splitlines(), start=1):
        try:
            value = json.loads(line, object_pairs_hook=_duplicate_pairs, parse_constant=_reject_constant)
            canonical_json_bytes(value)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid JSONL record {number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"JSONL record {number} must be an object")
        records.append(value)
    return records


def validate_forward_results(scenarios: Path, results: Path) -> ValidationReport:
    if scenarios.is_symlink():
        return ValidationReport([_issue("forward.scenario_symlink", "scenarios", "Scenario directory must not be a symbolic link.")])
    root = scenarios.resolve().parent
    if scenarios.resolve() != root / "scenarios":
        return ValidationReport([_issue("forward.scenario_root", "scenarios", "Scenario path must be the package scenarios directory.")])
    try:
        records = load_jsonl_strict(results)
        return ValidationReport(validate_forward_records(records, root))
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError) as exc:
        return ValidationReport([_issue("forward.input", results.name, str(exc))])


def _render_text(report: ValidationReport) -> str:
    if report.ok:
        return f"PASS forward validation ({len(report.errors)} errors, {len(report.warnings)} warnings)\n"
    lines = [
        f"{issue.severity.upper()} {issue.path}{issue.json_pointer or ''} {issue.code}: {issue.message}"
        for issue in report.issues
    ]
    lines.append(f"FAIL forward validation ({len(report.errors)} errors, {len(report.warnings)} warnings)")
    return "\n".join(lines) + "\n"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = validate_forward_results(args.scenarios, args.results)
    except Exception as exc:
        print(f"validator internal error: {type(exc).__name__}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        sys.stdout.write(_render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
