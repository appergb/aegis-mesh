from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

from scripts.validate_package import validate_package
from scripts.validation_core import load_yaml_strict


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = ROOT / "scenarios"
SCENARIO_FILES = (
    "qr-issuance-spike.yaml",
    "legitimate-opening-surge.yaml",
    "api-abuse.yaml",
    "database-degradation.yaml",
    "region-failure.yaml",
    "verified-abuse-notice.yaml",
    "wazuh-read-triage.yaml",
    "wazuh-write-denied.yaml",
    "unauthorized-external-target-denied.yaml",
    "incident-ioc-enrichment.yaml",
    "sensitive-url-reputation-denied.yaml",
    "existing-public-url-report.yaml",
    "vulnfeed-payment-denied.yaml",
    "vulnfeed-epss-kev.yaml",
    "attack-chain-gaps.yaml",
    "detection-rule-validation.yaml",
    "stride-incomplete.yaml",
)
CASE_FIELDS = {
    "scenario_id", "title", "preconditions", "input_events", "mocked_tool_results",
    "expected_routes", "minimum_severity", "expected_classification",
    "expected_actions", "prohibited_actions", "expected_output_fragments",
    "expected_audit_records", "expected_evidence", "expected_verification", "pass_conditions",
}
SCENARIO_IDS_BY_FILE = {
    "qr-issuance-spike.yaml": ["SCN-01"],
    "legitimate-opening-surge.yaml": ["SCN-02"],
    "api-abuse.yaml": ["SCN-03"],
    "database-degradation.yaml": ["SCN-04"],
    "region-failure.yaml": ["SCN-05"],
    "verified-abuse-notice.yaml": [f"SCN-{index:02d}" for index in range(6, 12)],
    "wazuh-read-triage.yaml": ["SCN-12"],
    "wazuh-write-denied.yaml": ["SCN-13"],
    "unauthorized-external-target-denied.yaml": ["SCN-14"],
    "incident-ioc-enrichment.yaml": ["SCN-15"],
    "sensitive-url-reputation-denied.yaml": ["SCN-16"],
    "existing-public-url-report.yaml": ["SCN-17"],
    "vulnfeed-payment-denied.yaml": ["SCN-18"],
    "vulnfeed-epss-kev.yaml": ["SCN-19", "SCN-20"],
    "attack-chain-gaps.yaml": ["SCN-21"],
    "detection-rule-validation.yaml": ["SCN-22"],
    "stride-incomplete.yaml": ["SCN-23"],
}


def load_scenarios() -> list[dict]:
    cases: list[dict] = []
    for name in SCENARIO_FILES:
        document = load_yaml_strict(SCENARIO_ROOT / name, ROOT)
        assert isinstance(document, dict)
        assert set(document) == {"schema_version", "document_id", "title", "purpose", "cases"}
        assert document["schema_version"] == "1.0.0"
        assert document["document_id"] == name.removesuffix(".yaml")
        assert isinstance(document["title"], str) and document["title"].strip()
        assert isinstance(document["purpose"], str) and document["purpose"].strip()
        assert isinstance(document["cases"], list) and document["cases"]
        assert [case["scenario_id"] for case in document["cases"]] == SCENARIO_IDS_BY_FILE[name]
        cases.extend(document["cases"])
    return cases


def test_scenario_inventory_and_case_contract_are_closed() -> None:
    expected_paths = {SCENARIO_ROOT / name for name in SCENARIO_FILES}
    assert SCENARIO_ROOT.is_dir() and not SCENARIO_ROOT.is_symlink()
    assert set(SCENARIO_ROOT.iterdir()) == expected_paths
    assert all(path.is_file() and not path.is_symlink() for path in expected_paths)

    cases = load_scenarios()
    assert [case["scenario_id"] for case in cases] == [f"SCN-{index:02d}" for index in range(1, 24)]
    for case in cases:
        assert set(case) == CASE_FIELDS
        for field in (
            "preconditions", "input_events", "mocked_tool_results", "expected_routes",
            "prohibited_actions", "expected_output_fragments", "expected_audit_records",
            "expected_evidence", "expected_verification", "pass_conditions",
        ):
            assert isinstance(case[field], list) and case[field], (case["scenario_id"], field)
        assert isinstance(case["expected_actions"], list)


def test_scenario_semantics_reuse_authoritative_registries() -> None:
    protocol = load_yaml_strict(ROOT / "configs/agent_protocol.yaml", ROOT)
    ioc_policy = load_yaml_strict(ROOT / "configs/incident_ioc_policy.yaml", ROOT)
    agents = set(protocol["registries"]["agents"])
    severities = set(protocol["registries"]["severity"])
    statuses = set(protocol["registries"]["agent_result_status"])
    audits = set(protocol["registries"]["audit_event"])
    classification_values = (
        set(ioc_policy["classifications"])
        | set(protocol["registries"]["mcp_policy_status"])
        | set(protocol["registries"]["detection_release_stage"])
        | set(protocol["registries"]["threat_model_status"])
        | {
            band["name"]
            for band in load_yaml_strict(ROOT / "configs/thresholds.yaml", ROOT)["qr"]["participant_valid_credential_bands"]
        }
    )
    actions = {
        action
        for values in protocol["registries"]["action_categories"].values()
        for action in values
    }
    mcp_tools: set[str] = set()
    for fixture in (ROOT / "tests/fixtures/mcp").glob("*-tools-list.json"):
        value = json.loads(fixture.read_text(encoding="utf-8"))
        mcp_tools.update(tool["name"] for tool in value["tools"])

    for case in load_scenarios():
        assert set(case["expected_routes"]) <= agents
        assert case["minimum_severity"] in severities
        assert case["expected_classification"] in classification_values
        assert set(case["expected_audit_records"]) <= audits
        allowed_mcp = set()
        for policy_path in (ROOT / "integrations").glob("*/tool_policy.yaml"):
            inventory = load_yaml_strict(policy_path, ROOT)["inventory"]
            allowed_mcp.update(inventory.get("retained_tools", inventory.get("allow_tools", [])))
        for reference in case["expected_actions"] + case["prohibited_actions"]:
            kind, name = reference.split(":", 1)
            assert kind in {"action", "mcp_tool"}
            assert name in (actions if kind == "action" else mcp_tools)
            if reference in case["expected_actions"] and kind == "mcp_tool":
                assert name in allowed_mcp
        assert set(case["expected_actions"]).isdisjoint(case["prohibited_actions"])


def test_scenarios_cover_required_security_acceptance_paths() -> None:
    cases = {case["scenario_id"]: case for case in load_scenarios()}
    corpus = "\n".join(json.dumps(case, sort_keys=True) for case in cases.values()).lower()
    for phrase in (
        "880", "1250", "3000", "legitimate opening surge", "replayed nonce",
        "database degradation", "region failure", "prompt injection", "source fingerprint", "nat",
        "cloud-provider abuse", "rir", "personal email", "wazuh read",
        "wazuh write", "shodan", "incident ioc", "sensitive url",
        "existing public url", "402", "epss", "kev", "attack-chain gap",
        "false positive", "stride incomplete",
    ):
        assert phrase in corpus


def test_package_validator_text_and_json_modes_are_deterministic() -> None:
    command = [
        sys.executable, "scripts/validate_package.py", "--root", str(ROOT),
    ]
    text_result = subprocess.run(command + ["--format", "text"], cwd=ROOT, capture_output=True, text=True)
    assert text_result.returncode == 0, text_result.stdout + text_result.stderr
    assert text_result.stdout == "PASS package validation (0 errors, 0 warnings)\n"

    first = subprocess.run(command + ["--format", "json"], cwd=ROOT, capture_output=True, text=True)
    second = subprocess.run(command + ["--format", "json"], cwd=ROOT, capture_output=True, text=True)
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    assert json.loads(first.stdout) == {
        "error_count": 0, "issues": [], "ok": True, "warning_count": 0,
    }


def test_package_validator_rejects_sentinel_scenario_and_notification_drift(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(
        ROOT,
        package,
        ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__", "Video"),
    )
    assert validate_package(package).ok

    thresholds = package / "configs/thresholds.yaml"
    original = thresholds.read_text(encoding="utf-8")
    thresholds.write_text(original.replace("unit: null", "unit: requests_per_second", 1), encoding="utf-8")
    assert "config.unconfigured" in {issue.code for issue in validate_package(package).errors}
    thresholds.write_text(original, encoding="utf-8")

    opening = package / "scenarios/legitimate-opening-surge.yaml"
    original = opening.read_text(encoding="utf-8")
    opening.write_text(original.replace("SCN-02", "SCN-01", 1), encoding="utf-8")
    codes = {issue.code for issue in validate_package(package).errors}
    assert {"scenario.mapping", "scenario.inventory"} <= codes
    opening.write_text(original, encoding="utf-8")

    notices = package / "scenarios/verified-abuse-notice.yaml"
    original = notices.read_text(encoding="utf-8")
    notices.write_text(original.replace("synthetic-approver-b", "synthetic-approver-a", 1), encoding="utf-8")
    assert "notification.approvals" in {issue.code for issue in validate_package(package).errors}


def test_package_validator_rejects_security_inventory_and_outcome_bypasses(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(
        ROOT,
        package,
        ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__", "Video"),
    )
    mutations = (
        ("scenarios/unauthorized-external-target-denied.yaml", "expected_classification: denied", "expected_classification: observed", "scenario.fixed_outcome"),
        ("scenarios/wazuh-write-denied.yaml", "minimum_severity: P0", "minimum_severity: P3", "scenario.content_hash"),
        ("scenarios/api-abuse.yaml", "principal_scope: exact", "principal_scope: exact, api_key: live-production-secret", "secret.literal"),
        ("scenarios/api-abuse.yaml", "principal_scope: exact", "principal_scope: exact, note: 'Bear" + "er abcdefghijklmnopqrstuvwxyz123456'", "secret.literal"),
        ("configs/runtime.example.yaml", "https://gateway.example.invalid", "https://gateway.production.example.com", "endpoint.real"),
        ("adapters/openai.md", "# OpenAI runtime adapter", "# OpenAI runtime adapter\ngateway_endpoint: https://gateway.production.example.com", "endpoint.real"),
        ("integrations/wazuh-mcp/upstream.lock.yaml", "52c1d375d22419ce662bc4218f904de015e4a7c7", "62c1d375d22419ce662bc4218f904de015e4a7c7", "mcp.upstream_lock"),
        ("integrations/wazuh-mcp/upstream.lock.yaml", "complete_dependency_lock_missing", "complete_dependency_lock_replaced", "mcp.lock_gate"),
        ("integrations/wazuh-mcp/tool_policy.yaml", "class: policy_authorized_read", "class: two_person_high_impact", "mcp.read_approval"),
        ("schemas/agent-response.schema.json", "urn:aegis-mesh:schema:incident-event:1.0.0#/$defs/uuid", "https://schema.production.example.com/uuid", "schema.ref"),
        ("configs/agent_permissions.yaml", "grants: [observe, recommend]", "grants: [observe]", "permission.maximum"),
        ("configs/approval_matrix.yaml", "  - two_person_irreversible", "  - two_person_irreversible\n  - invented_approval", "approval.registry"),
        ("configs/mcp_tool_policy.yaml", "default_effect: deny", "default_effect: allow", "mcp.global_policy"),
        ("configs/notification_policy.yaml", "enabled: false", "enabled: true", "notification.policy"),
        ("configs/forensics_policy.yaml", "history_deletion_allowed: false", "history_deletion_allowed: true", "forensics.policy"),
        ("skills/shared/engineer-sigma-yara-rules/tests/negative/sysmon-legitimate-maintenance.json", "wscript.exe", "calc.exe", "detection.validation"),
        ("skills/shared/engineer-sigma-yara-rules/tests/rules/sigma-high-fp.yaml", "status: test", "status: experimental", "detection.validation"),
        ("skills/shared/engineer-sigma-yara-rules/tests/rules/yara-valid.yar", "filesize <= 1048576", "filesize <= 2000000", "detection.validation"),
        ("SYSTEM_PROMPT.md", "你的模型身份名称是 Aegis-Mesh-General。", "Aegis-Mesh-General", "identity.missing"),
        ("README.md", "# Aegis Mesh", "# Aegis Mesh\n[broken](missing-contract.md)", "link.missing"),
        ("configs/thresholds.yaml", "qr:", "qr_missing:", "scenario.classification_registry"),
        ("configs/runtime.example.yaml", "adapters:", "adapters: []\nadapters_removed:", "contract.invalid"),
    )
    for relative, before, after, expected_code in mutations:
        path = package / relative
        original = path.read_text(encoding="utf-8")
        assert before in original, relative
        path.write_text(original.replace(before, after, 1), encoding="utf-8")
        assert expected_code in {issue.code for issue in validate_package(package).errors}, relative
        path.write_text(original, encoding="utf-8")
    policy_path = package / "integrations/wazuh-mcp/tool_policy.yaml"
    original = policy_path.read_text(encoding="utf-8")
    swapped = original.replace(
        "    - get_wazuh_alerts", "    - __swap_read_tool__", 1
    ).replace(
        "    - wazuh_block_ip", "    - get_wazuh_alerts", 1
    ).replace(
        "    - __swap_read_tool__", "    - wazuh_block_ip", 1
    )
    policy_path.write_text(swapped, encoding="utf-8")
    assert "mcp.partition" in {issue.code for issue in validate_package(package).errors}
    policy_path.write_text(original, encoding="utf-8")
    hidden = package / "configs/.env"
    hidden.write_text("API_KEY=live-production-secret\n", encoding="utf-8")
    assert "inventory.closed" in {issue.code for issue in validate_package(package).errors}


def test_package_validator_treats_missing_governed_files_as_contract_failures(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(
        ROOT,
        package,
        ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__", "Video"),
    )
    (package / "configs/thresholds.yaml").unlink()
    report = validate_package(package)
    assert report.ok is False
    command = [
        sys.executable, "scripts/validate_package.py",
        "--root", str(package), "--format", "json",
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 1, result.stdout + result.stderr

    package = tmp_path / "package-root-file"
    shutil.copytree(
        ROOT,
        package,
        ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__", "Video"),
    )
    (package / ".python-version").unlink()
    assert "inventory.root_file" in {issue.code for issue in validate_package(package).errors}


def test_package_validator_cli_distinguishes_usage_from_contract_failure() -> None:
    command = [sys.executable, "scripts/validate_package.py"]
    usage = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    assert usage.returncode == 2
    invalid = subprocess.run(
        command + ["--root", str(ROOT / "missing-package"), "--format", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert invalid.returncode == 1
    assert json.loads(invalid.stdout)["ok"] is False
