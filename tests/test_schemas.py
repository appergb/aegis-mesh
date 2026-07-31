from copy import deepcopy
from datetime import datetime, timezone
from importlib.metadata import version as package_version
import json
from pathlib import Path
import shutil

import pytest
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
import yara

from scripts.validation_core import (
    ACTION_CONTRACTS,
    canonical_json_bytes,
    compute_notification_idempotency_key,
    compute_scope_hash,
    load_json_strict,
    load_yaml_strict,
    raw_sha256,
    structured_sha256,
    validate_action_contract,
    validate_approval_set,
    validate_action_transition,
    validate_evidence_references,
    validate_incident_transition,
    validate_notification_transition,
    validate_recovery_contract,
    validate_schema_instance,
    validate_time_window,
    validate_threat_model,
)

from scripts.validate_forward_results import validate_forward_records


ROOT = Path(__file__).resolve().parents[1]
UUID1 = "123e4567-e89b-42d3-a456-426614174000"
UUID2 = "123e4567-e89b-42d3-a456-426614174001"
HASH = "sha256:" + "a" * 64
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def evidence() -> dict:
    return {
        "evidence_id": UUID2,
        "incident_id": UUID1,
        "storage_ref": "evidence://store/object/version-1",
        "content_hash": HASH,
        "collected_at": "2026-12-31T23:00:00Z",
        "storage_version": "version-1",
    }


def scope(*, notification: bool = False, irreversible: bool = False) -> dict:
    action_category = "external_notification" if notification else ("identity_session_control" if irreversible else "edge_protection")
    action_type = "send_abuse_notification" if notification else ("revoke_exact_session" if irreversible else "apply_waf_challenge")
    target = {"resource_type": "notification_recipient", "resource_id": "official-abuse-contact-01"} if notification else (
        {"resource_type": "session_set", "resource_id": "session-set-01"} if irreversible else
        {"resource_type": "edge_policy", "resource_id": "edge-policy-01"}
    )
    exact_scope = {
        "notice_id": UUID2,
        "recipient_ref": "official-abuse-contact-01",
        "template_version": "1.0.0",
        "body_hash": HASH,
    } if notification else (
        {"session_ids": ["session-01"], "reason": "Confirmed session compromise."} if irreversible else
        {"route_ids": ["registration"], "match_rule_id": "invalid-pattern-01", "duration_seconds": 300}
    )
    value = {
        "purpose": "notification" if notification else "action",
        "schema_version": "1.0.0",
        "incident_id": UUID1,
        "action_category": action_category,
        "action_type": action_type,
        "target": target,
        "exact_scope": exact_scope,
        "environment": "production",
        "expires_at": "2030-01-01T01:00:00+00:00",
    }
    if notification:
        value.update(
            {
                "recipient_ref": "official-abuse-contact-01",
                "template_version": "1.0.0",
                "body_hash": HASH,
            }
        )
    return value


def human_approval(role: str, approver_id: str, bound_scope: dict) -> dict:
    return {
        "approval_id": UUID2,
        "approver_id": approver_id,
        "approver_role": role,
        "approved_at": "2026-12-31T23:30:00Z",
        "scope_hash": compute_scope_hash(bound_scope),
        "expires_at": "2030-01-01T01:00:00Z",
    }


def action_request(*, reversible: bool = True) -> dict:
    bound_scope = scope(irreversible=not reversible)
    approval = {
        "approval_class": "two_person_reversible" if reversible else "two_person_irreversible",
        "human_approvals": [
            human_approval("incident_commander", "human-01", bound_scope),
            human_approval("service_owner", "human-02", bound_scope),
        ],
    }
    result = {
        "schema_version": "1.0.0",
        "request_id": UUID2,
        "incident_id": UUID1,
        "created_at": "2026-12-31T23:00:00Z",
        "action_status": "approved",
        "action_category": bound_scope["action_category"],
        "action_type": bound_scope["action_type"],
        "target": bound_scope["target"],
        "exact_scope": bound_scope["exact_scope"],
        "environment": "production",
        "expires_at": bound_scope["expires_at"],
        "expected_effect": "Challenge invalid traffic on one registered route.",
        "risk": "Legitimate clients may see an additional challenge.",
        "blast_radius": "One registered route for five minutes.",
        "preconditions": ["Incident remains active."],
        "reversible": reversible,
        "timeout_seconds": 300,
        "approval": approval,
        "approval_class": approval["approval_class"],
        "scope_hash": compute_scope_hash(bound_scope),
        "verification_query": "edge.challenge.effectiveness.v1",
    }
    if reversible:
        result.update(
            {
                "rollback_trigger": "Verified business failure rate exceeds threshold.",
                "rollback_steps": ["Restore the prior registered edge policy version."],
                "rollback_timeout_seconds": 300,
                "rollback_verification_query": "edge.policy.version.v1",
            }
        )
    else:
        result.update(
            {
                "irreversibility_reason": "The external recipient may retain delivered content.",
                "compensating_actions": ["Issue a separately approved corrective notice."],
                "stop_conditions": ["Authorization expires before send starts."],
            }
        )
    return result


def assert_valid(schema: str, instance: dict) -> None:
    assert validate_schema_instance(schema, instance, ROOT) == []


def assert_invalid(schema: str, instance: dict) -> None:
    assert validate_schema_instance(schema, instance, ROOT)


RULE_SKILL = ROOT / "skills/shared/engineer-sigma-yara-rules"


def synthetic_sigma_match(rule: dict, event: dict) -> bool:
    selection = rule["detection"]["selection"]
    for expression, expected in selection.items():
        field, *modifiers = expression.split("|")
        actual = str(event.get(field, ""))
        values = expected if isinstance(expected, list) else [expected]
        if not modifiers:
            matched = event.get(field) in values
        elif modifiers == ["endswith"]:
            matched = any(actual.endswith(str(value)) for value in values)
        elif modifiers == ["contains"]:
            matched = any(str(value) in actual for value in values)
        else:
            raise ValueError(f"unsupported synthetic Sigma modifier: {modifiers}")
        if not matched:
            return False
    condition = rule["detection"]["condition"]
    if condition != "selection":
        raise ValueError(f"unsupported synthetic Sigma condition: {condition}")
    return True


def detection_test_result(
    rule_id: str, backend: str, artifact_hash: str, cases: list[dict], status: str,
    release_stage: str = "experimental",
) -> dict:
    return {
        "schema_version": "1.0.0",
        "test_id": UUID2,
        "rule_id": rule_id,
        "tested_at": "2030-01-01T00:00:00Z",
        "release_stage": release_stage,
        "backend": backend,
        "artifact_hash": artifact_hash,
        "status": status,
        "test_cases": cases,
        "evidence": [evidence()],
    }


def test_all_nine_root_schemas_are_offline_draft_2020_12() -> None:
    expected = {
        "incident-event",
        "agent-response",
        "action-request",
        "notification-request",
        "normalized-security-event",
        "threat-model",
        "detection-rule-test",
        "ioc-enrichment-request",
        "mcp-query-request",
    }
    observed = {path.name.removesuffix(".schema.json") for path in (ROOT / "schemas").glob("*.schema.json")}
    assert observed == expected
    for name in observed:
        document = load_json_strict(ROOT / "schemas" / f"{name}.schema.json", ROOT)
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert document["$id"] == f"urn:aegis-mesh:schema:{name}:1.0.0"
        assert document["type"] == "object"
        assert document["additionalProperties"] is False
        assert "http://" not in json.dumps(document).replace(document["$schema"], "")
        assert "https://" not in json.dumps(document).replace(document["$schema"], "")


def test_incident_event_formats_confidence_and_evidence_reference() -> None:
    item = {
        "schema_version": "1.0.0",
        "incident_id": UUID1,
        "event_id": UUID2,
        "timestamp": "2026-12-31T23:00:00Z",
        "source_agent": "observability-agent",
        "target_agent": "main-security-orchestrator",
        "service": "registration-api",
        "environment": "production",
        "severity": "P1",
        "confidence": 0.75,
        "status": "investigating",
        "summary": "Elevated error rate is under investigation.",
        "facts": ["Error rate exceeded the configured signal threshold."],
        "hypotheses": ["A dependency may be degraded."],
        "unknowns": ["Root cause is not confirmed."],
        "evidence": [evidence()],
        "recommended_actions": [],
        "approval_required": True,
        "rollback_plan": "No action has been executed.",
        "verification_plan": "Compare independent service and edge telemetry.",
        "correlation_id": UUID1,
    }
    assert_valid("incident-event", item)
    for key, value in (("incident_id", "not-a-uuid"), ("timestamp", "yesterday"), ("confidence", 1.01)):
        invalid = deepcopy(item)
        invalid[key] = value
        assert_invalid("incident-event", invalid)
    invalid = deepcopy(item)
    invalid["evidence"][0]["storage_ref"] = "https://example.invalid/evidence"
    assert_invalid("incident-event", invalid)


@pytest.mark.parametrize(
    ("schema", "field", "values"),
    [
        ("agent-response", "agent_result_status", ("complete", "partial", "blocked", "failed")),
        ("action-request", "action_status", ("proposed", "awaiting_approval", "approved", "rejected", "executing", "succeeded", "failed", "compensated", "rolled_back")),
        ("notification-request", "notification_status", ("draft", "awaiting_approval", "approved", "sent", "failed", "revoked")),
        ("normalized-security-event", "parse_status", ("parsed", "partial", "rejected")),
        ("threat-model", "status", ("incomplete", "complete")),
        (
            "detection-rule-test",
            "release_stage",
            ("draft", "experimental", "validated", "staging_approved", "production_approved"),
        ),
        (
            "ioc-enrichment-request",
            "decision_status",
            ("proposed", "authorized", "denied", "completed", "failed"),
        ),
        (
            "mcp-query-request",
            "policy_status",
            ("proposed", "authorized", "denied", "completed", "failed"),
        ),
    ],
)
def test_status_specific_enums_are_closed(schema: str, field: str, values: tuple[str, ...]) -> None:
    document = load_json_strict(ROOT / "schemas" / f"{schema}.schema.json", ROOT)
    assert document["properties"][field]["enum"] == list(values)


def test_action_approval_discriminator_and_recovery_branches() -> None:
    assert_valid("action-request", action_request())
    irreversible = action_request(reversible=False)
    assert_valid("action-request", irreversible)

    one_approval = action_request()
    one_approval["approval"]["human_approvals"].pop()
    assert_invalid("action-request", one_approval)

    read_on_write_action = action_request()
    read_on_write_action["approval"] = {
        "approval_class": "policy_authorized_read",
        "policy_decision_id": UUID2,
        "policy_id": "internal-read-policy",
        "policy_version": "1.0.0",
        "scope_hash": read_on_write_action["scope_hash"],
        "decided_at": "2026-12-31T23:00:00Z",
        "expires_at": "2030-01-01T01:00:00Z",
        "audit_event_id": UUID1,
    }
    read_on_write_action["approval_class"] = "policy_authorized_read"
    assert_invalid("action-request", read_on_write_action)

    preauthorized = action_request()
    preauthorized_scope = {
        "purpose": "action",
        "schema_version": "1.0.0",
        "incident_id": UUID1,
        "action_category": "incident_control",
        "action_type": "create_incident",
        "target": {"resource_type": "incident", "resource_id": UUID1},
        "exact_scope": {"severity": "P1", "service": "registration-api", "environment": "production"},
        "environment": "production",
        "expires_at": "2030-01-01T01:00:00Z",
    }
    preauthorized.update(
        {
            "action_category": preauthorized_scope["action_category"],
            "action_type": preauthorized_scope["action_type"],
            "target": preauthorized_scope["target"],
            "exact_scope": preauthorized_scope["exact_scope"],
            "scope_hash": compute_scope_hash(preauthorized_scope),
        }
    )
    preauthorized["approval"] = {
        "approval_class": "preauthorized_reversible",
        "authorization_id": UUID2,
        "policy_id": "incident-control-policy",
        "policy_version": "1.0.0",
        "authorized_role": "incident_commander",
        "scope_hash": preauthorized["scope_hash"],
        "immutable_config_hash": HASH,
        "approved_at": "2026-12-31T23:00:00Z",
        "expires_at": "2030-01-01T01:00:00Z",
        "audit_event_id": UUID1,
    }
    preauthorized["approval_class"] = "preauthorized_reversible"
    assert_valid("action-request", preauthorized)

    irreversible_waf = action_request()
    irreversible_waf["reversible"] = False
    irreversible_waf.update(
        {
            "irreversibility_reason": "Incorrectly declared irreversible.",
            "compensating_actions": ["Escalate."],
            "stop_conditions": ["Stop."],
        }
    )
    for key in ("rollback_trigger", "rollback_steps", "rollback_timeout_seconds", "rollback_verification_query"):
        del irreversible_waf[key]
    irreversible_waf["approval"]["approval_class"] = "two_person_irreversible"
    irreversible_waf["approval_class"] = "two_person_irreversible"
    assert_invalid("action-request", irreversible_waf)


def test_semantic_approval_validation_is_fail_closed() -> None:
    request = action_request()
    request["scope"] = scope()
    assert {issue.code for issue in validate_approval_set(request, now=NOW)} == {"authorization.registry_unavailable"}

    same_person = deepcopy(request)
    same_person["approval"]["human_approvals"][1]["approver_id"] = "human-01"
    assert {issue.code for issue in validate_approval_set(same_person, now=NOW)} >= {"approval.approver_not_distinct"}

    wrong_role = deepcopy(request)
    wrong_role["approval"]["human_approvals"][1]["approver_role"] = "database_owner"
    assert {issue.code for issue in validate_approval_set(wrong_role, now=NOW)} >= {"approval.role_pair_mismatch"}

    expired = deepcopy(request)
    expired["approval"]["human_approvals"][0]["expires_at"] = "2026-01-01T00:00:00Z"
    assert {issue.code for issue in validate_approval_set(expired, now=NOW)} >= {"approval.expired"}

    disabled = deepcopy(request)
    disabled["approval"] = {
        "approval_class": "preauthorized_reversible",
        "scope_hash": disabled["scope_hash"],
        "expires_at": "2030-01-01T01:00:00Z",
    }
    disabled["approval_class"] = "preauthorized_reversible"
    assert {issue.code for issue in validate_approval_set(disabled, now=NOW)} >= {"approval.preauthorization_disabled"}


def test_recovery_semantics_require_real_rollback_or_compensation() -> None:
    assert validate_recovery_contract(action_request()) == []
    reversible = action_request()
    reversible["rollback_steps"] = []
    assert {issue.code for issue in validate_recovery_contract(reversible)} == {"recovery.rollback_required"}

    irreversible = action_request(reversible=False)
    assert validate_recovery_contract(irreversible) == []
    irreversible["approval"]["approval_class"] = "two_person_reversible"
    assert {issue.code for issue in validate_recovery_contract(irreversible)} >= {"recovery.irreversible_approval_required"}


def test_action_registration_and_scope_inputs_are_closed() -> None:
    request = action_request()
    for mutation in (
        {"action_type": "unregistered_action"},
        {"action_category": "database_recovery"},
        {"target": {"resource_type": "database", "resource_id": "db-01"}},
        {"exact_scope": {"route_ids": ["registration"], "duration_seconds": 300}},
    ):
        invalid = deepcopy(request)
        invalid.update(mutation)
        assert_invalid("action-request", invalid)
    missing_expiry = deepcopy(request)
    del missing_expiry["expires_at"]
    assert_invalid("action-request", missing_expiry)

    schema = load_json_strict(ROOT / "schemas/action-request.schema.json", ROOT)
    branches = schema["allOf"][0]["oneOf"]
    observed = {
        branch["properties"]["action_type"]["const"]: {
            "category": branch["properties"]["action_category"]["const"],
            "target": branch["properties"]["target"]["properties"]["resource_type"]["const"],
            "fields": tuple(branch["properties"]["exact_scope"]["required"]),
            "approval": branch["properties"]["approval_class"]["const"],
            "reversible": branch["properties"]["reversible"]["const"],
        }
        for branch in branches
    }
    expected = {
        action_type: {key: value for key, value in contract.items() if key != "roles"}
        for action_type, contract in ACTION_CONTRACTS.items()
    }
    assert observed == expected


def test_notification_scope_and_idempotency_are_recomputable() -> None:
    bound_scope = scope(notification=True)
    approval = {
        "approval_class": "two_person_irreversible",
        "human_approvals": [
            human_approval("incident_commander", "human-01", bound_scope),
            human_approval("legal_compliance_approver", "human-02", bound_scope),
        ],
    }
    request = {
        "schema_version": "1.0.0",
        "notification_id": UUID2,
        "incident_id": UUID1,
        "created_at": "2026-12-31T23:00:00Z",
        "notification_status": "approved",
        "action_category": "external_notification",
        "action_type": "send_abuse_notification",
        "target": bound_scope["target"],
        "exact_scope": bound_scope["exact_scope"],
        "environment": "production",
        "expires_at": bound_scope["expires_at"],
        "recipient_ref": bound_scope["recipient_ref"],
        "template_version": "1.0.0",
        "body_hash": HASH,
        "redacted_facts": ["A registered incident contains confirmed technical indicators."],
        "evidence": [evidence()],
        "scope_hash": compute_scope_hash(bound_scope),
        "approval": approval,
        "approval_class": "two_person_irreversible",
        "reversible": False,
        "irreversibility_reason": "The recipient may retain delivered content.",
        "compensating_actions": ["Send a separately approved corrective notification."],
        "stop_conditions": ["Stop if either approval expires."],
    }
    request["idempotency_key"] = compute_notification_idempotency_key(request)
    assert_valid("notification-request", request)
    assert {issue.code for issue in validate_approval_set(request, now=NOW)} == {"authorization.registry_unavailable"}

    changed = deepcopy(request)
    changed["recipient_ref"] = "different-official-contact"
    assert {issue.code for issue in validate_approval_set(changed, now=NOW)} >= {
        "approval.scope_hash_mismatch",
        "notification.idempotency_mismatch",
    }
    changed_notice = deepcopy(request)
    changed_notice["exact_scope"]["notice_id"] = UUID1
    assert {issue.code for issue in validate_approval_set(changed_notice, now=NOW)} >= {"notification.notice_id_mismatch"}

    corrective = deepcopy(request)
    corrective["action_type"] = "send_corrective_notification"
    corrective["original_notification_id"] = UUID1
    corrective["exact_scope"]["original_notice_id"] = UUID2
    assert {issue.code for issue in validate_approval_set(corrective, now=NOW)} >= {"notification.original_notice_id_mismatch"}


def test_scope_hash_binds_all_fields_and_normalizes_timestamp() -> None:
    base = scope()
    assert compute_scope_hash(base) == compute_scope_hash({**base, "expires_at": "2030-01-01T09:00:00+08:00"})
    for field in ("incident_id", "target", "exact_scope", "environment", "expires_at"):
        changed = deepcopy(base)
        if field == "incident_id":
            changed[field] = UUID2
        elif field == "target":
            changed[field]["resource_id"] = "edge-policy-02"
        elif field == "exact_scope":
            changed[field]["duration_seconds"] = 301
        elif field == "expires_at":
            changed[field] = "2030-01-01T01:00:01Z"
        else:
            changed[field] = "staging"
        assert compute_scope_hash(changed) != compute_scope_hash(base)
    for field, value in (("purpose", "unknown"), ("schema_version", "2.0.0"), ("action_category", "database_recovery"), ("action_type", "unknown_action")):
        changed = deepcopy(base)
        changed[field] = value
        with pytest.raises(ValueError):
            compute_scope_hash(changed)
    assert compute_scope_hash(scope(notification=True)) != compute_scope_hash(scope())
    notification = scope(notification=True)
    for field, value in (("recipient_ref", "official-contact-02"), ("template_version", "1.0.1"), ("body_hash", "sha256:" + "b" * 64)):
        changed = deepcopy(notification)
        changed[field] = value
        changed["exact_scope"][field] = value
        assert compute_scope_hash(changed) != compute_scope_hash(notification)
    for invalid in ("*", "edge-*", "${UNRESOLVED}", ""):
        bad = deepcopy(base)
        bad["target"]["resource_id"] = invalid
        with pytest.raises(ValueError):
            compute_scope_hash(bad)


def test_jcs_and_raw_hash_contracts_reject_non_ijson(tmp_path: Path) -> None:
    assert canonical_json_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert structured_sha256({"b": 1, "a": 2}).startswith("sha256:")
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"a\r\nb\n")
    assert raw_sha256(artifact, tmp_path) != structured_sha256("a\r\nb\n")
    for invalid in (float("nan"), float("inf"), 9007199254740992, {1: "value"}, "\ud800"):
        with pytest.raises((TypeError, ValueError)):
            canonical_json_bytes(invalid)


def test_strict_loaders_reject_non_ijson_values_and_parent_symlinks(tmp_path: Path) -> None:
    for index, payload in enumerate((b"9007199254740992", b"1e999", b'"\\ud800"')):
        candidate = tmp_path / f"invalid-{index}.json"
        candidate.write_bytes(payload)
        with pytest.raises(ValueError):
            load_json_strict(candidate, tmp_path)

    for index, payload in enumerate(("when: 2030-01-01\n", "values: !!set {a: null}\n", "1: value\n", "value: 9007199254740992\n")):
        candidate = tmp_path / f"invalid-{index}.yaml"
        candidate.write_text(payload, encoding="utf-8")
        with pytest.raises((TypeError, ValueError)):
            load_yaml_strict(candidate, tmp_path)

    real = tmp_path / "real"
    real.mkdir()
    (real / "item.json").write_text("{}", encoding="utf-8")
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError):
        load_json_strict(linked_parent / "item.json", tmp_path)


def test_strict_loaders_reject_duplicates_symlinks_and_root_escape(tmp_path: Path) -> None:
    duplicate_json = tmp_path / "duplicate.json"
    duplicate_json.write_text('{"a": 1, "a": 2}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_json_strict(duplicate_json, tmp_path)

    duplicate_yaml = tmp_path / "duplicate.yaml"
    duplicate_yaml.write_text("a: 1\na: 2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_yaml_strict(duplicate_yaml, tmp_path)

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError):
        load_json_strict(link, tmp_path)
    with pytest.raises(ValueError):
        raw_sha256(Path(__file__), tmp_path)


def test_offline_schema_registry_rejects_duplicate_ids_and_network_refs(tmp_path: Path) -> None:
    copied_root = tmp_path / "package"
    shutil.copytree(ROOT / "schemas", copied_root / "schemas")
    agent_path = copied_root / "schemas/agent-response.schema.json"
    agent = json.loads(agent_path.read_text(encoding="utf-8"))
    agent["$id"] = "urn:aegis-mesh:schema:incident-event:1.0.0"
    agent_path.write_text(json.dumps(agent), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate schema"):
        validate_schema_instance("incident-event", {}, copied_root)

    shutil.rmtree(copied_root)
    shutil.copytree(ROOT / "schemas", copied_root / "schemas")
    agent_path = copied_root / "schemas/agent-response.schema.json"
    agent = json.loads(agent_path.read_text(encoding="utf-8"))
    agent["properties"]["response_id"] = {"$ref": "https://example.invalid/schema.json"}
    agent_path.write_text(json.dumps(agent), encoding="utf-8")
    with pytest.raises(ValueError, match="unregistered or network-capable"):
        validate_schema_instance("incident-event", {}, copied_root)


def test_state_transitions_and_time_windows_are_fail_closed() -> None:
    assert validate_incident_transition("detected", "triaged")
    assert not validate_incident_transition("detected", "resolved")
    assert validate_action_transition("failed", "rolled_back", reversible=True)
    assert not validate_action_transition("failed", "rolled_back", reversible=False)
    assert validate_action_transition("failed", "compensated", reversible=False)
    assert not validate_action_transition("succeeded", "compensated", reversible=True)
    assert validate_notification_transition("approved", "sent")
    assert not validate_notification_transition("sent", "revoked")
    assert validate_time_window({"start": "2026-12-31T22:00:00Z", "end": "2026-12-31T23:00:00Z"}) == []
    assert {issue.code for issue in validate_time_window({"start": "2026-12-31T23:00:00Z", "end": "2026-12-31T22:00:00Z"})} == {"time_window.order"}
    assert {issue.code for issue in validate_time_window({"start": "2026-12-30T00:00:00Z", "end": "2026-12-31T23:00:00Z"})} == {"time_window.too_large"}


def test_evidence_references_bind_the_parent_incident() -> None:
    container = {"incident_id": UUID1, "evidence": [evidence()]}
    assert validate_evidence_references(container) == []
    container["evidence"][0]["incident_id"] = UUID2
    assert {issue.code for issue in validate_evidence_references(container)} == {"evidence.incident_mismatch"}
    embedded = {
        "incident_id": UUID1,
        "exact_scope": {"dependency_snapshot": {**evidence(), "incident_id": UUID2}},
    }
    assert {issue.code for issue in validate_evidence_references(embedded)} == {"evidence.incident_mismatch"}


def test_action_specific_semantics_reject_noops_and_noncanonical_cidrs() -> None:
    regional = {
        "action_type": "shift_regional_traffic",
        "exact_scope": {"from_region": "region-a", "to_region": "region-a", "percentage": 10, "duration_seconds": 60},
    }
    assert {issue.code for issue in validate_action_contract(regional)} >= {"action.distinct_values_required"}
    firewall = {
        "action_type": "change_broad_firewall_rule",
        "exact_scope": {
            "rule_id": "rule-01",
            "source_cidrs": ["192.0.2.1/24"],
            "destinations": ["service-a"],
            "ports": [443],
            "duration_seconds": 60,
        },
    }
    assert {issue.code for issue in validate_action_contract(firewall)} >= {"action.cidr_not_canonical"}


def test_dr_drill_scope_environment_must_match_outer_environment() -> None:
    drill = {
        "action_type": "run_isolated_dr_drill",
        "environment": "test",
        "exact_scope": {
            "drill_id": "drill-01",
            "environment": "test",
            "isolation_evidence": evidence(),
            "abort_thresholds": ["abort-on-production-reachability"],
        },
        "incident_id": UUID1,
    }
    matching_codes = {issue.code for issue in validate_action_contract(drill)}
    assert "action.environment_mismatch" not in matching_codes
    mismatched = deepcopy(drill)
    mismatched["exact_scope"]["environment"] = "staging"
    mismatch_issues = [
        issue for issue in validate_action_contract(mismatched)
        if issue.code == "action.environment_mismatch"
    ]
    assert len(mismatch_issues) == 1
    assert mismatch_issues[0].json_pointer == "/exact_scope/environment"
    for outer, inner in (
        (None, "test"),
        ("test", None),
        (1, "test"),
        ("test", 1),
        ([], "test"),
        ("test", {}),
        ("unknown", "test"),
        ("test", "unknown"),
    ):
        malformed = deepcopy(drill)
        if outer is None:
            del malformed["environment"]
        else:
            malformed["environment"] = outer
        if inner is None:
            del malformed["exact_scope"]["environment"]
        else:
            malformed["exact_scope"]["environment"] = inner
        assert "action.environment_mismatch" not in {
            issue.code for issue in validate_action_contract(malformed)
        }


def test_ioc_requires_evidence_and_mcp_query_classes_are_mutually_exclusive() -> None:
    ioc = {
        "schema_version": "1.0.0",
        "request_id": UUID2,
        "incident_id": UUID1,
        "created_at": "2026-12-31T23:00:00Z",
        "decision_status": "authorized",
        "query_class": "incident_ioc",
        "ioc_type": "domain",
        "ioc_value": "example.invalid",
        "classification": "suspicious",
        "expires_at": "2030-01-01T01:00:00Z",
        "provider": "virustotal-passive",
        "evidence": evidence(),
    }
    assert_valid("ioc-enrichment-request", ioc)
    without_evidence = deepcopy(ioc)
    del without_evidence["evidence"]
    assert_invalid("ioc-enrichment-request", without_evidence)

    query_scope = {
        "purpose": "action",
        "schema_version": "1.0.0",
        "incident_id": UUID1,
        "action_category": "security_query",
        "action_type": "query_internal_telemetry",
        "target": {"resource_type": "telemetry_source", "resource_id": "wazuh-cluster-01"},
        "exact_scope": {
            "incident_id": UUID1,
            "internal_resource_ref": "wazuh-alert-index",
            "query_name": "incident-alert-window",
            "time_window": {"start": "2026-12-31T22:00:00Z", "end": "2026-12-31T23:00:00Z"},
        },
        "environment": "production",
        "expires_at": "2030-01-01T01:00:00Z",
    }
    query = {
        "schema_version": "1.0.0",
        "request_id": UUID2,
        "incident_id": UUID1,
        "created_at": "2026-12-31T23:00:00Z",
        "policy_status": "authorized",
        "query_class": "internal_security_telemetry",
        "requesting_agent": "observability-agent",
        "action_category": "security_query",
        "action_type": "query_internal_telemetry",
        "target": query_scope["target"],
        "exact_scope": query_scope["exact_scope"],
        "environment": "production",
        "expires_at": query_scope["expires_at"],
        "internal_resource_ref": "wazuh-alert-index",
        "tool_name": "get_wazuh_alerts",
        "query_name": "incident-alert-window",
        "time_window": {"start": "2026-12-31T22:00:00Z", "end": "2026-12-31T23:00:00Z"},
        "scope_hash": compute_scope_hash(query_scope),
        "approval_class": "policy_authorized_read",
        "approval": {
            "approval_class": "policy_authorized_read",
            "policy_decision_id": UUID2,
            "policy_id": "internal-read-policy",
            "policy_version": "1.0.0",
            "scope_hash": compute_scope_hash(query_scope),
            "decided_at": "2026-12-31T23:00:00Z",
            "expires_at": "2030-01-01T01:00:00Z",
            "audit_event_id": UUID1,
        },
    }
    assert_valid("mcp-query-request", query)
    assert {issue.code for issue in validate_approval_set(query, now=NOW)} == {
        "approval.policy_registry_unavailable",
        "authorization.registry_unavailable",
    }
    mismatched_query = deepcopy(query)
    mismatched_query["internal_resource_ref"] = "different-index"
    assert {issue.code for issue in validate_approval_set(mismatched_query, now=NOW)} >= {"query.executable_scope_mismatch"}
    mixed = deepcopy(query)
    mixed["owned_asset_id"] = "asset-01"
    assert_invalid("mcp-query-request", mixed)

    ioc_query = deepcopy(query)
    for field in ("internal_resource_ref", "time_window"):
        del ioc_query[field]
    ioc_scope = {
        "purpose": "action", "schema_version": "1.0.0", "incident_id": UUID1,
        "action_category": "security_query", "action_type": "enrich_incident_ioc_passive",
        "target": {"resource_type": "incident_ioc", "resource_id": "ioc-01"},
        "exact_scope": {
            "incident_id": UUID1, "evidence_id": UUID1, "ioc_type": "domain",
            "expires_at": "2030-01-01T01:00:00Z", "provider": "virustotal-passive",
        },
        "environment": "production", "expires_at": "2030-01-01T01:00:00Z",
    }
    ioc_query.update({
        "query_class": "incident_ioc", "action_type": "enrich_incident_ioc_passive",
        "target": ioc_scope["target"], "exact_scope": ioc_scope["exact_scope"],
        "ioc_type": "domain", "ioc_value": "example.invalid", "classification": "suspicious",
        "provider": "virustotal-passive", "evidence": evidence(),
        "scope_hash": compute_scope_hash(ioc_scope),
    })
    ioc_query["approval"]["scope_hash"] = ioc_query["scope_hash"]
    assert_valid("mcp-query-request", ioc_query)
    assert {issue.code for issue in validate_approval_set(ioc_query, now=NOW)} >= {"query.evidence_id_mismatch"}


def test_complete_threat_model_contains_all_stride_categories() -> None:
    categories = ("spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege")
    elements = (
        ("browser", "Attendee browser"),
        ("registration-api", "Registration API"),
        ("registration-db", "Registration database"),
    )
    model = {
        "schema_version": "1.0.0",
        "model_id": UUID1,
        "created_at": "2026-12-31T23:00:00Z",
        "status": "complete",
        "system": "registration-platform",
        "entities": [{"element_id": elements[0][0], "name": "attendee-browser", "description": elements[0][1]}],
        "processes": [{"element_id": elements[1][0], "name": "registration-api", "description": elements[1][1]}],
        "data_stores": [{"element_id": elements[2][0], "name": "registration-db", "description": elements[2][1]}],
        "assets": ["registration-records"],
        "trust_boundaries": ["internet-to-edge"],
        "data_classifications": ["personal-registration-data"],
        "calling_identities": ["attendee-session"],
        "data_flows": [{
            "flow_id": "browser-to-registration-api", "source_element_id": "browser",
            "destination_element_id": "registration-api", "data_classification": "personal-registration-data",
            "trust_boundaries": ["internet-to-edge"],
        }],
        "controls": [{"control_id": "authz-01", "element_ids": ["registration-api"], "description": "Object authorization control."}],
        "threats": [
            {
                "threat_id": f"T-{element_index}-{category_index}", "element_id": element_id,
                "category": category, "description": "Reviewed threat disposition.",
                "disposition": "mitigated", "mitigations": ["Registered mitigation."],
            }
            for element_index, element_id in enumerate(
                ("browser", "registration-api", "registration-db", "browser-to-registration-api"),
                start=1,
            )
            for category_index, category in enumerate(categories, start=1)
        ],
    }
    assert_valid("threat-model", model)
    assert validate_threat_model(model) == []
    dangling = deepcopy(model)
    dangling["data_flows"][0]["destination_element_id"] = "missing-process"
    dangling["controls"][0]["element_ids"] = ["missing-process"]
    dangling["threats"][0]["element_id"] = "missing-process"
    assert {issue.code for issue in validate_threat_model(dangling)} >= {
        "threat_model.dangling_flow_endpoint", "threat_model.dangling_control_reference", "threat_model.dangling_threat_reference",
    }
    duplicates = deepcopy(model)
    duplicates["data_flows"].append({**duplicates["data_flows"][0], "destination_element_id": "registration-db"})
    duplicates["controls"].append({**duplicates["controls"][0], "description": "Duplicate identifier."})
    duplicates["threats"][1]["threat_id"] = duplicates["threats"][0]["threat_id"]
    assert {issue.code for issue in validate_threat_model(duplicates)} >= {"threat_model.element_id_not_unique"}

    incomplete = deepcopy(dangling)
    incomplete["status"] = "incomplete"
    incomplete["missing_inputs"] = ["Destination process inventory is incomplete."]
    assert {issue.code for issue in validate_threat_model(incomplete)} >= {"threat_model.dangling_flow_endpoint"}
    model["threats"] = [
        threat for threat in model["threats"]
        if not (threat["element_id"] == "browser" and threat["category"] == "elevation_of_privilege")
    ]
    assert_valid("threat-model", model)
    assert {issue.code for issue in validate_threat_model(model)} == {"threat_model.stride_coverage_incomplete"}


def test_sigma_rules_parse_convert_and_use_positive_negative_fixtures() -> None:
    valid_path = RULE_SKILL / "tests/rules/sigma-valid.yaml"
    high_fp_path = RULE_SKILL / "tests/rules/sigma-high-fp.yaml"
    positive_path = RULE_SKILL / "tests/positive/sysmon-synthetic-suspicious.json"
    negative_path = RULE_SKILL / "tests/negative/sysmon-legitimate-maintenance.json"
    valid = load_yaml_strict(valid_path, ROOT)
    high_fp = load_yaml_strict(high_fp_path, ROOT)
    positive = load_json_strict(positive_path, ROOT)
    negative = load_json_strict(negative_path, ROOT)
    assert all(isinstance(item, dict) for item in (valid, high_fp, positive, negative))

    assert package_version("pysigma") == "1.4.0"
    assert package_version("pysigma-backend-elasticsearch") == "2.1.0"
    assert package_version("pysigma-pipeline-sysmon") == "2.0.0"
    for path in (valid_path, high_fp_path):
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        queries = LuceneBackend(processing_pipeline=sysmon_pipeline()).convert(collection)
        assert len(queries) == 1 and isinstance(queries[0], str) and queries[0]
        repeated = LuceneBackend(processing_pipeline=sysmon_pipeline()).convert(
            SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        )
        assert repeated == queries

    assert synthetic_sigma_match(valid, positive) is True
    assert synthetic_sigma_match(valid, negative) is False
    assert synthetic_sigma_match(high_fp, positive) is True
    assert synthetic_sigma_match(high_fp, negative) is True
    unsupported_modifier = deepcopy(valid)
    unsupported_modifier["detection"]["selection"] = {"Image|startswith": "C:\\Windows"}
    with pytest.raises(ValueError, match="unsupported synthetic Sigma modifier"):
        synthetic_sigma_match(unsupported_modifier, positive)
    unsupported_condition = deepcopy(valid)
    unsupported_condition["detection"]["condition"] = "selection or another"
    with pytest.raises(ValueError, match="unsupported synthetic Sigma condition"):
        synthetic_sigma_match(unsupported_condition, positive)
    assert valid["status"] == "experimental" and high_fp["status"] == "test"

    valid_result = detection_test_result(
        valid["id"], "elasticsearch-lucene", raw_sha256(valid_path, ROOT),
        [
            {"case_id": "sigma-positive", "expected_match": True, "observed_match": True},
            {"case_id": "sigma-negative", "expected_match": False, "observed_match": False},
        ],
        "passed",
    )
    high_fp_result = detection_test_result(
        high_fp["id"], "elasticsearch-lucene", raw_sha256(high_fp_path, ROOT),
        [{"case_id": "sigma-high-fp-negative", "expected_match": False, "observed_match": True}],
        "failed", "draft",
    )
    assert_valid("detection-rule-test", valid_result)
    assert_valid("detection-rule-test", high_fp_result)


def test_yara_rules_compile_and_use_positive_negative_fixtures() -> None:
    valid_path = RULE_SKILL / "tests/rules/yara-valid.yar"
    high_fp_path = RULE_SKILL / "tests/rules/yara-high-fp.yar"
    positive_path = RULE_SKILL / "tests/positive/yara-synthetic-marker.txt"
    negative_path = RULE_SKILL / "tests/negative/yara-benign-software.txt"
    assert package_version("yara-python") == "4.5.4"
    valid_rules = yara.compile(filepath=str(valid_path), error_on_warning=True)
    high_fp_rules = yara.compile(filepath=str(high_fp_path), error_on_warning=True)
    assert len(valid_rules.match(filepath=str(positive_path))) == 1
    assert valid_rules.match(filepath=str(negative_path)) == []
    assert len(high_fp_rules.match(filepath=str(positive_path))) == 1
    assert len(high_fp_rules.match(filepath=str(negative_path))) == 1
    oversized = b"MZ\nAEGIS_MESH_SYNTHETIC_FORMAT\nAEGIS_MESH_SYNTHETIC_SUSPICIOUS_MARKER\n" + b"A" * 1_048_576
    assert valid_rules.match(data=oversized) == []
    valid_text = valid_path.read_text(encoding="utf-8")
    high_fp_text = high_fp_path.read_text(encoding="utf-8")
    assert raw_sha256(positive_path, ROOT) in valid_text
    assert raw_sha256(negative_path, ROOT) in high_fp_text

    valid_result = detection_test_result(
        "Aegis_Mesh_Synthetic_Marker", "yara-python-4.5.4", raw_sha256(valid_path, ROOT),
        [
            {"case_id": "yara-positive", "expected_match": True, "observed_match": True},
            {"case_id": "yara-negative", "expected_match": False, "observed_match": False},
        ],
        "passed",
    )
    high_fp_result = detection_test_result(
        "Aegis_Mesh_Synthetic_High_FP", "yara-python-4.5.4", raw_sha256(high_fp_path, ROOT),
        [{"case_id": "yara-high-fp-negative", "expected_match": False, "observed_match": True}],
        "failed", "draft",
    )
    assert_valid("detection-rule-test", valid_result)
    assert_valid("detection-rule-test", high_fp_result)


def test_stride_complete_status_requires_boundaries_classifications_and_identities() -> None:
    categories = (
        "spoofing", "tampering", "repudiation", "information_disclosure",
        "denial_of_service", "elevation_of_privilege",
    )
    applicable = (
        "external-user", "api-process", "data-store", "user-to-api",
    )
    model = {
        "schema_version": "1.0.0",
        "model_id": UUID1,
        "created_at": "2030-01-01T00:00:00Z",
        "status": "complete",
        "system": "synthetic-system",
        "entities": [{"element_id": "external-user", "name": "external-user", "description": "Synthetic external entity."}],
        "processes": [{"element_id": "api-process", "name": "api-process", "description": "Synthetic API process."}],
        "data_stores": [{"element_id": "data-store", "name": "data-store", "description": "Synthetic data store."}],
        "data_flows": [{
            "flow_id": "user-to-api", "source_element_id": "external-user",
            "destination_element_id": "api-process", "data_classification": "confidential",
            "trust_boundaries": ["internet-boundary"],
        }],
        "trust_boundaries": ["internet-boundary"],
        "assets": ["protected-data"],
        "data_classifications": ["confidential"],
        "calling_identities": ["caller-session"],
        "controls": [{"control_id": "control-01", "element_ids": ["api-process"], "description": "Synthetic authorization control."}],
        "threats": [
            {
                "threat_id": f"T-{element_index}-{category_index}", "element_id": element_id,
                "category": category, "description": "Reviewed synthetic disposition.",
                "disposition": "mitigated", "mitigations": ["Synthetic control validation."],
            }
            for element_index, element_id in enumerate(applicable, start=1)
            for category_index, category in enumerate(categories, start=1)
        ],
    }
    assert_valid("threat-model", model)
    assert validate_threat_model(model) == []
    for field in ("trust_boundaries", "assets", "data_classifications", "calling_identities"):
        invalid = deepcopy(model)
        invalid[field] = []
        assert_invalid("threat-model", invalid)

    duplicate = deepcopy(model)
    duplicate["threats"].append({
        **duplicate["threats"][0],
        "threat_id": "T-conflicting-spoofing",
        "disposition": "accepted",
        "description": "Conflicting synthetic disposition.",
    })
    assert_valid("threat-model", duplicate)
    assert validate_threat_model(duplicate) == []
    incomplete_duplicate = deepcopy(duplicate)
    incomplete_duplicate["status"] = "incomplete"
    incomplete_duplicate["missing_inputs"] = ["The model inventory is still incomplete."]
    assert validate_threat_model(incomplete_duplicate) == []

    incomplete = deepcopy(model)
    incomplete["status"] = "incomplete"
    incomplete["trust_boundaries"] = []
    incomplete["assets"] = []
    incomplete["data_classifications"] = []
    incomplete["calling_identities"] = []
    incomplete["data_flows"] = []
    incomplete["threats"] = [
        threat for threat in incomplete["threats"] if threat["element_id"] != "user-to-api"
    ]
    incomplete["missing_inputs"] = [
        "Trust boundaries, assets, classifications, and calling identities are missing."
    ]
    assert_valid("threat-model", incomplete)
    assert validate_threat_model(incomplete) == []

    empty_gaps = deepcopy(incomplete)
    empty_gaps["missing_inputs"] = []
    assert_invalid("threat-model", empty_gaps)

    internal_flow = deepcopy(model)
    internal_flow["data_flows"][0]["trust_boundaries"] = []
    assert_valid("threat-model", internal_flow)
    assert validate_threat_model(internal_flow) == []


def test_forward_result_checker_fails_closed_before_schema_free_acceptance() -> None:
    issues = validate_forward_records([], ROOT)
    assert [(issue.code, issue.path) for issue in issues] == [
        ("forward.case_inventory", "results"),
    ]
