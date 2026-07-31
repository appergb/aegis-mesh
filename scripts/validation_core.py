"""Fail-closed validation primitives shared by tests and package CLIs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from referencing import Registry, Resource
import rfc8785
from ruamel.yaml import YAML


SAFE_INTEGER_MAX = 9_007_199_254_740_991
MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_NESTING_DEPTH = 100
MAX_JSON_NODES = 100_000
HASH_PREFIX = "sha256:"
REGISTERED_ENVIRONMENTS = frozenset({"development", "test", "staging", "production"})
BASE_SCOPE_FIELDS = frozenset(
    {
        "purpose",
        "schema_version",
        "incident_id",
        "action_category",
        "action_type",
        "target",
        "exact_scope",
        "environment",
        "expires_at",
    }
)
NOTIFICATION_SCOPE_FIELDS = frozenset({"recipient_ref", "template_version", "body_hash"})
RFC3339_PATTERN = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T"
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?P<offset>Z|[+-][0-9]{2}:[0-9]{2})$"
)


ACTION_CONTRACTS: dict[str, dict[str, object]] = {
    "create_incident": {"category": "incident_control", "target": "incident", "fields": ("severity", "service", "environment"), "approval": "preauthorized_reversible", "roles": (), "reversible": True},
    "update_incident_status": {"category": "incident_control", "target": "incident", "fields": ("from_status", "to_status", "reason"), "approval": "preauthorized_reversible", "roles": (), "reversible": True},
    "append_timeline_event": {"category": "incident_control", "target": "incident", "fields": ("event_id", "timestamp", "evidence_ids"), "approval": "preauthorized_reversible", "roles": (), "reversible": True},
    "apply_waf_challenge": {"category": "edge_protection", "target": "edge_policy", "fields": ("route_ids", "match_rule_id", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "apply_edge_rate_limit": {"category": "edge_protection", "target": "edge_policy", "fields": ("route_ids", "principal_classes", "rate", "window_seconds", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "block_exact_invalid_pattern": {"category": "edge_protection", "target": "edge_policy", "fields": ("pattern_id", "route_ids", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "degrade_non_core_route": {"category": "edge_protection", "target": "service_route", "fields": ("route_ids", "degradation_mode", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "throttle_qr_issuance": {"category": "identity_session_control", "target": "qr_event", "fields": ("event_id", "role", "rate", "window_seconds", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "force_server_qr_verification": {"category": "identity_session_control", "target": "qr_event", "fields": ("event_id", "credential_classes", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "revoke_exact_credentials": {"category": "identity_session_control", "target": "credential_set", "fields": ("credential_ids", "reason"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "apply_endpoint_rate_limit": {"category": "identity_session_control", "target": "api_endpoint", "fields": ("endpoint_ids", "principal_ids", "rate", "window_seconds", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "revoke_exact_session": {"category": "identity_session_control", "target": "session_set", "fields": ("session_ids", "reason"), "approval": "two_person_irreversible", "roles": ("incident_commander", "service_owner"), "reversible": False},
    "revoke_exact_api_credential": {"category": "identity_session_control", "target": "api_credential_set", "fields": ("credential_ids", "reason"), "approval": "two_person_irreversible", "roles": ("incident_commander", "service_owner"), "reversible": False},
    "scale_exact_workload": {"category": "compute_recovery", "target": "workload", "fields": ("namespace", "workload_name", "replicas", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "restart_exact_workload": {"category": "compute_recovery", "target": "workload", "fields": ("namespace", "workload_name", "rollout_strategy", "max_unavailable"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "shift_queue_or_cache_mode": {"category": "compute_recovery", "target": "service_dependency", "fields": ("service_id", "mode_from", "mode_to", "duration_seconds"), "approval": "two_person_reversible", "roles": ("incident_commander", "service_owner"), "reversible": True},
    "replace_certificate": {"category": "infrastructure_change", "target": "certificate", "fields": ("certificate_id", "new_version_ref", "activation_window"), "approval": "two_person_high_impact", "roles": ("incident_commander", "infrastructure_owner"), "reversible": True},
    "change_dns_authority": {"category": "infrastructure_change", "target": "dns_zone", "fields": ("zone_id", "current_nameservers", "desired_nameservers", "ttl"), "approval": "two_person_high_impact", "roles": ("incident_commander", "infrastructure_owner"), "reversible": True},
    "shift_regional_traffic": {"category": "infrastructure_change", "target": "traffic_policy", "fields": ("from_region", "to_region", "percentage", "duration_seconds"), "approval": "two_person_high_impact", "roles": ("incident_commander", "infrastructure_owner"), "reversible": True},
    "change_broad_firewall_rule": {"category": "infrastructure_change", "target": "firewall_policy", "fields": ("rule_id", "source_cidrs", "destinations", "ports", "duration_seconds"), "approval": "two_person_high_impact", "roles": ("incident_commander", "infrastructure_owner"), "reversible": True},
    "promote_database_primary": {"category": "database_recovery", "target": "database_cluster", "fields": ("cluster_id", "candidate_id", "expected_data_loss"), "approval": "two_person_high_impact", "roles": ("incident_commander", "database_owner"), "reversible": True},
    "failover_database": {"category": "database_recovery", "target": "database_cluster", "fields": ("cluster_id", "from_node", "to_node", "expected_data_loss"), "approval": "two_person_high_impact", "roles": ("incident_commander", "database_owner"), "reversible": True},
    "restore_database": {"category": "database_recovery", "target": "database", "fields": ("backup_id", "restore_point", "destination_id", "expected_data_loss"), "approval": "two_person_high_impact", "roles": ("incident_commander", "database_owner"), "reversible": True},
    "change_database_schema": {"category": "database_recovery", "target": "database", "fields": ("migration_id", "schema_objects", "compatibility_mode"), "approval": "two_person_high_impact", "roles": ("incident_commander", "database_owner"), "reversible": True},
    "terminate_query_set": {"category": "database_recovery", "target": "database", "fields": ("query_ids", "session_ids", "reason"), "approval": "two_person_irreversible", "roles": ("incident_commander", "database_owner"), "reversible": False},
    "delete_database_data": {"category": "database_recovery", "target": "database", "fields": ("record_set_ref", "legal_basis", "deletion_method"), "approval": "two_person_irreversible", "roles": ("incident_commander", "database_owner"), "reversible": False},
    "execute_registered_failover": {"category": "disaster_recovery", "target": "recovery_plan", "fields": ("runbook_id", "from_region", "to_region", "dependency_snapshot"), "approval": "two_person_high_impact", "roles": ("incident_commander", "infrastructure_owner"), "reversible": True},
    "execute_registered_failback": {"category": "disaster_recovery", "target": "recovery_plan", "fields": ("runbook_id", "from_region", "to_region", "consistency_checkpoint"), "approval": "two_person_high_impact", "roles": ("incident_commander", "infrastructure_owner"), "reversible": True},
    "run_isolated_dr_drill": {"category": "disaster_recovery", "target": "recovery_drill", "fields": ("drill_id", "environment", "isolation_evidence", "abort_thresholds"), "approval": "two_person_high_impact", "roles": ("security_owner", "system_owner"), "reversible": True},
    "release_detection_rule": {"category": "detection_release", "target": "detection_rule", "fields": ("rule_id", "release_stage", "backend", "artifact_hash"), "approval": "two_person_high_impact", "roles": ("detection_engineering_reviewer", "siem_edr_owner"), "reversible": True},
    "disable_detection_rule": {"category": "detection_release", "target": "detection_rule", "fields": ("rule_id", "reason", "duration_seconds"), "approval": "two_person_reversible", "roles": ("detection_engineering_reviewer", "siem_edr_owner"), "reversible": True},
    "export_evidence": {"category": "evidence_governance", "target": "evidence_set", "fields": ("evidence_ids", "recipient_ref", "fields", "purpose", "expiry"), "approval": "two_person_irreversible", "roles": ("incident_commander", "privacy_legal_approver"), "reversible": False},
    "change_legal_hold": {"category": "evidence_governance", "target": "legal_hold", "fields": ("evidence_ids", "current_state", "desired_state", "legal_basis"), "approval": "two_person_high_impact", "roles": ("incident_commander", "privacy_legal_approver"), "reversible": True},
    "delete_evidence": {"category": "evidence_governance", "target": "evidence_set", "fields": ("evidence_ids", "retention_basis", "deletion_method"), "approval": "two_person_irreversible", "roles": ("incident_commander", "privacy_legal_approver"), "reversible": False},
}

NOTIFICATION_CONTRACTS: dict[str, dict[str, object]] = {
    action_type: {"category": "external_notification", "target": "notification_recipient", "approval": "two_person_irreversible", "roles": ("incident_commander", "legal_compliance_approver"), "reversible": False}
    for action_type in ("send_abuse_notification", "send_cert_notification", "send_provider_abuse_report", "send_corrective_notification")
}

QUERY_CONTRACTS: dict[str, dict[str, object]] = {
    "query_internal_telemetry": {"category": "security_query", "query_class": "internal_security_telemetry", "target": "telemetry_source", "fields": ("incident_id", "internal_resource_ref", "query_name", "time_window")},
    "query_owned_asset_passive": {"category": "security_query", "query_class": "owned_asset", "target": "owned_asset", "fields": ("owned_asset_id", "query_name", "result_limit")},
    "enrich_incident_ioc_passive": {"category": "security_query", "query_class": "incident_ioc", "target": "incident_ioc", "fields": ("incident_id", "evidence_id", "ioc_type", "expires_at", "provider")},
}

ROOT_SCHEMA_NAMES = frozenset(
    {
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
)


@dataclass(frozen=True, order=True)
class SemanticIssue:
    path: str
    json_pointer: str
    code: str
    message: str


def _secure_read(path: Path, root: Path) -> bytes:
    root_resolved = root.resolve(strict=True)
    candidate = path if path.is_absolute() else root_resolved / path
    lexical = Path(os.path.abspath(candidate))
    try:
        relative = lexical.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"path escapes validation root: {candidate}") from exc
    current = root_resolved
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"symbolic links are not accepted: {current}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"path escapes validation root: {candidate}") from exc

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"path is not a regular file: {candidate}")
        if metadata.st_size > MAX_INPUT_BYTES:
            raise ValueError(f"validation input exceeds {MAX_INPUT_BYTES} bytes: {candidate}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-I-JSON numeric constant: {value}")


def load_json_strict(path: Path, root: Path) -> object:
    payload = _secure_read(path, root)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("JSON must be UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg}") from exc
    _validate_ijson(value)
    return value


def load_yaml_strict(path: Path, root: Path) -> object:
    payload = _secure_read(path, root)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("YAML must be UTF-8") from exc
    yaml = YAML(typ="safe", pure=True)
    yaml.version = (1, 2)
    yaml.allow_duplicate_keys = False
    try:
        value = yaml.load(text)
    except Exception as exc:
        raise ValueError(f"invalid strict YAML: {exc}") from exc
    _validate_ijson(value)
    return value


def _validate_ijson(
    value: object,
    pointer: str = "",
    *,
    depth: int = 0,
    counter: list[int] | None = None,
) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValueError(f"JSON nesting exceeds {MAX_NESTING_DEPTH} at {pointer or '/'}")
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_JSON_NODES:
        raise ValueError(f"JSON node count exceeds {MAX_JSON_NODES}")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
            raise ValueError(f"integer outside I-JSON safe range at {pointer or '/'}")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"non-finite number at {pointer or '/'}")
        return
    if type(value) is str:
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError(f"lone surrogate at {pointer or '/'}")
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_ijson(item, f"{pointer}/{index}", depth=depth + 1, counter=counter)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError(f"non-string object key at {pointer or '/'}")
            _validate_ijson(key, f"{pointer}/<key>", depth=depth + 1, counter=counter)
            escaped = key.replace("~", "~0").replace("/", "~1")
            _validate_ijson(item, f"{pointer}/{escaped}", depth=depth + 1, counter=counter)
        return
    raise TypeError(f"non-JSON type at {pointer or '/'}: {type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    _validate_ijson(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeEncodeError) as exc:
        raise ValueError(f"value cannot be JCS canonicalized: {exc}") from exc


def structured_sha256(value: object) -> str:
    return HASH_PREFIX + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def raw_bytes_sha256(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("raw hash input must be bytes")
    return HASH_PREFIX + hashlib.sha256(value).hexdigest()


def raw_sha256(path: Path, root: Path) -> str:
    return raw_bytes_sha256(_secure_read(path, root))


def _parse_timestamp(value: object, pointer: str) -> datetime:
    if not isinstance(value, str) or RFC3339_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{pointer} must be an RFC3339 timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{pointer} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{pointer} must include an offset")
    return parsed.astimezone(timezone.utc)


def _utc_second(value: object, pointer: str) -> str:
    parsed = _parse_timestamp(value, pointer).replace(microsecond=0)
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _reject_unresolved_scope_values(value: object, pointer: str = "") -> None:
    if isinstance(value, str):
        if not value or any(character in value for character in ("*", "?", "[", "]")):
            raise ValueError(f"empty, wildcard, or glob scope value at {pointer or '/'}")
        if "${" in value or value.lower().startswith(("alias:", "unresolved:")):
            raise ValueError(f"unresolved scope value at {pointer or '/'}")
    elif isinstance(value, Mapping):
        if not value:
            raise ValueError(f"empty scope object at {pointer or '/'}")
        for key, item in value.items():
            _reject_unresolved_scope_values(item, f"{pointer}/{key}")
    elif isinstance(value, list):
        if not value:
            raise ValueError(f"empty scope array at {pointer or '/'}")
        for index, item in enumerate(value):
            _reject_unresolved_scope_values(item, f"{pointer}/{index}")


def compute_scope_hash(scope: Mapping[str, object]) -> str:
    if not isinstance(scope, Mapping):
        raise TypeError("scope must be a mapping")
    purpose = scope.get("purpose")
    if purpose not in {"action", "notification"}:
        raise ValueError("scope purpose must be action or notification")
    expected = BASE_SCOPE_FIELDS | (NOTIFICATION_SCOPE_FIELDS if purpose == "notification" else frozenset())
    if set(scope) != expected:
        missing = sorted(expected - set(scope))
        extra = sorted(set(scope) - expected)
        raise ValueError(f"scope fields are not closed; missing={missing}, extra={extra}")
    target = scope.get("target")
    if not isinstance(target, Mapping) or set(target) != {"resource_type", "resource_id"}:
        raise ValueError("target must contain only resource_type and resource_id")
    if not isinstance(scope.get("exact_scope"), Mapping):
        raise ValueError("exact_scope must be a closed object")
    if scope.get("schema_version") != "1.0.0":
        raise ValueError("scope schema_version must be 1.0.0")
    if scope.get("environment") not in REGISTERED_ENVIRONMENTS:
        raise ValueError("scope environment is not registered")
    if not isinstance(scope.get("incident_id"), str) or re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        scope["incident_id"],
    ) is None:
        raise ValueError("scope incident_id must be a UUID")
    action_type = scope.get("action_type")
    contract = NOTIFICATION_CONTRACTS.get(action_type) if purpose == "notification" else (ACTION_CONTRACTS.get(action_type) or QUERY_CONTRACTS.get(action_type))
    if contract is None:
        raise ValueError("scope action_type is not registered for its purpose")
    if scope.get("action_category") != contract["category"]:
        raise ValueError("scope action_category does not match action_type")
    if target.get("resource_type") != contract["target"]:
        raise ValueError("scope target resource_type does not match action_type")
    if purpose == "action" and set(scope["exact_scope"]) != set(contract["fields"]):
        raise ValueError("scope exact_scope fields do not match action_type")
    if purpose == "notification":
        required_notification_fields = {"notice_id", "recipient_ref", "template_version", "body_hash"}
        if action_type == "send_corrective_notification":
            required_notification_fields.add("original_notice_id")
        if set(scope["exact_scope"]) != required_notification_fields:
            raise ValueError("notification exact_scope fields do not match action_type")
        if scope["recipient_ref"] != scope["exact_scope"].get("recipient_ref"):
            raise ValueError("notification recipient_ref differs from exact_scope")
        if scope["template_version"] != scope["exact_scope"].get("template_version"):
            raise ValueError("notification template_version differs from exact_scope")
        if scope["body_hash"] != scope["exact_scope"].get("body_hash"):
            raise ValueError("notification body_hash differs from exact_scope")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(scope["template_version"])) is None:
            raise ValueError("notification template_version must be SemVer")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", str(scope["body_hash"])) is None:
            raise ValueError("notification body_hash must be SHA-256")
    normalized = dict(scope)
    normalized["expires_at"] = _utc_second(scope["expires_at"], "/expires_at")
    _reject_unresolved_scope_values(normalized)
    return structured_sha256(normalized)


def compute_notification_idempotency_key(request: Mapping[str, object]) -> str:
    fields = ("incident_id", "notification_id", "recipient_ref", "body_hash", "scope_hash")
    if any(field not in request for field in fields):
        raise ValueError("notification idempotency inputs are incomplete")
    return structured_sha256({field: request[field] for field in fields})


def _issue(code: str, pointer: str, message: str) -> SemanticIssue:
    return SemanticIssue(path="request", json_pointer=pointer, code=code, message=message)


def _scope_from_request(request: Mapping[str, object]) -> dict[str, object]:
    purpose = "notification" if "notification_id" in request else "action"
    fields = (
        "schema_version",
        "incident_id",
        "action_category",
        "action_type",
        "target",
        "exact_scope",
        "environment",
        "expires_at",
    )
    result: dict[str, object] = {"purpose": purpose}
    for field in fields:
        if field not in request:
            raise ValueError(f"request lacks scope input: {field}")
        result[field] = request[field]
    if purpose == "notification":
        for field in ("recipient_ref", "template_version", "body_hash"):
            if field not in request:
                raise ValueError(f"request lacks notification scope input: {field}")
            result[field] = request[field]
    return result


def validate_approval_set(
    request: Mapping[str, object], *, now: datetime
) -> list[SemanticIssue]:
    issues: list[SemanticIssue] = []
    if now.tzinfo is None or now.utcoffset() is None:
        return [_issue("approval.now_timezone_required", "/", "Validation time must be timezone-aware.")]
    approval = request.get("approval")
    if not isinstance(approval, Mapping):
        return [_issue("approval.missing", "/approval", "Approval object is required.")]
    approval_class = approval.get("approval_class")
    scope_hash = request.get("scope_hash")
    try:
        bound_scope = _scope_from_request(request)
        computed = compute_scope_hash(bound_scope)
        scope_expiry = _parse_timestamp(bound_scope["expires_at"], "/expires_at")
    except (TypeError, ValueError) as exc:
        issues.append(_issue("approval.scope_invalid", "/", str(exc)))
        issues.append(_issue("approval.scope_hash_mismatch", "/scope_hash", "Request scope cannot reproduce the approved scope hash."))
        scope_expiry = None
    else:
        if isinstance(request.get("scope"), Mapping) and dict(request["scope"]) != bound_scope:
            issues.append(_issue("approval.scope_mismatch", "/scope", "Provided scope differs from request fields."))
        if scope_hash != computed:
            issues.append(_issue("approval.scope_hash_mismatch", "/scope_hash", "Scope hash does not bind the request scope."))

    action_type = request.get("action_type")
    contract = ACTION_CONTRACTS.get(action_type) or NOTIFICATION_CONTRACTS.get(action_type)
    expected_class: object | None = contract.get("approval") if contract else None
    if action_type in QUERY_CONTRACTS:
        expected_class = "policy_authorized_read"
    if expected_class is None:
        issues.append(_issue("approval.action_unregistered", "/action_type", "Action type is not registered."))
    elif approval_class != expected_class:
        issues.append(_issue("approval.class_mismatch", "/approval/approval_class", "Approval class does not match the registered action contract."))
    if approval.get("scope_hash") != scope_hash and approval_class in {"policy_authorized_read", "preauthorized_reversible"}:
        issues.append(_issue("approval.scope_hash_mismatch", "/approval/scope_hash", "Policy approval scope differs from the request."))
    if approval_class in {"policy_authorized_read", "preauthorized_reversible"}:
        try:
            approval_expiry = _parse_timestamp(approval.get("expires_at"), "/approval/expires_at")
        except ValueError as exc:
            issues.append(_issue("approval.expiry_invalid", "/approval/expires_at", str(exc)))
        else:
            if approval_expiry <= now.astimezone(timezone.utc):
                issues.append(_issue("approval.expired", "/approval/expires_at", "Policy approval expired before execution."))
            if scope_expiry is not None and approval_expiry > scope_expiry:
                issues.append(_issue("approval.exceeds_scope_expiry", "/approval/expires_at", "Policy approval outlives the bound scope."))
        time_field = "decided_at" if approval_class == "policy_authorized_read" else "approved_at"
        try:
            decision_time = _parse_timestamp(approval.get(time_field), f"/approval/{time_field}")
        except ValueError as exc:
            issues.append(_issue("approval.decision_time_invalid", f"/approval/{time_field}", str(exc)))
        else:
            if decision_time > now.astimezone(timezone.utc):
                issues.append(_issue("approval.from_future", f"/approval/{time_field}", "Policy approval time is in the future."))

    if approval_class == "preauthorized_reversible":
        issues.append(
            _issue(
                "approval.preauthorization_disabled",
                "/approval/approval_class",
                "The base package has no trusted immutable policy source; preauthorization is denied by default.",
            )
        )
    if approval_class == "policy_authorized_read":
        issues.append(
            _issue(
                "approval.policy_registry_unavailable",
                "/approval/approval_class",
                "The base package has no trusted immutable MCP policy registry; read authorization is denied by default.",
            )
        )
    if approval_class in {
        "two_person_reversible",
        "two_person_high_impact",
        "two_person_irreversible",
    }:
        records = approval.get("human_approvals")
        if not isinstance(records, list) or len(records) != 2:
            issues.append(_issue("approval.two_person_required", "/approval/human_approvals", "Exactly two human approvals are required."))
        else:
            approver_ids = [record.get("approver_id") for record in records if isinstance(record, Mapping)]
            if len(set(approver_ids)) != 2:
                issues.append(_issue("approval.approver_not_distinct", "/approval/human_approvals", "Approver identities must be distinct."))
            required_roles = contract.get("roles") if contract else None
            if isinstance(required_roles, tuple):
                actual_roles = {record.get("approver_role") for record in records if isinstance(record, Mapping)}
                if actual_roles != set(required_roles):
                    issues.append(_issue("approval.role_pair_mismatch", "/approval/human_approvals", "Approver roles do not match the registered pair."))
            for index, record in enumerate(records):
                if not isinstance(record, Mapping):
                    continue
                if record.get("scope_hash") != scope_hash:
                    issues.append(_issue("approval.scope_hash_mismatch", f"/approval/human_approvals/{index}/scope_hash", "Approval scope hash differs from the request."))
                try:
                    expires = _parse_timestamp(record.get("expires_at"), f"/approval/human_approvals/{index}/expires_at")
                except ValueError as exc:
                    issues.append(_issue("approval.expiry_invalid", f"/approval/human_approvals/{index}/expires_at", str(exc)))
                else:
                    comparison_now = now.astimezone(timezone.utc)
                    if expires <= comparison_now:
                        issues.append(_issue("approval.expired", f"/approval/human_approvals/{index}/expires_at", "Approval expired before execution."))
                    if scope_expiry is not None and expires > scope_expiry:
                        issues.append(_issue("approval.exceeds_scope_expiry", f"/approval/human_approvals/{index}/expires_at", "Approval outlives the bound scope."))
                try:
                    approved_at = _parse_timestamp(record.get("approved_at"), f"/approval/human_approvals/{index}/approved_at")
                except ValueError as exc:
                    issues.append(_issue("approval.approved_at_invalid", f"/approval/human_approvals/{index}/approved_at", str(exc)))
                else:
                    if approved_at > now.astimezone(timezone.utc):
                        issues.append(_issue("approval.from_future", f"/approval/human_approvals/{index}/approved_at", "Approval timestamp is in the future."))
    elif "human_approvals" in approval:
        issues.append(_issue("approval.human_approvals_forbidden", "/approval/human_approvals", "This approval class cannot accept human approvals."))

    if request.get("notification_id") is not None:
        try:
            expected_idempotency = compute_notification_idempotency_key(request)
        except ValueError as exc:
            issues.append(_issue("notification.idempotency_invalid", "/idempotency_key", str(exc)))
        else:
            if request.get("idempotency_key") != expected_idempotency:
                issues.append(_issue("notification.idempotency_mismatch", "/idempotency_key", "Notification idempotency key does not bind recipient and body."))

    issues.extend(validate_action_contract(request))

    return sorted(issues)


def validate_recovery_contract(action: Mapping[str, object]) -> list[SemanticIssue]:
    issues: list[SemanticIssue] = []
    action_type = action.get("action_type")
    contract = ACTION_CONTRACTS.get(action_type) or NOTIFICATION_CONTRACTS.get(action_type)
    if contract is None:
        issues.append(_issue("recovery.action_unregistered", "/action_type", "Action type is not registered."))
    elif action.get("reversible") is not contract["reversible"]:
        issues.append(_issue("recovery.reversibility_mismatch", "/reversible", "Declared reversibility differs from the registered action contract."))
    if action.get("reversible") is True:
        required = (
            action.get("rollback_trigger"),
            action.get("rollback_steps"),
            action.get("rollback_timeout_seconds"),
            action.get("rollback_verification_query"),
        )
        if not all(required) or not isinstance(action.get("rollback_steps"), list):
            issues.append(_issue("recovery.rollback_required", "/rollback_steps", "Reversible actions require a non-empty rollback and verification contract."))
        if any(field in action for field in ("irreversibility_reason", "compensating_actions", "stop_conditions")):
            issues.append(_issue("recovery.compensation_forbidden", "/compensating_actions", "Reversible actions cannot carry an irreversible compensation branch."))
    elif action.get("reversible") is False:
        required = (
            action.get("irreversibility_reason"),
            action.get("compensating_actions"),
            action.get("stop_conditions"),
        )
        if not all(required):
            issues.append(_issue("recovery.compensation_required", "/compensating_actions", "Irreversible actions require reason, compensation, and stop conditions."))
        approval = action.get("approval")
        if not isinstance(approval, Mapping) or approval.get("approval_class") != "two_person_irreversible":
            issues.append(_issue("recovery.irreversible_approval_required", "/approval/approval_class", "Irreversible actions require two_person_irreversible approval."))
        if any(field in action for field in ("rollback_trigger", "rollback_steps", "rollback_timeout_seconds", "rollback_verification_query")):
            issues.append(_issue("recovery.rollback_forbidden", "/rollback_steps", "Irreversible actions cannot claim rollback."))
    else:
        issues.append(_issue("recovery.reversibility_required", "/reversible", "Reversibility must be explicitly true or false."))
    return sorted(issues)


INCIDENT_TRANSITIONS: dict[str, frozenset[str]] = {
    "detected": frozenset({"triaged"}),
    "triaged": frozenset({"investigating"}),
    "investigating": frozenset({"mitigating", "monitoring"}),
    "mitigating": frozenset({"investigating", "monitoring"}),
    "monitoring": frozenset({"investigating", "mitigating", "recovered"}),
    "recovered": frozenset({"monitoring", "resolved"}),
    "resolved": frozenset({"reviewed"}),
    "reviewed": frozenset(),
}
NOTIFICATION_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"awaiting_approval", "revoked"}),
    "awaiting_approval": frozenset({"approved", "revoked"}),
    "approved": frozenset({"sent", "failed", "revoked"}),
    "sent": frozenset(),
    "failed": frozenset(),
    "revoked": frozenset(),
}


def validate_incident_transition(current: str, desired: str) -> bool:
    return desired in INCIDENT_TRANSITIONS.get(current, frozenset())


def validate_notification_transition(current: str, desired: str) -> bool:
    return desired in NOTIFICATION_TRANSITIONS.get(current, frozenset())


def validate_action_transition(current: str, desired: str, *, reversible: bool) -> bool:
    common = {
        "proposed": frozenset({"awaiting_approval", "rejected"}),
        "awaiting_approval": frozenset({"approved", "rejected"}),
        "approved": frozenset({"executing", "rejected"}),
        "executing": frozenset({"succeeded", "failed"}),
    }
    if current in common:
        return desired in common[current]
    if current == "failed":
        return desired == ("rolled_back" if reversible else "compensated")
    if current == "succeeded" and not reversible:
        return desired == "compensated"
    return False


def validate_time_window(window: Mapping[str, object]) -> list[SemanticIssue]:
    issues: list[SemanticIssue] = []
    try:
        start = _parse_timestamp(window.get("start"), "/start")
        end = _parse_timestamp(window.get("end"), "/end")
    except (AttributeError, ValueError) as exc:
        return [_issue("time_window.invalid", "/", str(exc))]
    if end <= start:
        issues.append(_issue("time_window.order", "/end", "Time window end must be after start."))
    elif (end - start).total_seconds() > 86400:
        issues.append(_issue("time_window.too_large", "/end", "Time window exceeds 86400 seconds."))
    return issues


def validate_evidence_references(container: Mapping[str, object]) -> list[SemanticIssue]:
    incident_id = container.get("incident_id")
    issues: list[SemanticIssue] = []
    evidence_keys = {"evidence_id", "incident_id", "storage_ref", "content_hash", "collected_at", "storage_version"}

    def walk(value: object, pointer: str) -> None:
        if isinstance(value, Mapping):
            if evidence_keys <= set(value) and value.get("incident_id") != incident_id:
                issues.append(
                    _issue(
                        "evidence.incident_mismatch",
                        f"{pointer}/incident_id",
                        "Evidence reference is bound to a different incident.",
                    )
                )
            for key, item in value.items():
                escaped = str(key).replace("~", "~0").replace("/", "~1")
                walk(item, f"{pointer}/{escaped}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{pointer}/{index}")

    walk(container, "")
    return sorted(issues)


FORENSIC_SCHEMA_NAMES = frozenset({"source-fingerprint", "evidence-event", "chain-of-custody"})
_FORENSIC_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bauthorization\s*:\s*\S+", re.IGNORECASE),
    re.compile(r"\bcookie\s*:\s*\S+", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\b(?:(?:api|auth|id|access|refresh|session|plaintext)[_-]?)?token\s*[:=]\s*\S+", re.IGNORECASE),
)


def compute_source_fingerprint_hash(fingerprint: Mapping[str, object]) -> str:
    if not isinstance(fingerprint, Mapping):
        raise TypeError("fingerprint must be a mapping")
    projected = dict(fingerprint)
    projected.pop("fingerprint_hash", None)
    return structured_sha256(projected)


def compute_custody_event_hash(event: Mapping[str, object]) -> str:
    if not isinstance(event, Mapping):
        raise TypeError("custody event must be a mapping")
    projected = dict(event)
    projected.pop("event_hash", None)
    return structured_sha256(projected)


def _forensic_sensitive_value_issues(value: object, pointer: str = "") -> list[SemanticIssue]:
    issues: list[SemanticIssue] = []
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _FORENSIC_SENSITIVE_VALUE_PATTERNS):
            issues.append(
                _issue(
                    "forensics.sensitive_value",
                    pointer or "/",
                    "Forensic metadata must not contain credentials, complete authentication headers, or plaintext tokens.",
                )
            )
    elif isinstance(value, Mapping):
        for key, item in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            issues.extend(_forensic_sensitive_value_issues(item, f"{pointer}/{escaped}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            issues.extend(_forensic_sensitive_value_issues(item, f"{pointer}/{index}"))
    return issues


def validate_forensic_classification_transition(
    current: str, desired: str, policy: Mapping[str, object]
) -> bool:
    transitions = policy.get("classification_transitions")
    return isinstance(transitions, Mapping) and desired in transitions.get(current, [])


def validate_source_fingerprint(
    fingerprint: Mapping[str, object], policy: Mapping[str, object]
) -> list[SemanticIssue]:
    if not isinstance(fingerprint, Mapping):
        return [_issue("forensics.invalid", "/", "Source fingerprint must be an object.")]
    issues = _forensic_sensitive_value_issues(fingerprint)
    issues.extend(validate_evidence_references(fingerprint))

    try:
        first_seen = _parse_timestamp(fingerprint.get("first_seen"), "/first_seen")
        last_seen = _parse_timestamp(fingerprint.get("last_seen"), "/last_seen")
        collected_at = _parse_timestamp(fingerprint.get("collected_at"), "/collected_at")
        if last_seen < first_seen:
            issues.append(_issue("forensics.time_order", "/last_seen", "last_seen must not precede first_seen."))
        if collected_at < first_seen:
            issues.append(_issue("forensics.collection_time", "/collected_at", "collected_at must not precede first_seen."))
    except ValueError as exc:
        issues.append(_issue("forensics.timestamp", "/", str(exc)))

    raw_reference = fingerprint.get("raw_evidence_ref")
    if isinstance(raw_reference, Mapping):
        if raw_reference.get("incident_id") != fingerprint.get("incident_id"):
            issues.append(_issue("forensics.incident_binding", "/raw_evidence_ref/incident_id", "Raw evidence is bound to a different incident."))
        if raw_reference.get("content_hash") != fingerprint.get("content_hash"):
            issues.append(_issue("forensics.content_hash_binding", "/content_hash", "Fingerprint content_hash must equal the raw evidence byte hash."))

    try:
        if fingerprint.get("fingerprint_hash") != compute_source_fingerprint_hash(fingerprint):
            issues.append(_issue("forensics.fingerprint_hash", "/fingerprint_hash", "Fingerprint JCS hash does not match its closed projection."))
    except (TypeError, ValueError) as exc:
        issues.append(_issue("forensics.fingerprint_hash", "/fingerprint_hash", str(exc)))

    version = fingerprint.get("fingerprint_version")
    supersedes = fingerprint.get("supersedes_fingerprint_hash")
    if version == 1 and supersedes is not None:
        issues.append(_issue("forensics.supersedes", "/supersedes_fingerprint_hash", "Fingerprint version 1 must not supersede another record."))
    if isinstance(version, int) and not isinstance(version, bool) and version > 1 and supersedes is None:
        issues.append(_issue("forensics.supersedes", "/supersedes_fingerprint_hash", "Later fingerprint versions must bind the superseded hash."))

    source_ip = fingerprint.get("source_ip")
    network_prefix = fingerprint.get("network_prefix")
    try:
        address = ipaddress.ip_address(source_ip)
    except (TypeError, ValueError):
        address = None
        issues.append(_issue("forensics.source_ip", "/source_ip", "source_ip must be a valid IPv4 or IPv6 address."))
    if network_prefix is not None:
        try:
            network = ipaddress.ip_network(network_prefix, strict=True)
            if str(network) != network_prefix:
                issues.append(_issue("forensics.network_prefix_canonical", "/network_prefix", "network_prefix must use canonical CIDR form."))
            if address is not None and address not in network:
                issues.append(_issue("forensics.network_prefix_binding", "/network_prefix", "network_prefix must contain source_ip."))
        except (TypeError, ValueError):
            issues.append(_issue("forensics.network_prefix", "/network_prefix", "network_prefix must be a canonical IPv4 or IPv6 CIDR."))

    basis = fingerprint.get("source_ip_basis")
    if isinstance(basis, Mapping):
        method = basis.get("method")
        proxy_ref = basis.get("trusted_proxy_ref")
        hops = basis.get("forwarded_chain_hops")
        if method == "direct_peer" and (proxy_ref is not None or hops != 0):
            issues.append(_issue("forensics.proxy_basis", "/source_ip_basis", "direct_peer must not claim a trusted proxy or forwarded hops."))
        if method == "trusted_proxy_chain" and (not isinstance(proxy_ref, str) or not isinstance(hops, int) or isinstance(hops, bool) or hops < 1):
            issues.append(_issue("forensics.proxy_basis", "/source_ip_basis", "trusted_proxy_chain requires a registered proxy reference and at least one hop."))

    transitions = policy.get("classification_transitions") if isinstance(policy, Mapping) else None
    classification = fingerprint.get("classification")
    if not isinstance(transitions, Mapping) or classification not in transitions:
        issues.append(_issue("forensics.classification", "/classification", "Classification is not registered by forensics policy."))
    return sorted(set(issues))


def validate_chain_of_custody(
    manifest: Mapping[str, object], policy: Mapping[str, object]
) -> list[SemanticIssue]:
    if not isinstance(manifest, Mapping):
        return [_issue("forensics.invalid", "/", "Chain of custody must be an object.")]
    issues = _forensic_sensitive_value_issues(manifest)
    issues.extend(validate_evidence_references(manifest))

    incident_id = manifest.get("incident_id")
    evidence = manifest.get("evidence_reference")
    evidence_id = evidence.get("evidence_id") if isinstance(evidence, Mapping) else None
    storage = manifest.get("storage_contract")
    retention = manifest.get("retention")
    configured_retention = policy.get("retention") if isinstance(policy, Mapping) else None
    if isinstance(storage, Mapping) and storage.get("production_gate") is True:
        issues.append(_issue("forensics.production_gate", "/storage_contract/production_gate", "The static package cannot enable production evidence storage."))
    if isinstance(storage, Mapping) and storage.get("configured") is False and (
        storage.get("provider") is not None or storage.get("immutable_store_ref") is not None
    ):
        issues.append(_issue("forensics.storage_unconfigured", "/storage_contract", "Unconfigured storage must not claim a provider or immutable store reference."))
    if isinstance(configured_retention, Mapping) and isinstance(retention, Mapping):
        for key in ("configured", "value", "unit"):
            if retention.get(key) != configured_retention.get(key):
                issues.append(_issue("forensics.retention_binding", f"/retention/{key}", "Manifest retention must match configured policy."))

    events = manifest.get("events")
    if not isinstance(events, list) or not events:
        return sorted(set(issues + [_issue("forensics.events", "/events", "At least one custody event is required.")]))

    previous_hash: object = None
    previous_time: datetime | None = None
    previous_output_hash = evidence.get("content_hash") if isinstance(evidence, Mapping) else None
    legal_hold = manifest.get("legal_hold")
    hold_enabled = isinstance(legal_hold, Mapping) and legal_hold.get("state") == "enabled"
    for index, event in enumerate(events):
        pointer = f"/events/{index}"
        if not isinstance(event, Mapping):
            issues.append(_issue("forensics.event", pointer, "Custody event must be an object."))
            continue
        if event.get("incident_id") != incident_id:
            issues.append(_issue("forensics.event_incident", f"{pointer}/incident_id", "Custody event is bound to a different incident."))
        if event.get("evidence_id") != evidence_id:
            issues.append(_issue("forensics.event_evidence", f"{pointer}/evidence_id", "Custody event is bound to different evidence."))
        if event.get("previous_event_hash") != previous_hash:
            issues.append(_issue("forensics.previous_hash", f"{pointer}/previous_event_hash", "Custody event does not link to the prior event hash."))
        try:
            expected_hash = compute_custody_event_hash(event)
            if event.get("event_hash") != expected_hash:
                issues.append(_issue("forensics.event_hash", f"{pointer}/event_hash", "Custody event JCS hash does not match its closed projection."))
        except (TypeError, ValueError) as exc:
            issues.append(_issue("forensics.event_hash", f"{pointer}/event_hash", str(exc)))
        if index == 0 and event.get("action") != "collection":
            issues.append(_issue("forensics.collection_first", f"{pointer}/action", "The custody chain must begin with collection."))
        if index == 0 and isinstance(evidence, Mapping):
            for event_field, evidence_field in (
                ("storage_ref", "storage_ref"),
                ("storage_version", "storage_version"),
                ("timestamp", "collected_at"),
                ("output_hash", "content_hash"),
            ):
                if event.get(event_field) != evidence.get(evidence_field):
                    issues.append(
                        _issue(
                            "forensics.collection_binding",
                            f"{pointer}/{event_field}",
                            f"Initial collection {event_field} must match evidence_reference.{evidence_field}.",
                        )
                    )
        if event.get("input_hash") != previous_output_hash:
            issues.append(_issue("forensics.content_continuity", f"{pointer}/input_hash", "Custody input_hash must equal the prior output or original evidence hash."))
        if event.get("action") == "access" and event.get("output_hash") != event.get("input_hash"):
            issues.append(_issue("forensics.access_transform", f"{pointer}/output_hash", "Read-only access must not change the content hash."))
        try:
            event_time = _parse_timestamp(event.get("timestamp"), f"{pointer}/timestamp")
            if previous_time is not None and event_time < previous_time:
                issues.append(_issue("forensics.event_order", f"{pointer}/timestamp", "Custody event timestamps must not move backward."))
            previous_time = event_time
        except ValueError as exc:
            issues.append(_issue("forensics.timestamp", f"{pointer}/timestamp", str(exc)))
        action = event.get("action")
        if action == "delete" and hold_enabled:
            issues.append(_issue("forensics.legal_hold", f"{pointer}/action", "Legal Hold blocks deletion."))
        if action in {"export", "delete"} and not isinstance(event.get("approval_reference"), str):
            issues.append(_issue("forensics.approval_reference", f"{pointer}/approval_reference", f"{action} must reuse one existing governance authorization reference."))
        previous_hash = event.get("event_hash")
        previous_output_hash = event.get("output_hash")

    if manifest.get("chain_head_hash") != previous_hash:
        issues.append(_issue("forensics.chain_head", "/chain_head_hash", "chain_head_hash must equal the final event hash."))
    return sorted(set(issues))


def validate_forensic_schema_instance(
    schema_name: str, instance: object, root: Path
) -> list[SemanticIssue]:
    if schema_name not in FORENSIC_SCHEMA_NAMES:
        raise ValueError(f"unknown forensic schema: {schema_name}")
    paths = [root / "schemas/incident-event.schema.json", *sorted((root / "forensics/schemas").glob("*.schema.json"))]
    resources: list[tuple[str, Resource[Any]]] = []
    documents: dict[str, object] = {}
    identifiers: set[str] = set()
    for path in paths:
        document = load_json_strict(path, root)
        if not isinstance(document, dict) or not isinstance(document.get("$id"), str):
            raise ValueError(f"schema lacks an offline $id: {path}")
        identifier = document["$id"]
        if not identifier.startswith("urn:aegis-mesh:schema:") or identifier in identifiers:
            raise ValueError(f"forensic schema has an invalid or duplicate offline $id: {identifier}")
        identifiers.add(identifier)
        resources.append((identifier, Resource.from_contents(document)))
        if path.parent.name == "schemas" and path.parent.parent.name == "forensics":
            documents[path.name.removesuffix(".schema.json")] = document
    if set(documents) != FORENSIC_SCHEMA_NAMES:
        raise ValueError("forensic schema registry is not closed")

    def references(value: object) -> list[str]:
        if isinstance(value, Mapping):
            return [
                reference
                for key, item in value.items()
                for reference in (([item] if key == "$ref" and isinstance(item, str) else []) + references(item))
            ]
        if isinstance(value, list):
            return [reference for item in value for reference in references(item)]
        return []

    for name, document in documents.items():
        validator_for(document).check_schema(document)
        for reference in references(document):
            if reference.startswith("#"):
                continue
            if reference.split("#", 1)[0] not in identifiers:
                raise ValueError(f"forensic schema {name} contains an unregistered or network-capable $ref: {reference}")

    schema = documents[schema_name]
    validator_type = validator_for(schema)
    validator = validator_type(schema, registry=Registry().with_resources(resources), format_checker=FormatChecker())
    issues: list[SemanticIssue] = []
    for error in validator.iter_errors(instance):
        pointer = "".join(f"/{str(part).replace('~', '~0').replace('/', '~1')}" for part in error.absolute_path) or "/"
        issues.append(SemanticIssue(path=f"forensics/schemas/{schema_name}.schema.json", json_pointer=pointer, code="schema.invalid", message=error.message))
    return sorted(issues)


def validate_action_contract(action: Mapping[str, object]) -> list[SemanticIssue]:
    issues: list[SemanticIssue] = []
    action_type = action.get("action_type")
    contract = ACTION_CONTRACTS.get(action_type) or NOTIFICATION_CONTRACTS.get(action_type) or QUERY_CONTRACTS.get(action_type)
    if contract is None:
        return [_issue("action.unregistered", "/action_type", "Action type is not registered.")]
    exact_scope = action.get("exact_scope")
    if not isinstance(exact_scope, Mapping):
        return [_issue("action.scope_missing", "/exact_scope", "Exact scope is required.")]

    if action_type in QUERY_CONTRACTS:
        for field in contract["fields"]:
            if field in action and action[field] != exact_scope.get(field):
                issues.append(_issue("query.executable_scope_mismatch", f"/{field}", "Executable query field differs from approved exact_scope."))
        if action.get("query_class") == "incident_ioc":
            evidence = action.get("evidence")
            if not isinstance(evidence, Mapping) or exact_scope.get("evidence_id") != evidence.get("evidence_id"):
                issues.append(_issue("query.evidence_id_mismatch", "/exact_scope/evidence_id", "Incident-IOC exact scope is bound to a different evidence record."))
    if action_type in NOTIFICATION_CONTRACTS:
        if exact_scope.get("notice_id") != action.get("notification_id"):
            issues.append(_issue("notification.notice_id_mismatch", "/exact_scope/notice_id", "Notification identity differs from approved exact_scope."))
        if action_type == "send_corrective_notification" and exact_scope.get("original_notice_id") != action.get("original_notification_id"):
            issues.append(
                _issue(
                    "notification.original_notice_id_mismatch",
                    "/exact_scope/original_notice_id",
                    "Corrective notification chain differs from approved exact_scope.",
                )
            )

    outer_environment = action.get("environment")
    drill_environment = exact_scope.get("environment")
    if (
        action_type == "run_isolated_dr_drill"
        and isinstance(outer_environment, str)
        and isinstance(drill_environment, str)
        and outer_environment in REGISTERED_ENVIRONMENTS
        and drill_environment in REGISTERED_ENVIRONMENTS
        and drill_environment != outer_environment
    ):
        issues.append(
            _issue(
                "action.environment_mismatch",
                "/exact_scope/environment",
                "DR drill exact_scope environment must match the request environment.",
            )
        )

    for left, right in (("from_region", "to_region"), ("from_node", "to_node"), ("current_state", "desired_state"), ("mode_from", "mode_to")):
        if left in exact_scope and exact_scope.get(left) == exact_scope.get(right):
            issues.append(_issue("action.distinct_values_required", f"/exact_scope/{right}", f"{left} and {right} must differ."))
    source_cidrs = exact_scope.get("source_cidrs")
    if isinstance(source_cidrs, list):
        for index, cidr in enumerate(source_cidrs):
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except (TypeError, ValueError):
                issues.append(_issue("action.cidr_not_canonical", f"/exact_scope/source_cidrs/{index}", "CIDR must be canonical and must not contain host bits."))
            else:
                if str(network) != str(cidr).lower():
                    issues.append(_issue("action.cidr_not_canonical", f"/exact_scope/source_cidrs/{index}", "CIDR text is not canonical."))
    for field in ("activation_window", "time_window"):
        if isinstance(exact_scope.get(field), Mapping):
            issues.extend(validate_time_window(exact_scope[field]))
    issues.extend(validate_evidence_references(action))
    issues.append(
        _issue(
            "authorization.registry_unavailable",
            "/action_type",
            "The base package has no trusted asset, tool, or resource registry; authorization is denied by default.",
        )
    )
    return sorted(issues)


def validate_threat_model(model: Mapping[str, object]) -> list[SemanticIssue]:
    issues: list[SemanticIssue] = []
    complete = model.get("status") == "complete"
    if complete:
        for context_field in ("trust_boundaries", "data_classifications", "calling_identities"):
            if not model.get(context_field):
                issues.append(_issue("threat_model.context_missing", f"/{context_field}", "Complete threat models require this context."))

    core_element_ids: set[object] = set()
    declared_ids: list[tuple[object, str]] = []
    for collection in ("entities", "processes", "data_stores"):
        values = model.get(collection, []) if isinstance(model.get(collection), list) else []
        for index, item in enumerate(values):
            element_id = item.get("element_id") if isinstance(item, Mapping) else item
            core_element_ids.add(element_id)
            declared_ids.append((element_id, f"/{collection}/{index}/element_id"))

    data_flows = model.get("data_flows") if isinstance(model.get("data_flows"), list) else []
    flow_id_values = [flow.get("flow_id") for flow in data_flows if isinstance(flow, Mapping)]
    flow_ids = set(flow_id_values)
    declared_ids.extend((value, f"/data_flows/{index}/flow_id") for index, value in enumerate(flow_id_values))

    context_sets: dict[str, set[object]] = {}
    for field in ("trust_boundaries", "assets", "data_classifications", "calling_identities"):
        values = model.get(field, []) if isinstance(model.get(field), list) else []
        context_sets[field] = set(values)
        declared_ids.extend((value, f"/{field}/{index}") for index, value in enumerate(values))
    boundaries = context_sets["trust_boundaries"]
    assets = context_sets["assets"]
    classifications = context_sets["data_classifications"]
    identities = context_sets["calling_identities"]

    controls = model.get("controls") if isinstance(model.get("controls"), list) else []
    control_id_values = [control.get("control_id") for control in controls if isinstance(control, Mapping)]
    control_ids = set(control_id_values)
    declared_ids.extend((value, f"/controls/{index}/control_id") for index, value in enumerate(control_id_values))

    threats = model.get("threats") if isinstance(model.get("threats"), list) else []
    threat_id_values = [threat.get("threat_id") for threat in threats if isinstance(threat, Mapping)]
    declared_ids.extend((value, f"/threats/{index}/threat_id") for index, value in enumerate(threat_id_values))
    occurrences: dict[object, list[str]] = {}
    for identifier, pointer in declared_ids:
        occurrences.setdefault(identifier, []).append(pointer)
    for identifier, pointers in occurrences.items():
        if identifier is None or len(pointers) > 1:
            issues.append(_issue("threat_model.element_id_not_unique", pointers[-1], f"Declared ID {identifier!r} is missing or duplicated."))

    referenceable_ids = core_element_ids | flow_ids | boundaries | assets | classifications | identities | control_ids
    coverage_required_ids = core_element_ids | flow_ids

    for index, flow in enumerate(data_flows):
        if not isinstance(flow, Mapping):
            continue
        if flow.get("source_element_id") not in core_element_ids or flow.get("destination_element_id") not in core_element_ids:
            issues.append(_issue("threat_model.dangling_flow_endpoint", f"/data_flows/{index}", "Data flow endpoint does not reference a typed entity, process, or data store."))
        if flow.get("data_classification") not in classifications:
            issues.append(_issue("threat_model.dangling_classification_reference", f"/data_flows/{index}/data_classification", "Data flow classification is not registered in the model."))
        if not set(flow.get("trust_boundaries", [])) <= boundaries:
            issues.append(_issue("threat_model.dangling_boundary_reference", f"/data_flows/{index}/trust_boundaries", "Data flow references an unknown trust boundary."))
    control_targets = referenceable_ids - control_ids
    for index, control in enumerate(controls):
        if isinstance(control, Mapping) and not set(control.get("element_ids", [])) <= control_targets:
            issues.append(_issue("threat_model.dangling_control_reference", f"/controls/{index}/element_ids", "Control references an unknown model element."))
    for index, threat in enumerate(threats):
        if not isinstance(threat, Mapping):
            continue
        if threat.get("element_id") not in referenceable_ids:
            issues.append(_issue("threat_model.dangling_threat_reference", f"/threats/{index}/element_id", "Threat references an unknown applicable model element."))
    if complete:
        required = {"spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"}
        for element_id in coverage_required_ids:
            observed = [
                item.get("category")
                for item in threats
                if isinstance(item, Mapping) and item.get("element_id") == element_id
            ]
            if set(observed) != required:
                issues.append(_issue("threat_model.stride_coverage_incomplete", "/threats", f"Element {element_id!r} lacks a complete STRIDE disposition set."))
        if not coverage_required_ids:
            issues.append(_issue("threat_model.elements_missing", "/", "Complete threat models require typed DFD elements."))
    return sorted(issues)


def _schema_registry(root: Path) -> tuple[dict[str, object], Registry]:
    schemas: dict[str, object] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    identifiers: set[str] = set()
    for path in sorted((root / "schemas").glob("*.schema.json")):
        document = load_json_strict(path, root)
        if not isinstance(document, dict) or not isinstance(document.get("$id"), str):
            raise ValueError(f"schema lacks an offline $id: {path}")
        identifier = document["$id"]
        if not identifier.startswith("urn:aegis-mesh:schema:"):
            raise ValueError(f"schema $id is not an approved offline URN: {identifier}")
        if identifier in identifiers:
            raise ValueError(f"duplicate schema $id: {identifier}")
        identifiers.add(identifier)
        name = path.name.removesuffix(".schema.json")
        schemas[name] = document
        resources.append((identifier, Resource.from_contents(document)))
    if set(schemas) != ROOT_SCHEMA_NAMES:
        raise ValueError(
            f"schema registry is not closed; missing={sorted(ROOT_SCHEMA_NAMES - set(schemas))}, "
            f"extra={sorted(set(schemas) - ROOT_SCHEMA_NAMES)}"
        )

    def references(value: object) -> list[str]:
        found: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref" and isinstance(item, str):
                    found.append(item)
                found.extend(references(item))
        elif isinstance(value, list):
            for item in value:
                found.extend(references(item))
        return found

    for name, document in schemas.items():
        validator_for(document).check_schema(document)
        for reference in references(document):
            if reference.startswith("#"):
                continue
            base = reference.split("#", 1)[0]
            if base not in identifiers:
                raise ValueError(f"schema {name} contains an unregistered or network-capable $ref: {reference}")
    return schemas, Registry().with_resources(resources)


def validate_schema_instance(schema_name: str, instance: object, root: Path) -> list[SemanticIssue]:
    schemas, registry = _schema_registry(root)
    if schema_name not in schemas:
        raise ValueError(f"unknown schema: {schema_name}")
    schema = schemas[schema_name]
    validator_type = validator_for(schema)
    validator_type.check_schema(schema)
    format_checker = FormatChecker()
    if "date-time" not in format_checker.checkers:
        @format_checker.checks("date-time", raises=(TypeError, ValueError))
        def _is_rfc3339_datetime(value: object) -> bool:
            _parse_timestamp(value, "/date-time")
            return True

    validator = validator_type(schema, registry=registry, format_checker=format_checker)
    issues: list[SemanticIssue] = []
    for error in validator.iter_errors(instance):
        pointer = "".join(f"/{str(part).replace('~', '~0').replace('/', '~1')}" for part in error.absolute_path) or "/"
        issues.append(
            SemanticIssue(
                path=f"schemas/{schema_name}.schema.json",
                json_pointer=pointer,
                code="schema.invalid",
                message=error.message,
            )
        )
    return sorted(issues)
