from collections import Counter
from pathlib import Path

import pytest

from scripts.validation_core import load_yaml_strict


ROOT = Path(__file__).resolve().parents[1]
CONFIG_ROOT = ROOT / "configs"

CONFIG_NAMES = {
    "thresholds.yaml",
    "alert_rules.yaml",
    "recovery_policy.yaml",
    "agent_permissions.yaml",
    "agent_protocol.yaml",
    "approval_matrix.yaml",
    "slo.yaml",
    "forensics_policy.yaml",
    "notification_policy.yaml",
    "authorized_assets.yaml",
    "incident_ioc_policy.yaml",
    "mcp_tool_policy.yaml",
    "vulnerability_priority_policy.yaml",
    "standards_versions.yaml",
    "runtime.example.yaml",
}

AGENTS = {
    "main-security-orchestrator": "recommend",
    "qr-security-agent": "execute_reversible",
    "ddos-defense-agent": "execute_reversible",
    "api-security-agent": "execute_reversible",
    "infrastructure-agent": "execute_reversible",
    "kubernetes-agent": "execute_reversible",
    "database-agent": "recommend",
    "observability-agent": "observe",
    "incident-response-agent": "execute_reversible",
    "disaster-recovery-agent": "execute_high_impact",
    "threat-intelligence-agent": "recommend",
    "abuse-notification-agent": "execute_high_impact",
}

APPROVAL_CLASSES = [
    "policy_authorized_read",
    "preauthorized_reversible",
    "two_person_reversible",
    "two_person_high_impact",
    "two_person_irreversible",
]

APPROVAL_ROLES = [
    "incident_commander", "service_owner", "infrastructure_owner", "database_owner",
    "legal_compliance_approver", "privacy_legal_approver",
    "detection_engineering_reviewer", "siem_edr_owner", "security_owner", "system_owner",
]

UNCONFIGURED = {
    "configured": False,
    "value": None,
    "unit": None,
    "required_before_production": True,
}

AUDIT_EVENTS = [
    "event_received", "event_validated", "route_selected", "recommendation_created",
    "policy_denied", "action_proposed", "approval_requested", "approval_granted",
    "approval_rejected", "action_authorized", "action_started", "action_succeeded",
    "action_failed", "rollback_started", "rollback_succeeded", "rollback_failed",
    "compensation_started", "compensation_completed", "verification_requested",
    "verification_succeeded", "verification_failed", "mcp_query_started",
    "mcp_query_completed", "mcp_query_failed", "notification_drafted",
    "notification_authorized", "notification_send_started", "notification_sent",
    "notification_failed", "notification_bounced", "notification_reply_received",
    "notification_authorization_revoked", "evidence_collected", "evidence_transformed",
    "evidence_accessed", "evidence_exported", "evidence_deleted", "legal_hold_changed",
    "production_gate_blocked",
]

ACTION_CATEGORIES = {
    "security_query": [
        "query_internal_telemetry", "query_owned_asset_passive", "enrich_incident_ioc_passive",
    ],
    "incident_control": ["create_incident", "update_incident_status", "append_timeline_event"],
    "edge_protection": [
        "apply_waf_challenge", "apply_edge_rate_limit", "block_exact_invalid_pattern", "degrade_non_core_route",
    ],
    "identity_session_control": [
        "throttle_qr_issuance", "force_server_qr_verification", "revoke_exact_credentials",
        "apply_endpoint_rate_limit", "revoke_exact_session", "revoke_exact_api_credential",
    ],
    "compute_recovery": ["scale_exact_workload", "restart_exact_workload", "shift_queue_or_cache_mode"],
    "infrastructure_change": [
        "replace_certificate", "change_dns_authority", "shift_regional_traffic", "change_broad_firewall_rule",
    ],
    "database_recovery": [
        "promote_database_primary", "failover_database", "restore_database", "change_database_schema",
        "terminate_query_set", "delete_database_data",
    ],
    "disaster_recovery": [
        "execute_registered_failover", "execute_registered_failback", "run_isolated_dr_drill",
    ],
    "detection_release": ["release_detection_rule", "disable_detection_rule"],
    "evidence_governance": ["export_evidence", "change_legal_hold", "delete_evidence"],
    "external_notification": [
        "send_abuse_notification", "send_cert_notification", "send_provider_abuse_report",
        "send_corrective_notification",
    ],
}

APPROVAL_PAIRS = {
    "query_internal_telemetry": ("policy_authorized_read", []),
    "query_owned_asset_passive": ("policy_authorized_read", []),
    "enrich_incident_ioc_passive": ("policy_authorized_read", []),
    "create_incident": ("preauthorized_reversible", []),
    "update_incident_status": ("preauthorized_reversible", []),
    "append_timeline_event": ("preauthorized_reversible", []),
    "apply_waf_challenge": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "apply_edge_rate_limit": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "block_exact_invalid_pattern": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "degrade_non_core_route": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "throttle_qr_issuance": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "force_server_qr_verification": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "revoke_exact_credentials": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "apply_endpoint_rate_limit": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "revoke_exact_session": ("two_person_irreversible", ["incident_commander", "service_owner"]),
    "revoke_exact_api_credential": ("two_person_irreversible", ["incident_commander", "service_owner"]),
    "scale_exact_workload": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "restart_exact_workload": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "shift_queue_or_cache_mode": ("two_person_reversible", ["incident_commander", "service_owner"]),
    "replace_certificate": ("two_person_high_impact", ["incident_commander", "infrastructure_owner"]),
    "change_dns_authority": ("two_person_high_impact", ["incident_commander", "infrastructure_owner"]),
    "shift_regional_traffic": ("two_person_high_impact", ["incident_commander", "infrastructure_owner"]),
    "change_broad_firewall_rule": ("two_person_high_impact", ["incident_commander", "infrastructure_owner"]),
    "promote_database_primary": ("two_person_high_impact", ["incident_commander", "database_owner"]),
    "failover_database": ("two_person_high_impact", ["incident_commander", "database_owner"]),
    "restore_database": ("two_person_high_impact", ["incident_commander", "database_owner"]),
    "change_database_schema": ("two_person_high_impact", ["incident_commander", "database_owner"]),
    "terminate_query_set": ("two_person_irreversible", ["incident_commander", "database_owner"]),
    "delete_database_data": ("two_person_irreversible", ["incident_commander", "database_owner"]),
    "execute_registered_failover": ("two_person_high_impact", ["incident_commander", "infrastructure_owner"]),
    "execute_registered_failback": ("two_person_high_impact", ["incident_commander", "infrastructure_owner"]),
    "run_isolated_dr_drill": ("two_person_high_impact", ["security_owner", "system_owner"]),
    "release_detection_rule": ("two_person_high_impact", ["detection_engineering_reviewer", "siem_edr_owner"]),
    "disable_detection_rule": ("two_person_reversible", ["detection_engineering_reviewer", "siem_edr_owner"]),
    "export_evidence": ("two_person_irreversible", ["incident_commander", "privacy_legal_approver"]),
    "change_legal_hold": ("two_person_high_impact", ["incident_commander", "privacy_legal_approver"]),
    "delete_evidence": ("two_person_irreversible", ["incident_commander", "privacy_legal_approver"]),
    "send_abuse_notification": ("two_person_irreversible", ["incident_commander", "legal_compliance_approver"]),
    "send_cert_notification": ("two_person_irreversible", ["incident_commander", "legal_compliance_approver"]),
    "send_provider_abuse_report": ("two_person_irreversible", ["incident_commander", "legal_compliance_approver"]),
    "send_corrective_notification": ("two_person_irreversible", ["incident_commander", "legal_compliance_approver"]),
}

REGISTRY_KEYS = {
    "agents", "severity", "incident_status", "permission", "environment",
    "agent_result_status", "action_status", "notification_status", "normalized_parse_status",
    "threat_model_status", "detection_release_stage", "ioc_decision_status",
    "mcp_policy_status", "query_class", "action_categories", "audit_event",
}


def load(name: str) -> dict:
    value = load_yaml_strict(CONFIG_ROOT / name, ROOT)
    assert isinstance(value, dict)
    return value


def walk(value: object):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def test_exact_config_inventory_and_schema_versions() -> None:
    assert {path.name for path in CONFIG_ROOT.iterdir()} == CONFIG_NAMES
    assert all(path.is_file() and not path.is_symlink() for path in CONFIG_ROOT.iterdir())
    for name in CONFIG_NAMES:
        assert load(name)["schema_version"] == "1.0.0"


def test_agent_protocol_is_the_closed_enum_and_action_registry() -> None:
    registries = load("agent_protocol.yaml")["registries"]
    assert set(registries) == REGISTRY_KEYS
    assert registries["agents"] == list(AGENTS)
    assert registries["severity"] == ["P0", "P1", "P2", "P3"]
    assert registries["incident_status"] == ["detected", "triaged", "investigating", "mitigating", "monitoring", "recovered", "resolved", "reviewed"]
    assert registries["permission"] == ["observe", "recommend", "execute_reversible", "execute_high_impact"]
    assert registries["environment"] == ["development", "test", "staging", "production"]
    assert registries["agent_result_status"] == ["complete", "partial", "blocked", "failed"]
    assert registries["action_status"] == ["proposed", "awaiting_approval", "approved", "rejected", "executing", "succeeded", "failed", "compensated", "rolled_back"]
    assert registries["notification_status"] == ["draft", "awaiting_approval", "approved", "sent", "failed", "revoked"]
    assert registries["normalized_parse_status"] == ["parsed", "partial", "rejected"]
    assert registries["threat_model_status"] == ["incomplete", "complete"]
    assert registries["detection_release_stage"] == ["draft", "experimental", "validated", "staging_approved", "production_approved"]
    assert registries["ioc_decision_status"] == ["proposed", "authorized", "denied", "completed", "failed"]
    assert registries["mcp_policy_status"] == ["proposed", "authorized", "denied", "completed", "failed"]
    assert registries["query_class"] == ["internal_security_telemetry", "owned_asset", "incident_ioc"]
    assert registries["audit_event"] == AUDIT_EVENTS

    assert registries["action_categories"] == ACTION_CATEGORIES


def test_approval_matrix_is_closed_and_matches_action_contracts() -> None:
    matrix = load("approval_matrix.yaml")
    assert matrix["default_effect"] == "deny"
    assert matrix["approval_classes"] == APPROVAL_CLASSES
    assert len(matrix["approval_classes"]) == len(set(matrix["approval_classes"]))
    assert matrix["approver_roles"] == APPROVAL_ROLES
    assert len(matrix["approver_roles"]) == len(set(matrix["approver_roles"]))
    preauthorized = matrix["preauthorized_reversible"]
    assert set(preauthorized) == {
        "enabled", "trusted_config_required", "immutable_config_hash",
        "allowed_action_types", "authorized_role", "fallback",
    }
    assert preauthorized["enabled"] is False
    assert preauthorized["trusted_config_required"] is True
    assert set(preauthorized["immutable_config_hash"]) == set(UNCONFIGURED)
    assert preauthorized["allowed_action_types"] == ACTION_CATEGORIES["incident_control"]
    assert preauthorized["authorized_role"] == "incident_commander"
    assert preauthorized["fallback"] == "deny"
    raw_entries = matrix["action_approvals"]
    action_types = [entry["action_type"] for entry in raw_entries]
    assert len(raw_entries) == 41
    assert len(action_types) == len(set(action_types))
    assert action_types == [action for actions in ACTION_CATEGORIES.values() for action in actions]
    assert list(APPROVAL_PAIRS) == action_types
    entries = {entry["action_type"]: entry for entry in raw_entries}
    assert Counter(entry["approval_class"] for entry in raw_entries) == {
        "policy_authorized_read": 3,
        "preauthorized_reversible": 3,
        "two_person_reversible": 12,
        "two_person_high_impact": 13,
        "two_person_irreversible": 10,
    }
    for action_type, (approval_class, roles) in APPROVAL_PAIRS.items():
        entry = entries[action_type]
        assert set(entry) == {
            "action_type", "approval_class", "approver_roles",
            "exact_scope_required", "finite_expiry_required", "wildcards_allowed",
        }
        assert entry["approval_class"] == approval_class
        assert entry["approver_roles"] == roles
        assert entry["exact_scope_required"] is True
        assert entry["finite_expiry_required"] is True
        assert entry["wildcards_allowed"] is False


def test_agent_permissions_are_least_privilege_and_default_deny() -> None:
    permissions = load("agent_permissions.yaml")
    assert permissions["default_effect"] == "deny"
    raw_roles = permissions["agents"]
    agent_ids = [role["agent_id"] for role in raw_roles]
    assert len(raw_roles) == 12
    assert len(agent_ids) == len(set(agent_ids))
    assert agent_ids == list(AGENTS)
    roles = {role["agent_id"]: role for role in raw_roles}
    assert {agent_id: role["maximum_permission"] for agent_id, role in roles.items()} == AGENTS
    ordered = ["observe", "recommend", "execute_reversible", "execute_high_impact"]
    for agent_id, maximum in AGENTS.items():
        role = roles[agent_id]
        assert set(role) == {"agent_id", "maximum_permission", "grants", "explicit_denials"}
        assert role["grants"] == ordered[: ordered.index(maximum) + 1]
        assert role["explicit_denials"]
        assert "bypass_approval" in role["explicit_denials"]


def test_qr_thresholds_and_standards_are_fixed() -> None:
    thresholds = load("thresholds.yaml")
    assert thresholds["qr"]["participant_valid_credential_bands"] == [
        {"name": "below_baseline", "minimum": 0, "maximum": 799},
        {"name": "normal", "minimum": 800, "maximum": 900},
        {"name": "warning", "minimum": 901, "maximum": 999},
        {"name": "high", "minimum": 1000, "maximum": 1199},
        {"name": "critical", "minimum": 1200, "maximum": None},
    ]
    standards = load("standards_versions.yaml")["standards"]
    assert standards == {
        "mitre_attack": "19.1",
        "sigma_specification": "2.1.0",
        "pysigma": "1.4.0",
        "pysigma_backend_elasticsearch": "2.1.0",
        "pysigma_pipeline_sysmon": "2.0.0",
        "yara_language": "4.5",
        "yara_python": "4.5.4",
        "json_schema": "2020-12",
    }


@pytest.mark.parametrize(
    ("credential_count", "expected_band"),
    [
        (799, "below_baseline"),
        (800, "normal"),
        (900, "normal"),
        (901, "warning"),
        (999, "warning"),
        (1000, "high"),
        (1199, "high"),
        (1200, "critical"),
        (3000, "critical"),
    ],
)
def test_qr_credential_boundary_classification(credential_count: int, expected_band: str) -> None:
    qr = load("thresholds.yaml")["qr"]
    matches = [
        band["name"]
        for band in qr["participant_valid_credential_bands"]
        if credential_count >= band["minimum"]
        and (band["maximum"] is None or credential_count <= band["maximum"])
    ]
    assert matches == [expected_band]
    assert qr["incomplete_stage_result"] == "collecting"


def test_qr_bands_are_contiguous_stage_bound_and_investigative_only() -> None:
    qr = load("thresholds.yaml")["qr"]
    bands = qr["participant_valid_credential_bands"]
    assert bands[0]["minimum"] == 0
    assert bands[-1]["maximum"] is None
    for previous, current in zip(bands, bands[1:]):
        assert previous["maximum"] is not None
        assert current["minimum"] == previous["maximum"] + 1
    assert qr["required_dimensions"] == ["event", "role", "environment", "stage"]
    assert qr["full_population_stage_required"] is True
    assert qr["anomaly_is_proof_of_intrusion"] is False


def test_default_closed_assets_integrations_and_production_values() -> None:
    assets = load("authorized_assets.yaml")
    assert assets["default_effect"] == "deny"
    assert assets["assets"] == {"ip": [], "cidr": [], "domain": [], "lockfile": []}
    assert load("mcp_tool_policy.yaml")["servers"] == []
    notification = load("notification_policy.yaml")
    assert notification["enabled"] is False
    assert notification["recipients"] == []
    assert notification["channels"] == []
    assert notification["templates"] == []
    assert load("incident_ioc_policy.yaml")["providers"] == []

    for filename in CONFIG_NAMES:
        config = load(filename)
        for item in walk(config):
            if isinstance(item, dict) and item.get("configured") is False:
                assert UNCONFIGURED.keys() <= item.keys()
                assert {key: item.get(key) for key in UNCONFIGURED} == UNCONFIGURED
            if isinstance(item, str):
                assert not any(character in item for character in "*?[]")

    runtime = load("runtime.example.yaml")
    assert runtime["resources"]["gateway_endpoint"].endswith(".invalid")
    for adapter in runtime["adapters"].values():
        assert adapter["api_secret_ref"].startswith("secret://")
        assert UNCONFIGURED.keys() <= adapter["provider_model"].keys()
        assert {key: adapter["provider_model"].get(key) for key in UNCONFIGURED} == UNCONFIGURED


def test_service_baselines_preserve_expected_units_while_values_are_unconfigured() -> None:
    baselines = load("thresholds.yaml")["service_baselines"]
    assert {name: baseline["expected_unit"] for name, baseline in baselines.items()} == {
        "traffic": "requests_per_second",
        "latency": "milliseconds",
        "error_rate": "percent",
        "resource_pressure": "percent",
        "database": "deployment_defined",
    }
    for baseline in baselines.values():
        assert UNCONFIGURED.keys() <= baseline.keys()
        assert {key: baseline.get(key) for key in UNCONFIGURED} == UNCONFIGURED
        assert UNCONFIGURED.keys() <= baseline["window"].keys()
        assert {key: baseline["window"].get(key) for key in UNCONFIGURED} == UNCONFIGURED
        assert UNCONFIGURED.keys() <= baseline["source"].keys()
        assert {key: baseline["source"].get(key) for key in UNCONFIGURED} == UNCONFIGURED
        assert UNCONFIGURED.keys() <= baseline["effective_at"].keys()
        assert {key: baseline["effective_at"].get(key) for key in UNCONFIGURED} == UNCONFIGURED


def test_fifteen_config_responsibilities_are_present_without_shadow_registries() -> None:
    exact_top_level = {
        "thresholds.yaml": {"qr", "service_baselines"},
        "alert_rules.yaml": {"default_effect", "rules", "required_fields", "missing_baseline_behavior"},
        "recovery_policy.yaml": {"default_effect", "services", "required_contract", "production_gate"},
        "agent_permissions.yaml": {"default_effect", "agents"},
        "agent_protocol.yaml": {"registries"},
        "approval_matrix.yaml": {"default_effect", "approval_classes", "approver_roles", "action_approvals", "preauthorized_reversible"},
        "slo.yaml": {"services", "required_sli_fields", "missing_value_behavior", "production_gate"},
        "forensics_policy.yaml": {"classification_transitions", "retention", "legal_hold", "rbac", "pseudonymization", "export", "delete"},
        "notification_policy.yaml": {"enabled", "recipients", "channels", "templates", "trigger_requirements", "approval_class", "frequency", "audit", "compensation"},
        "authorized_assets.yaml": {"default_effect", "assets", "required_registration_fields", "symlinks_allowed", "model_mutation_allowed"},
        "incident_ioc_policy.yaml": {"default_effect", "classifications", "types", "providers", "required_fields", "non_recursive", "third_party_result_expands_scope", "active_scanning_allowed"},
        "mcp_tool_policy.yaml": {"default_effect", "servers", "global_gates", "unknown_server_behavior", "unknown_tool_behavior"},
        "vulnerability_priority_policy.yaml": {"inputs", "decision", "production_gate"},
        "standards_versions.yaml": {"standards", "upgrade_review_required"},
        "runtime.example.yaml": {"configured", "value", "unit", "required_before_production", "display_identity", "adapters", "resources", "production_gate"},
    }
    for filename, keys in exact_top_level.items():
        assert set(load(filename)) == {"schema_version", *keys}

    shadow_registry_keys = REGISTRY_KEYS | {
        "registries",
        "approval_classes", "approver_roles", "action_approvals",
    }
    for filename in CONFIG_NAMES - {"agent_protocol.yaml", "approval_matrix.yaml"}:
        allowed_reference_keys = {"agents"} if filename == "agent_permissions.yaml" else set()
        for item in walk(load(filename)):
            if isinstance(item, dict):
                assert (shadow_registry_keys - allowed_reference_keys).isdisjoint(item)


def test_runtime_adapter_identity_and_provider_models_are_separate_and_unconfigured() -> None:
    runtime = load("runtime.example.yaml")
    assert runtime["display_identity"] == "Aegis Mesh"
    assert set(runtime["adapters"]) == {"kimi", "openai", "claude"}
    for name, adapter in runtime["adapters"].items():
        assert set(adapter) == {
            "configured", "value", "unit", "required_before_production",
            "provider_model", "api_secret_ref",
        }
        assert {key: adapter[key] for key in UNCONFIGURED} == UNCONFIGURED
        assert adapter["provider_model"] == UNCONFIGURED
        assert adapter["api_secret_ref"] == f"secret://runtime/{name}-api-key"
    assert runtime["production_gate"]["blockers"] == [
        "provider_model_missing", "credentials_missing", "production_endpoints_missing",
        "live_mcp_conformance_missing",
    ]


def test_scenarios_reference_config_registries_without_adding_approval_layers() -> None:
    protocol = load("agent_protocol.yaml")["registries"]
    approvals = load("approval_matrix.yaml")
    corpus = [
        case
        for path in sorted((ROOT / "scenarios").glob("*.yaml"))
        for case in load_yaml_strict(path, ROOT)["cases"]
    ]
    assert all(set(case["expected_routes"]) <= set(protocol["agents"]) for case in corpus)
    assert all(case["minimum_severity"] in protocol["severity"] for case in corpus)
    assert approvals["approval_classes"] == [
        "policy_authorized_read", "preauthorized_reversible", "two_person_reversible",
        "two_person_high_impact", "two_person_irreversible",
    ]
