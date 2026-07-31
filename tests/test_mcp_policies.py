from datetime import datetime
from pathlib import Path

from scripts.validation_core import load_json_strict, load_yaml_strict, raw_sha256


ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "integrations/wazuh-mcp"
FIXTURE = ROOT / "tests/fixtures/mcp/wazuh-v4.2.1-tools-list.json"
COMMIT = "52c1d375d22419ce662bc4218f904de015e4a7c7"
ARCHIVE_HASH = "sha256:107a1c24b412215a1ebf73531ced6335f05a11adf8edbd4194cce154e250a166"

READ_TOOLS = (
    "get_wazuh_alerts", "get_wazuh_alert_summary", "analyze_alert_patterns",
    "get_wazuh_agents", "get_wazuh_running_agents", "check_agent_health",
    "get_agent_processes", "get_agent_ports", "get_agent_configuration",
    "get_wazuh_vulnerabilities", "get_wazuh_critical_vulnerabilities",
    "get_wazuh_vulnerability_summary", "search_security_events",
    "analyze_security_threat", "check_ioc_reputation", "perform_risk_assessment",
    "get_top_security_threats", "generate_security_report", "run_compliance_check",
    "get_wazuh_statistics", "get_wazuh_weekly_stats", "get_wazuh_cluster_health",
    "get_wazuh_cluster_nodes", "get_wazuh_rules_summary", "get_wazuh_remoted_stats",
    "get_wazuh_log_collector_stats", "search_wazuh_manager_logs",
    "get_wazuh_manager_error_logs", "validate_wazuh_connection",
    "wazuh_check_blocked_ip", "wazuh_check_agent_isolation", "wazuh_check_process",
    "wazuh_check_user_status", "wazuh_check_file_quarantine",
)

WRITE_TOOLS = (
    "wazuh_block_ip", "wazuh_isolate_host", "wazuh_kill_process",
    "wazuh_disable_user", "wazuh_quarantine_file", "wazuh_firewall_drop",
    "wazuh_host_deny", "wazuh_active_response", "wazuh_restart",
    "wazuh_unisolate_host", "wazuh_enable_user", "wazuh_restore_file",
    "wazuh_firewall_allow", "wazuh_host_allow",
)

ADEO_INTEGRATION = ROOT / "integrations/adeo-cti-mcp"
ADEO_FIXTURE = ROOT / "tests/fixtures/mcp/adeo-ba7c696-tools-list.json"
ADEO_COMMIT = "ba7c6962c7bcb69964a44da9228cf5d43b7e7606"
ADEO_ARCHIVE_HASH = "sha256:fce173443e3de16aa2affa7a41f9a622928553072632d4f9b2d3db16686c507c"
ADEO_RETAINED = (
    "host-info", "dns-lookup", "reverse-dns", "domain-info", "search-host-count",
    "virustotal-file-analysis", "virustotal-ip-analysis", "virustotal-domain-analysis",
)
ADEO_REMOVED = (
    "hello", "search-host", "list-search-facets", "list-search-filters",
    "search-tokens", "list-ports", "list-protocols", "request-scan",
    "get-scan-status", "list-scans", "list-triggers", "create-alert",
    "get-alert-info", "delete-alert", "edit-alert", "list-alerts",
    "list-queries", "search-queries", "list-query-tags", "get-profile",
    "get-api-info", "get-billing", "get-http-headers", "get-my-ip",
    "virustotal-url-analysis", "virustotal-yara-rules", "current-date", "current-time",
)
ADEO_PROMPTS = (
    "asset-discovery", "vulnerability-assessment", "internet-search", "network-monitoring",
    "ics-analysis", "dns-intelligence", "service-exposure", "account-status",
    "scan-management", "search-analytics", "vulnerability-hunting", "malware-analysis",
    "infrastructure-analysis", "threat-hunting",
)
ADEO_RESOURCES = ("threat-hunting-guide", "shodan-tools-guide", "virustotal-tools-guide")

VULNFEED_INTEGRATION = ROOT / "integrations/vulnfeed-mcp"
VULNFEED_FIXTURE = ROOT / "tests/fixtures/mcp/vulnfeed-aa2452d-tools-list.json"
VULNFEED_COMMIT = "aa2452d724b29a6ee3e2bb68187c783ef2bb8847"
VULNFEED_ARCHIVE_HASH = "sha256:5ba594aca8be2878f36ab873eecae939d2c99c85240f52267828f292bcddbe4d"
VULNFEED_ALLOWED = ("scan_lockfile",)
VULNFEED_DENIED = (
    "scan_project", "check_package", "lookup_cve", "monitor_project",
    "check_alerts", "update_deps", "list_monitored", "unmonitor_project",
)


def load_yaml(path: Path) -> dict:
    value = load_yaml_strict(path, ROOT)
    assert isinstance(value, dict)
    return value


def load_json(path: Path) -> dict:
    value = load_json_strict(path, ROOT)
    assert isinstance(value, dict)
    return value


def test_wazuh_reviewed_fixture_is_exact_48_tool_partition() -> None:
    fixture = load_json(FIXTURE)
    assert fixture["schema_version"] == "1.0.0"
    assert fixture["source_commit"] == COMMIT
    assert fixture["source_ref"] == "v4.2.1"
    tools = fixture["tools"]
    assert len(tools) == 48
    assert all(set(tool) == {"name", "required_scope"} for tool in tools)
    names = [tool["name"] for tool in tools]
    assert len(names) == len(set(names))
    assert set(names) == set(READ_TOOLS) | set(WRITE_TOOLS)
    assert {tool["name"] for tool in tools if tool["required_scope"] == "wazuh:read"} == set(READ_TOOLS)
    assert {tool["name"] for tool in tools if tool["required_scope"] == "wazuh:write"} == set(WRITE_TOOLS)


def test_wazuh_upstream_lock_is_complete_and_honestly_blocked() -> None:
    lock = load_yaml(INTEGRATION / "upstream.lock.yaml")
    assert set(lock) == {
        "schema_version", "server_id", "repository_url", "requested_repository_url",
        "source_ref", "source_commit", "source_archive_sha256", "tool_inventory_fixture",
        "tool_inventory_sha256", "observed_tool_count", "license_status",
        "license_evidence_ref", "dependency_lock_ref", "dependency_lock_sha256",
        "sbom_ref", "sbom_sha256", "image_digest", "reviewed_at", "reviewed_by",
        "production_gate",
    }
    assert lock["schema_version"] == "1.0.0"
    assert lock["server_id"] == "wazuh-mcp"
    assert lock["repository_url"] == "https://github.com/gensecaihq/Wazuh-MCP-Server"
    assert lock["requested_repository_url"] is None
    assert lock["source_ref"] == "v4.2.1" and lock["source_commit"] == COMMIT
    assert lock["source_archive_sha256"] == ARCHIVE_HASH
    assert lock["tool_inventory_fixture"] == "tests/fixtures/mcp/wazuh-v4.2.1-tools-list.json"
    assert lock["tool_inventory_sha256"] == raw_sha256(FIXTURE, ROOT)
    assert lock["observed_tool_count"] == 48
    assert lock["license_status"] == "verified_mit"
    assert lock["license_evidence_ref"] == (
        f"https://github.com/gensecaihq/Wazuh-MCP-Server/blob/{COMMIT}/LICENSE"
    )
    reviewed_at = datetime.fromisoformat(lock["reviewed_at"])
    assert reviewed_at.tzinfo is not None
    assert isinstance(lock["reviewed_by"], str) and lock["reviewed_by"].strip()
    for field in (
        "dependency_lock_ref", "dependency_lock_sha256", "sbom_ref", "sbom_sha256", "image_digest",
    ):
        assert lock[field] is None
    gate = lock["production_gate"]
    assert set(gate) == {
        "enabled", "status", "blocked_reasons", "required_live_attestations",
    }
    assert gate["enabled"] is False and gate["status"] == "blocked"
    assert set(gate["blocked_reasons"]) >= {
        "complete_dependency_lock_missing", "sbom_missing", "controlled_reproducible_build_missing",
        "reviewed_image_digest_missing", "live_readonly_upstream_inventory_attestation_missing",
        "gateway_conformance_attestation_missing", "deployment_configuration_missing",
    }
    assert set(gate["required_live_attestations"]) == {
        "live_upstream_tools_list_exact_34", "gateway_client_tools_list_exact_34",
        "fourteen_denied_tools_call_level_rejected", "authentication_mode_non_none",
        "token_scope_exactly_wazuh_read", "tls_verification_enabled",
        "gateway_query_and_redaction_conformance",
    }


def test_wazuh_policy_is_read_only_default_deny_without_extra_approval() -> None:
    policy = load_yaml(INTEGRATION / "tool_policy.yaml")
    assert policy["schema_version"] == "1.0.0"
    assert policy["server_id"] == "wazuh-mcp"
    assert policy["enabled"] is False and policy["default_effect"] == "deny"
    identity = policy["runtime_identity"]
    assert identity == {"required_scope": "wazuh:read", "forbidden_scopes": ["wazuh:write"]}
    assert policy["gateway_only"] is True and policy["direct_upstream_connection"] is False
    auth = policy["authentication"]
    assert len(auth["allowed_modes"]) == 2
    assert set(auth["allowed_modes"]) == {"bearer", "oauth2"}
    assert {
        key: auth[key] for key in ("configured", "value", "unit", "required_before_production")
    } == {
        "configured": False, "value": None, "unit": None, "required_before_production": True,
    }
    assert auth["credential_ref_example"] == "secret://runtime/wazuh-mcp-token"
    tls = policy["tls"]
    assert tls["verify"] is True
    assert {key: tls[key] for key in ("configured", "value", "unit", "required_before_production")} == {
        "configured": False, "value": None, "unit": None, "required_before_production": True,
    }
    assert policy["AUTHLESS_ALLOW_WRITE"] is False
    inventory = policy["inventory"]
    assert inventory["reviewed_upstream_count"] == 48
    assert inventory["live_upstream_count"] == 34
    assert inventory["gateway_client_count"] == 34
    assert inventory["live_upstream_count"] == inventory["gateway_client_count"] == len(READ_TOOLS)
    assert set(inventory["allow_tools"]) == set(READ_TOOLS)
    assert set(inventory["deny_tools"]) == set(WRITE_TOOLS)
    assert inventory["exposure_mode"] == "allowlist_only"
    assert set(inventory["allow_tools"]).isdisjoint(inventory["deny_tools"])
    assert len(inventory["deny_tools"]) == len(WRITE_TOOLS)
    assert policy["call_policy"]["denied_tool_source"] == "inventory.deny_tools"
    assert policy["call_policy"]["denied_tool_effect"] == "deny_and_audit"
    assert policy["call_policy"]["unknown_tool"] == "deny"
    assert policy["call_policy"]["unknown_argument"] == "deny"
    assert policy["call_policy"]["unknown_server"] == "deny"
    assert policy["call_policy"]["scope_mismatch"] == "deny"
    assert policy["call_policy"]["inventory_drift"] == "refuse_startup"
    assert policy["query_class"] == "internal_security_telemetry"
    assert policy["tool_annotations"] == {
        "readOnlyHint": True, "destructiveHint": False,
        "idempotentHint": True, "openWorldHint": True,
    }
    assert policy["approval"] == {
        "class": "policy_authorized_read",
        "additional_human_approval_required": False,
    }
    assert policy["request_contract"] == {
        "schema": "schemas/mcp-query-request.schema.json",
        "required_query_class": "internal_security_telemetry",
        "formal_incident_required": True,
        "internal_resource_ref_required": True,
        "requesting_agent_required": True,
    }
    controls = policy["runtime_controls"]
    for name in ("exact_egress", "rate_limit"):
        assert controls[name] == {
            "configured": False, "value": None, "unit": None,
            "required_before_production": True,
        }
    assert controls["redaction_required"] is True and controls["audit_required"] is True
    assert policy["production_gate"] == {"enabled": False, "status": "blocked"}


def test_wazuh_agent_mapping_is_closed_and_orchestrator_gets_summaries() -> None:
    policy = load_yaml(INTEGRATION / "tool_policy.yaml")
    mappings = policy["agent_tool_mapping"]
    assert set(mappings) == {
        "observability-agent", "threat-intelligence-agent", "infrastructure-agent",
        "kubernetes-agent", "database-agent", "incident-response-agent",
    }
    mapped = set()
    for tools in mappings.values():
        assert tools
        assert set(tools) <= set(READ_TOOLS)
        mapped.update(tools)
    assert mapped == set(READ_TOOLS)
    delivery = policy["main_orchestrator_delivery"]
    assert delivery["default_full_logs"] is False
    assert delivery["allowed"] == ["summaries", "evidence_references"]


def test_wazuh_example_manifest_is_disabled_and_contains_no_credentials() -> None:
    manifest = load_json(INTEGRATION / "mcp.example.json")
    assert set(manifest) == {
        "schema_version", "configured", "value", "unit", "required_before_production", "mcpServers",
    }
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["configured"] is False and manifest["value"] is None
    assert manifest["unit"] is None
    assert manifest["required_before_production"] is True
    assert set(manifest["mcpServers"]) == {"wazuh"}
    server = manifest["mcpServers"]["wazuh"]
    assert set(server) == {
        "enabled", "gateway_only", "direct_upstream_connection", "transport", "url",
        "tls_verify", "scopes", "forbidden_scopes", "auth_mode",
        "AUTHLESS_ALLOW_WRITE", "credential_ref",
    }
    assert server["enabled"] is False
    assert server["gateway_only"] is True and server["direct_upstream_connection"] is False
    assert server["transport"] == "streamable_http"
    assert server["url"] == "https://gateway.example.invalid/mcp/wazuh"
    assert server["tls_verify"] is True
    assert server["scopes"] == ["wazuh:read"]
    assert server["forbidden_scopes"] == ["wazuh:write"]
    assert server["auth_mode"] == "bearer"
    assert server["AUTHLESS_ALLOW_WRITE"] is False
    assert server["credential_ref"] == "secret://runtime/wazuh-mcp-token"
    forbidden_keys = {
        "token", "password", "api_key", "client_secret", "access_token",
        "authorization", "private_key", "secret",
    }

    def reject_raw_credentials(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                assert key == "credential_ref" or key.lower() not in forbidden_keys
                reject_raw_credentials(item)
        elif isinstance(value, list):
            for item in value:
                reject_raw_credentials(item)
        elif isinstance(value, str):
            assert "-----BEGIN" not in value
            assert not value.startswith("Bearer ")

    reject_raw_credentials(manifest)


def test_wazuh_docs_require_live_fail_closed_boundary_without_bureaucracy() -> None:
    integration = (INTEGRATION / "INTEGRATION.md").read_text(encoding="utf-8")
    boundary = (INTEGRATION / "SECURITY_BOUNDARY.md").read_text(encoding="utf-8")
    for phrase in (
        "live upstream `tools/list` must equal the 34-item allowlist",
        "client-facing `tools/list` must equal the same 34-item allowlist",
        "refuse service on inventory drift", "call-level deny", "wazuh:write",
        "captured live attestation", "Gateway conformance", "production blocked",
        "summaries and evidence references", "not default full logs",
    ):
        assert phrase in integration
    for phrase in (
        "bearer or OAuth", "reverse-proxy TLS", "Secret Manager", "redaction",
        "operator-configured rate limit", "audit", "internal-only network",
        "independent source review", "AUTHLESS_ALLOW_WRITE=false",
        "no additional human approval", "does not trust annotations as enforcement",
    ):
        assert phrase in boundary


def test_mcp_acceptance_scenarios_use_only_reviewed_tool_names() -> None:
    reviewed = {
        tool["name"]
        for fixture in (FIXTURE, ADEO_FIXTURE, VULNFEED_FIXTURE)
        for tool in load_json(fixture)["tools"]
    }
    references = {
        reference.split(":", 1)[1]
        for path in (ROOT / "scenarios").glob("*.yaml")
        for case in load_yaml(path)["cases"]
        for reference in case["expected_actions"] + case["prohibited_actions"]
        if reference.startswith("mcp_tool:")
    }
    assert references <= reviewed
    allowed = set(READ_TOOLS) | set(ADEO_RETAINED) | set(VULNFEED_ALLOWED)
    expected = {
        reference.split(":", 1)[1]
        for path in (ROOT / "scenarios").glob("*.yaml")
        for case in load_yaml(path)["cases"]
        for reference in case["expected_actions"]
        if reference.startswith("mcp_tool:")
    }
    assert expected <= allowed


def test_adeo_reviewed_fixture_is_exact_36_tool_partition() -> None:
    fixture = load_json(ADEO_FIXTURE)
    assert set(fixture) == {"schema_version", "source_commit", "tools", "prompts", "resources"}
    assert fixture["schema_version"] == "1.0.0"
    assert fixture["source_commit"] == ADEO_COMMIT
    tools = fixture["tools"]
    assert len(tools) == 36
    assert all(set(tool) == {"name", "disposition"} for tool in tools)
    names = [tool["name"] for tool in tools]
    assert len(names) == len(set(names))
    assert set(names) == set(ADEO_RETAINED) | set(ADEO_REMOVED)
    assert {tool["name"] for tool in tools if tool["disposition"] == "retained_candidate"} == set(ADEO_RETAINED)
    assert {tool["name"] for tool in tools if tool["disposition"] == "physical_removal_required"} == set(ADEO_REMOVED)
    assert set(fixture["prompts"]) == set(ADEO_PROMPTS) and len(fixture["prompts"]) == 14
    assert set(fixture["resources"]) == set(ADEO_RESOURCES) and len(fixture["resources"]) == 3


def test_adeo_upstream_lock_records_unresolved_license_and_blockers() -> None:
    lock = load_yaml(ADEO_INTEGRATION / "upstream.lock.yaml")
    assert set(lock) == {
        "schema_version", "server_id", "repository_url", "requested_repository_url",
        "source_ref", "source_commit", "source_archive_sha256", "tool_inventory_fixture",
        "tool_inventory_sha256", "observed_tool_count", "license_status",
        "license_evidence_ref", "dependency_lock_ref", "dependency_lock_sha256",
        "sbom_ref", "sbom_sha256", "image_digest", "reviewed_at", "reviewed_by",
        "production_gate",
    }
    assert lock["schema_version"] == "1.0.0" and lock["server_id"] == "adeo-cti-mcp"
    assert lock["repository_url"] == "https://github.com/ADEOSec/mcp-shodan"
    assert lock["requested_repository_url"] is None
    assert lock["source_ref"] == ADEO_COMMIT
    assert lock["source_commit"] == ADEO_COMMIT
    assert lock["source_archive_sha256"] == ADEO_ARCHIVE_HASH
    assert lock["tool_inventory_fixture"] == "tests/fixtures/mcp/adeo-ba7c696-tools-list.json"
    assert lock["tool_inventory_sha256"] == raw_sha256(ADEO_FIXTURE, ROOT)
    assert lock["observed_tool_count"] == 36
    assert lock["license_status"] == "unresolved"
    assert lock["license_evidence_ref"] == "integrations/adeo-cti-mcp/INTEGRATION.md#license-evidence"
    for field in (
        "dependency_lock_ref", "dependency_lock_sha256", "sbom_ref", "sbom_sha256", "image_digest",
    ):
        assert lock[field] is None
    reviewed_at = datetime.fromisoformat(str(lock["reviewed_at"]))
    assert reviewed_at.utcoffset() is not None
    assert isinstance(lock["reviewed_by"], str) and lock["reviewed_by"].strip()
    gate = lock["production_gate"]
    assert set(gate) == {"enabled", "status", "blocked_reasons", "required_live_attestations"}
    assert gate["enabled"] is False and gate["status"] == "blocked"
    assert set(gate["blocked_reasons"]) == {
        "license_permission_unresolved", "safe_fork_missing", "credential_handling_fix_missing",
        "dependency_lock_inconsistent", "sbom_missing", "reproducible_artifact_missing",
        "live_removed_capabilities_attestation_missing", "gateway_conformance_missing",
        "upstream_interface_drift", "reviewed_image_digest_missing",
        "deployment_configuration_missing",
    }
    assert set(gate["required_live_attestations"]) == {
        "safe_fork_tools_list_exact_8", "safe_fork_prompts_list_empty",
        "safe_fork_resources_list_empty", "removed_tools_call_rejected",
        "credential_redaction_conformance", "gateway_conformance",
    }


def test_adeo_policy_exposes_only_passive_candidate_surface() -> None:
    policy = load_yaml(ADEO_INTEGRATION / "tool_policy.yaml")
    assert set(policy) == {
        "schema_version", "server_id", "enabled", "candidate_only", "default_effect",
        "gateway_only", "direct_upstream_connection", "upstream_code_copied",
        "query_schema", "authorized_agents", "inventory", "upstream_capabilities",
        "call_policy", "contracts", "independent_url_adapter", "credential_boundary",
        "runtime_controls", "output_boundary", "approval", "production_gate",
    }
    assert policy["schema_version"] == "1.0.0" and policy["server_id"] == "adeo-cti-mcp"
    assert policy["enabled"] is False and policy["default_effect"] == "deny"
    assert policy["candidate_only"] is True
    assert policy["gateway_only"] is True and policy["direct_upstream_connection"] is False
    assert policy["upstream_code_copied"] is False
    assert policy["query_schema"] == "schemas/mcp-query-request.schema.json"
    assert policy["authorized_agents"] == ["threat-intelligence-agent"]
    inventory = policy["inventory"]
    assert set(inventory) == {
        "fixture", "reviewed_upstream_count", "future_fork_client_count",
        "exposure_mode", "retained_tools", "physical_removal_required",
    }
    assert inventory["reviewed_upstream_count"] == 36
    assert inventory["future_fork_client_count"] == 8
    assert set(inventory["retained_tools"]) == set(ADEO_RETAINED)
    assert set(inventory["physical_removal_required"]) == set(ADEO_REMOVED)
    assert len(inventory["retained_tools"]) == len(ADEO_RETAINED)
    assert len(inventory["physical_removal_required"]) == len(ADEO_REMOVED)
    assert inventory["exposure_mode"] == "future_safe_fork_exact_allowlist"
    capabilities = policy["upstream_capabilities"]
    assert capabilities == {
        "reviewed_prompt_count": 14, "reviewed_resource_count": 3,
        "future_client_prompt_count": 0, "future_client_resource_count": 0,
        "physical_removal_required": True,
    }
    assert policy["call_policy"] == {
        "removed_tool": "deny", "unknown_tool": "deny", "unknown_argument": "deny",
        "unknown_server": "deny", "scope_mismatch": "deny", "inventory_drift": "refuse_startup",
    }
    assert policy["approval"] == {
        "class": "policy_authorized_read", "additional_human_approval_required": False,
    }
    credentials = policy["credential_boundary"]
    assert set(credentials) == {
        "key_in_argv_allowed", "shodan_key_in_logged_url_allowed", "configured",
        "value", "unit", "required_before_production", "credential_ref_examples",
    }
    assert credentials["key_in_argv_allowed"] is False
    assert credentials["shodan_key_in_logged_url_allowed"] is False
    assert {key: credentials[key] for key in (
        "configured", "value", "unit", "required_before_production",
    )} == {
        "configured": False, "value": None, "unit": None, "required_before_production": True,
    }
    assert credentials["credential_ref_examples"] == [
        "secret" + "://runtime/shodan-api-key",
        "secret" + "://runtime/virustotal-api-key",
    ]
    controls = policy["runtime_controls"]
    assert set(controls) == {
        "exact_egress", "rate_limit", "tls_verification_required",
        "redaction_required", "audit_required",
    }
    for name in ("exact_egress", "rate_limit"):
        assert controls[name] == {
            "configured": False, "value": None, "unit": None,
            "required_before_production": True,
        }
    assert controls["tls_verification_required"] is True
    assert controls["redaction_required"] is True and controls["audit_required"] is True
    assert policy["output_boundary"] == {
        "third_party_results_are_untrusted": True,
        "third_party_results_expand_scope": False,
        "main_orchestrator_default": ["summary", "evidence_reference"],
    }
    assert policy["production_gate"] == {"enabled": False, "status": "blocked"}


def test_shodan_contract_requires_owned_asset_and_gateway_ast() -> None:
    policy = load_yaml(ADEO_INTEGRATION / "tool_policy.yaml")
    assert set(policy["contracts"]) == {"shodan", "search_host_count", "virustotal"}
    shodan = policy["contracts"]["shodan"]
    assert set(shodan) == {
        "tools", "query_class", "owned_asset_id_required",
        "verified_exact_asset_match_required", "active_scan_allowed",
        "owned_asset_types_by_tool",
    }
    assert set(shodan["tools"]) == set(ADEO_RETAINED[:5])
    assert len(shodan["tools"]) == len(ADEO_RETAINED[:5])
    assert shodan["query_class"] == "owned_asset"
    assert shodan["owned_asset_id_required"] is True
    assert shodan["verified_exact_asset_match_required"] is True
    assert shodan["active_scan_allowed"] is False
    assert shodan["owned_asset_types_by_tool"] == {
        "host-info": ["ip"],
        "dns-lookup": ["domain"],
        "reverse-dns": ["ip"],
        "domain-info": ["domain"],
        "search-host-count": ["ip", "cidr", "domain"],
    }
    count = policy["contracts"]["search_host_count"]
    assert set(count) == {
        "raw_query_allowed", "gateway_ast_required", "allowed_ast_nodes", "forbidden_operators",
    }
    assert count["raw_query_allowed"] is False and count["gateway_ast_required"] is True
    assert count["allowed_ast_nodes"] == ["term", "and"]
    assert count["forbidden_operators"] == ["or", "not", "wildcard"]


def test_virustotal_contract_is_passive_and_type_bound() -> None:
    policy = load_yaml(ADEO_INTEGRATION / "tool_policy.yaml")
    vt = policy["contracts"]["virustotal"]
    assert set(vt) == {
        "file", "ip", "domain", "active_submission_allowed",
        "private_url_allowed", "customer_data_allowed", "incident_ioc_evidence_contract",
    }
    assert vt["incident_ioc_evidence_contract"] == {
        "required_request_field": "evidence",
        "required_exact_scope_field": "evidence_id",
        "binding": "exact_scope.evidence_id == evidence.evidence_id",
    }
    assert vt["file"] == {
        "tool": "virustotal-file-analysis", "query_class": "incident_ioc",
        "required_ioc_type": "file_hash", "file_upload_allowed": False,
    }
    assert vt["ip"] == {
        "tool": "virustotal-ip-analysis",
        "allowed_query_classes": ["incident_ioc", "owned_asset"],
        "required_ioc_type": "ip", "required_owned_asset_type": "ip",
        "verified_exact_asset_match_required": True,
    }
    assert vt["domain"] == {
        "tool": "virustotal-domain-analysis",
        "allowed_query_classes": ["incident_ioc", "owned_asset"],
        "required_ioc_type": "domain", "required_owned_asset_type": "domain",
        "verified_exact_asset_match_required": True,
    }
    assert vt["active_submission_allowed"] is False
    assert vt["private_url_allowed"] is False and vt["customer_data_allowed"] is False
    assert policy["independent_url_adapter"] == {
        "name": "vt-readonly-url-report", "counted_in_upstream_inventory": False,
        "enabled": False, "specification": "integrations/adeo-cti-mcp/vt-readonly-url-report.md",
    }


def test_adeo_manifest_and_docs_remain_disabled_without_secrets() -> None:
    manifest = load_json(ADEO_INTEGRATION / "mcp.example.json")
    assert set(manifest) == {
        "schema_version", "configured", "value", "unit", "required_before_production", "mcpServers",
    }
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["configured"] is False and manifest["value"] is None and manifest["unit"] is None
    assert manifest["required_before_production"] is True
    assert set(manifest["mcpServers"]) == {"adeo-cti"}
    server = manifest["mcpServers"]["adeo-cti"]
    assert set(server) == {
        "enabled", "candidate_only", "gateway_only", "direct_upstream_connection",
        "transport", "url", "tls_verify", "auth_mode", "credential_ref",
    }
    assert server["enabled"] is False and server["gateway_only"] is True
    assert server["candidate_only"] is True
    assert server["direct_upstream_connection"] is False
    assert server["transport"] == "streamable_http"
    assert server["url"] == "https://gateway.example.invalid/mcp/adeo-cti"
    assert server["tls_verify"] is True and server["auth_mode"] == "bearer"
    assert server["credential_ref"] == [
        "secret" + "://runtime/shodan-api-key",
        "secret" + "://runtime/virustotal-api-key",
    ]
    forbidden_keys = {
        "token", "password", "api_key", "client_secret", "access_token",
        "authorization", "private_key", "secret",
    }

    def reject_raw_credentials(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                assert key == "credential_ref" or key.lower() not in forbidden_keys
                reject_raw_credentials(item)
        elif isinstance(value, list):
            for item in value:
                reject_raw_credentials(item)
        elif isinstance(value, str):
            assert "-----BEGIN" not in value
            assert not value.startswith("Bearer ")

    reject_raw_credentials(manifest)
    integration = (ADEO_INTEGRATION / "INTEGRATION.md").read_text(encoding="utf-8")
    boundary = (ADEO_INTEGRATION / "SECURITY_BOUNDARY.md").read_text(encoding="utf-8")
    url_spec = (ADEO_INTEGRATION / "vt-readonly-url-report.md").read_text(encoding="utf-8")
    for phrase in (
        "license unresolved", "package.json declares MIT", "README states All rights reserved",
        "no LICENSE file", "36 = 8 retained + 28 removed", "14 prompts", "3 resources",
        "must be physically removed", "production blocked", "no additional human approval",
    ):
        assert phrase in integration
    for phrase in (
        "owned_asset_id", "evidence-backed `incident_ioc`", "exact_scope.evidence_id",
        "no active scanning", "no key in argv",
        "no Shodan key in a logged URL", "untrusted data", "exact egress",
    ):
        assert phrase in boundary
    for phrase in (
        "GET /api/v3/urls/{id}", "approved public URL", "remove query and fragment",
        "tokens, signatures, and user identifiers", "not_found", "not_rated",
        "never scan, submit, upload, or reanalyze", "private URL", "signed URL",
    ):
        assert phrase in url_spec


def test_vulnfeed_reviewed_fixture_is_exact_nine_tool_partition() -> None:
    fixture = load_json(VULNFEED_FIXTURE)
    assert set(fixture) == {"schema_version", "source_commit", "tools"}
    assert fixture["schema_version"] == "1.0.0"
    assert fixture["source_commit"] == VULNFEED_COMMIT
    tools = fixture["tools"]
    assert len(tools) == 9
    assert all(set(tool) == {"name", "disposition"} for tool in tools)
    names = [tool["name"] for tool in tools]
    assert len(names) == len(set(names))
    assert set(names) == set(VULNFEED_ALLOWED) | set(VULNFEED_DENIED)
    assert {tool["name"] for tool in tools if tool["disposition"] == "allowed"} == set(VULNFEED_ALLOWED)
    assert {tool["name"] for tool in tools if tool["disposition"] == "denied"} == set(VULNFEED_DENIED)


def test_vulnfeed_upstream_lock_is_pinned_mit_and_blocked() -> None:
    lock = load_yaml(VULNFEED_INTEGRATION / "upstream.lock.yaml")
    assert set(lock) == {
        "schema_version", "server_id", "repository_url", "requested_repository_url",
        "source_ref", "source_commit", "source_archive_sha256", "tool_inventory_fixture",
        "tool_inventory_sha256", "observed_tool_count", "license_status",
        "license_evidence_ref", "dependency_lock_ref", "dependency_lock_sha256",
        "sbom_ref", "sbom_sha256", "image_digest", "reviewed_at", "reviewed_by",
        "production_gate",
    }
    assert lock["schema_version"] == "1.0.0" and lock["server_id"] == "vulnfeed-mcp"
    assert lock["repository_url"] == "https://github.com/novadyne-hq/vulnfeed-mcp"
    assert lock["requested_repository_url"] == "https://github.com/infai-tech/vulnfeed-mcp"
    assert lock["source_ref"] == VULNFEED_COMMIT and lock["source_commit"] == VULNFEED_COMMIT
    assert lock["source_archive_sha256"] == VULNFEED_ARCHIVE_HASH
    assert lock["tool_inventory_fixture"] == "tests/fixtures/mcp/vulnfeed-aa2452d-tools-list.json"
    assert lock["tool_inventory_sha256"] == raw_sha256(VULNFEED_FIXTURE, ROOT)
    assert lock["observed_tool_count"] == 9
    assert lock["license_status"] == "verified_mit"
    assert lock["license_evidence_ref"] == (
        "https://github.com/novadyne-hq/vulnfeed-mcp/blob/"
        + VULNFEED_COMMIT + "/LICENSE"
    )
    for field in (
        "dependency_lock_ref", "dependency_lock_sha256", "sbom_ref", "sbom_sha256", "image_digest",
    ):
        assert lock[field] is None
    reviewed_at = datetime.fromisoformat(str(lock["reviewed_at"]))
    assert reviewed_at.utcoffset() is not None
    assert isinstance(lock["reviewed_by"], str) and lock["reviewed_by"].strip()
    gate = lock["production_gate"]
    assert set(gate) == {"enabled", "status", "blocked_reasons", "required_live_attestations"}
    assert gate["enabled"] is False and gate["status"] == "blocked"
    assert set(gate["blocked_reasons"]) == {
        "complete_dependency_lock_missing", "sbom_missing",
        "controlled_reproducible_build_missing", "reviewed_image_digest_missing",
        "isolated_readonly_wrapper_missing",
        "approved_root_hash_and_symlink_enforcement_missing",
        "show_all_override_enforcement_missing", "backend_override_hardening_missing",
        "vendor_data_review_missing", "payment_x402_disablement_attestation_missing",
        "live_tool_inventory_attestation_missing", "gateway_conformance_attestation_missing",
        "deployment_configuration_missing",
    }
    assert set(gate["required_live_attestations"]) == {
        "live_upstream_tools_list_exact_9", "gateway_client_tools_list_exact_1",
        "eight_denied_tools_call_rejected", "scan_lockfile_show_all_true",
        "approved_lockfile_canonical_path_and_hash_match", "symlink_rejected",
        "wallet_and_x402_absent", "http_402_budget_alert_only",
        "approved_https_backend_exact_egress", "gateway_redaction_and_audit_conformance",
    }


def test_vulnfeed_policy_exposes_only_scan_lockfile_without_extra_approval() -> None:
    policy = load_yaml(VULNFEED_INTEGRATION / "tool_policy.yaml")
    assert set(policy) == {
        "schema_version", "server_id", "enabled", "default_effect", "gateway_only",
        "direct_upstream_connection", "transport", "wrapper_implemented", "query_schema",
        "inventory", "call_policy", "request_contract", "path_boundary", "arguments",
        "mock_path_decision_contract", "data_disclosure", "vendor_data_review", "backend", "payment",
        "vulnerability_semantics", "output_boundary", "approval", "runtime_controls",
        "production_gate",
    }
    assert policy["schema_version"] == "1.0.0" and policy["server_id"] == "vulnfeed-mcp"
    assert policy["enabled"] is False and policy["default_effect"] == "deny"
    assert policy["gateway_only"] is True and policy["direct_upstream_connection"] is False
    assert policy["transport"] == "stdio" and policy["wrapper_implemented"] is False
    assert policy["query_schema"] == "schemas/mcp-query-request.schema.json"
    inventory = policy["inventory"]
    assert set(inventory) == {
        "fixture", "reviewed_upstream_count", "client_tool_count", "exposure_mode",
        "allow_tools", "deny_tools",
    }
    assert inventory["reviewed_upstream_count"] == 9 and inventory["client_tool_count"] == 1
    assert inventory["allow_tools"] == list(VULNFEED_ALLOWED)
    assert set(inventory["deny_tools"]) == set(VULNFEED_DENIED)
    assert len(inventory["deny_tools"]) == len(VULNFEED_DENIED)
    assert inventory["exposure_mode"] == "allowlist_only"
    assert policy["call_policy"] == {
        "denied_tool_effect": "deny_and_audit", "unknown_tool": "deny",
        "unknown_argument": "deny", "unknown_server": "deny",
        "scope_mismatch": "deny", "inventory_drift": "refuse_startup",
    }
    assert policy["approval"] == {
        "class": "policy_authorized_read", "additional_human_approval_required": False,
    }
    assert policy["output_boundary"] == {
        "third_party_results_are_untrusted": True,
        "third_party_results_can_expand_scope": False,
        "fields_are_filtered_and_redacted": True,
    }
    controls = policy["runtime_controls"]
    assert set(controls) == {"exact_egress", "rate_limit", "redaction_required", "audit_required"}
    for name in ("exact_egress", "rate_limit"):
        assert controls[name] == {
            "configured": False, "value": None, "unit": None,
            "required_before_production": True,
        }
    assert controls["redaction_required"] is True and controls["audit_required"] is True
    assert policy["production_gate"] == {"enabled": False, "status": "blocked"}


def test_vulnfeed_request_and_path_contract_are_closed() -> None:
    policy = load_yaml(VULNFEED_INTEGRATION / "tool_policy.yaml")
    request = policy["request_contract"]
    assert request == {
        "schema": "schemas/mcp-query-request.schema.json", "required_query_class": "owned_asset",
        "required_asset_type": "lockfile", "owned_asset_id_required": True,
        "incident_ioc_allowed": False, "registry": "configs/authorized_assets.yaml",
        "required_registry_fields": [
            "asset_id", "owner", "proof", "approval_ref", "expires_at", "immutable_value",
            "expected_raw_sha256",
        ],
        "registry_entry_must_be_unexpired": True,
        "registry_owned_asset_id_exact_match_required": True,
        "registry_asset_type_exact_match_required": True,
        "registry_owner_verification_required": True,
        "registry_proof_verification_required": True,
        "registry_approval_ref_must_resolve_and_be_valid": True,
        "immutable_value_semantics": "approved_source_path",
        "expected_raw_sha256_format": "sha256:<64 lowercase hex>",
    }
    path = policy["path_boundary"]
    assert path == {
        "one_file_per_invocation": True, "copy_to_dedicated_isolated_directory": True,
        "read_only_mount": True, "canonical_path_required": True, "symlinks_allowed": False,
        "all_path_components_must_not_be_symlinks": True, "regular_file_required": True,
        "approved_source_root": {
            "configured": False, "value": None, "unit": None,
            "required_before_production": True,
        },
        "canonical_path_must_be_within_approved_source_root": True,
        "raw_byte_sha256_must_match_registry_before_copy": True,
        "raw_byte_sha256_must_match_registry_after_copy": True,
        "wrapper_injects_only_isolated_copy_path": True,
        "repository_exposed": False, "user_home_exposed": False,
        "secret_paths_exposed": False, "other_lockfiles_exposed": False,
        "wrapper_implemented": False,
    }
    assert policy["arguments"] == {
        "scan_lockfile": {
            "model_allowed": [], "gateway_injected": ["lockfile_path", "show_all"],
            "lockfile_path_source": "registry_resolved_isolated_copy", "show_all": True,
        }
    }


def test_vulnfeed_mocked_path_decisions_fail_closed() -> None:
    policy = load_yaml(VULNFEED_INTEGRATION / "tool_policy.yaml")
    decision = policy["mock_path_decision_contract"]
    required_true = [
        "owned_asset_id_exact_match", "asset_type_is_lockfile", "owner_verified",
        "proof_verified", "approval_ref_valid", "registry_entry_unexpired",
        "canonical_path_within_approved_root", "source_is_not_symlink",
        "path_components_are_not_symlinks", "source_is_regular_file",
        "source_hash_matches_before_copy", "isolated_copy_hash_matches_after_copy",
    ]
    assert decision == {"required_true": required_true, "allow_only_when_all_true": True}

    def mocked_decision(facts: dict[str, bool]) -> str:
        return "allow_isolated_copy" if all(facts.get(name) is True for name in required_true) else "deny"

    valid = {name: True for name in required_true}
    assert mocked_decision(valid) == "allow_isolated_copy"
    for failed_fact in required_true:
        candidate = dict(valid)
        candidate[failed_fact] = False
        assert mocked_decision(candidate) == "deny", failed_fact


def test_vulnfeed_has_no_payment_and_keeps_prediction_distinct() -> None:
    policy = load_yaml(VULNFEED_INTEGRATION / "tool_policy.yaml")
    assert policy["payment"] == {
        "wallet_allowed": False, "x402_allowed": False,
        "payment_proxy_allowed": False, "automatic_payment_allowed": False,
        "http_402_effect": "budget_alert_and_stop", "payment_challenge_forwarded": False,
    }
    assert policy["data_disclosure"] == {
        "leaves_trust_boundary": ["package_name", "exact_version", "ecosystem"],
        "sbom_like_disclosure": True,
        "original_lockfile_leaves_boundary": False, "source_code_leaves_boundary": False,
        "private_package_names_allowed": False, "internal_project_names_allowed": False,
    }
    vendor = policy["vendor_data_review"]
    assert vendor == {
        "configured": False, "value": None, "unit": None, "required_before_production": True,
        "required_topics": [
            "retention", "tenant_isolation", "data_region", "dpa",
            "telemetry_training_use", "private_package_names", "backend_override_variables",
        ],
    }
    backend = policy["backend"]
    assert backend == {
        "configured": False, "value": None, "unit": None, "required_before_production": True,
        "https_required": True, "model_mutation_allowed": False,
        "upstream_override_variables_removed": [
            "VULNFEED_WORKER_URL", "WORKER_URL", "VULNFEED_TRANSPORT",
            "VULNFEED_API_KEY", "WORKER_BOOTSTRAP_KEY",
        ],
    }
    semantics = policy["vulnerability_semantics"]
    assert semantics == {
        "show_all": True,
        "required_fields": [
            "known_exploited", "known_exploited_source",
            "predicted_exploitation_probability", "epss_percentile", "epss_data_date",
        ],
        "known_exploited_sources": ["cisa_kev", "verified_vendor_advisory"],
        "epss_meaning": "probability_of_public_cve_exploitation_in_next_30_days",
        "epss_can_set_known_exploited": False,
    }


def test_vulnfeed_manifest_and_docs_stay_disabled_and_non_runnable() -> None:
    manifest = load_json(VULNFEED_INTEGRATION / "mcp.example.json")
    assert set(manifest) == {
        "schema_version", "configured", "value", "unit", "required_before_production", "mcpServers",
    }
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["configured"] is False and manifest["value"] is None and manifest["unit"] is None
    assert manifest["required_before_production"] is True
    assert set(manifest["mcpServers"]) == {"vulnfeed"}
    server = manifest["mcpServers"]["vulnfeed"]
    assert server == {
        "enabled": False, "gateway_only": True, "direct_upstream_connection": False,
        "transport": "stdio", "launcher": None, "args": [], "isolated_workdir": None,
        "backend_url": None, "backend_https_required": True, "show_all": True,
        "credential_ref": None, "wallet": None, "payment": None,
    }
    integration = (VULNFEED_INTEGRATION / "INTEGRATION.md").read_text(encoding="utf-8")
    boundary = (VULNFEED_INTEGRATION / "SECURITY_BOUNDARY.md").read_text(encoding="utf-8")
    for phrase in (
        "infai-tech/vulnfeed-mcp", "novadyne-hq/vulnfeed-mcp", "9 = 1 allowed + 8 denied",
        "package name, exact version, and ecosystem", "original lockfile and source code do not",
        "no additional human approval", "production blocked",
    ):
        assert phrase in integration
    for phrase in (
        "dedicated read-only directory", "canonical path", "reject symlinks",
        "raw-byte SHA-256", "show_all=true", "HTTP 402", "budget alert",
        "never pay", "future 30 days", "CISA KEV", "verified vendor advisory",
        "private package names", "VULNFEED_WORKER_URL", "WORKER_URL", "VULNFEED_API_KEY", "untrusted",
    ):
        assert phrase in boundary
