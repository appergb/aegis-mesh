from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from uuid import uuid4

import pytest

import scripts.notification_authorization as notification_authorization
import scripts.validation_core as validation_core
from scripts.notification_authorization import (
    AuthorizationDenied,
    InMemoryAuthorizationStore,
    NotificationAuthorizationRegistry,
    NotificationAuthorizationService,
    render_inbound_notice,
)
from scripts.validation_core import (
    compute_notification_idempotency_key,
    compute_scope_hash,
    load_json_strict,
    load_yaml_strict,
    raw_bytes_sha256,
    validate_notification_transition,
)


ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "skills/abuse-notification-agent"
SKILL = AGENT / "SKILL.md"
PROMPT = AGENT / "system_prompt.md"
LEGAL = AGENT / "references/prc-legal-basis.md"
LEGAL_TEMPLATE = AGENT / "references/legal-review-template.md"
ASSETS = {
    "abuse": AGENT / "assets/abuse-notice.zh-CN.md",
    "provider": AGENT / "assets/provider-abuse-report.zh-CN.md",
    "inbound": AGENT / "assets/inbound-403-notice.html",
}

IDENTITY_LINES = (
    "你的模型身份名称是 Aegis-Mesh-General。",
    "你运行在 Aegis Mesh 系统中。",
)
INCIDENT_ID = "123e4567-e89b-42d3-a456-426614174000"
NOTICE_ID = "123e4567-e89b-42d3-a456-426614174001"
APPROVAL_ONE_ID = "123e4567-e89b-42d3-a456-426614174002"
APPROVAL_TWO_ID = "123e4567-e89b-42d3-a456-426614174003"
AUTHORIZATION_ID = "123e4567-e89b-42d3-a456-426614174004"
EVIDENCE_ID = "123e4567-e89b-42d3-a456-426614174005"
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
BODY = "经批准的最终通知正文。\n".encode()


class _ConfiguredSyntheticRegistry:
    configured = True

    def validate_authorization(
        self, request: dict, *, executor_ref: str, now: datetime
    ) -> tuple:
        return ()


class _MutatingSyntheticRegistry:
    configured = True

    def validate_authorization(
        self, request: dict, *, executor_ref: str, now: datetime
    ) -> tuple:
        request["recipient_ref"] = "mutated-contact"
        request["approval"]["human_approvals"][0]["approval_id"] = AUTHORIZATION_ID
        return ()


class _RaisingConfiguredRegistry:
    @property
    def configured(self) -> bool:
        raise RuntimeError("registry unavailable")

    def validate_authorization(
        self, request: dict, *, executor_ref: str, now: datetime
    ) -> tuple:
        raise AssertionError("must not be called")


def authorization_service(
    store: InMemoryAuthorizationStore,
    *,
    registry: NotificationAuthorizationRegistry | None = None,
    clock=lambda: NOW,
    authorization_id_factory=uuid4,
) -> NotificationAuthorizationService:
    return NotificationAuthorizationService(
        root=ROOT,
        store=store,
        registry=registry,
        clock=clock,
        authorization_id_factory=authorization_id_factory,
    )


def approved_notification() -> dict:
    body_hash = raw_bytes_sha256(BODY)
    bound_scope = {
        "purpose": "notification",
        "schema_version": "1.0.0",
        "incident_id": INCIDENT_ID,
        "action_category": "external_notification",
        "action_type": "send_abuse_notification",
        "target": {"resource_type": "notification_recipient", "resource_id": "official-abuse-contact-01"},
        "exact_scope": {
            "notice_id": NOTICE_ID,
            "recipient_ref": "official-abuse-contact-01",
            "template_version": "1.0.0",
            "body_hash": body_hash,
        },
        "environment": "test",
        "expires_at": "2030-01-01T01:00:00Z",
        "recipient_ref": "official-abuse-contact-01",
        "template_version": "1.0.0",
        "body_hash": body_hash,
    }
    scope_hash = compute_scope_hash(bound_scope)
    request = {
        "schema_version": "1.0.0",
        "notification_id": NOTICE_ID,
        "incident_id": INCIDENT_ID,
        "created_at": "2026-12-31T23:00:00Z",
        "expires_at": bound_scope["expires_at"],
        "notification_status": "approved",
        "action_category": bound_scope["action_category"],
        "action_type": bound_scope["action_type"],
        "target": bound_scope["target"],
        "exact_scope": bound_scope["exact_scope"],
        "environment": bound_scope["environment"],
        "recipient_ref": bound_scope["recipient_ref"],
        "template_version": bound_scope["template_version"],
        "body_hash": body_hash,
        "redacted_facts": ["Bounded and redacted incident fact."],
        "evidence": [{
            "evidence_id": EVIDENCE_ID,
            "incident_id": INCIDENT_ID,
            "storage_ref": "evidence://store/object/version-1",
            "content_hash": "sha256:" + "a" * 64,
            "collected_at": "2026-12-31T22:59:00Z",
            "storage_version": "version-1",
        }],
        "scope_hash": scope_hash,
        "approval_class": "two_person_irreversible",
        "approval": {
            "approval_class": "two_person_irreversible",
            "human_approvals": [
                {
                    "approval_id": APPROVAL_ONE_ID,
                    "approver_id": "human-incident-commander",
                    "approver_role": "incident_commander",
                    "approved_at": "2026-12-31T23:30:00Z",
                    "scope_hash": scope_hash,
                    "expires_at": "2030-01-01T00:30:00Z",
                },
                {
                    "approval_id": APPROVAL_TWO_ID,
                    "approver_id": "human-legal-reviewer",
                    "approver_role": "legal_compliance_approver",
                    "approved_at": "2026-12-31T23:31:00Z",
                    "scope_hash": scope_hash,
                    "expires_at": "2030-01-01T00:30:00Z",
                },
            ],
        },
        "reversible": False,
        "irreversibility_reason": "A recipient may retain delivered content.",
        "compensating_actions": ["Separately approve a corrective notification."],
        "stop_conditions": ["Stop if any approval or legal review expires."],
    }
    request["idempotency_key"] = compute_notification_idempotency_key(request)
    return request


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def section(text: str, heading: str) -> str:
    return text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]


def test_notification_agent_files_metadata_identity_and_permission() -> None:
    assert all(path.is_file() and not path.is_symlink() for path in (SKILL, PROMPT, LEGAL, *ASSETS.values()))
    skill = read(SKILL)
    frontmatter, body = skill[4:].split("\n---\n", 1)
    assert skill.startswith("---\n")
    assert "name: abuse-notification-agent" in frontmatter
    assert "description:" in frontmatter and "Use for " in frontmatter

    permissions = load_yaml_strict(ROOT / "configs/agent_permissions.yaml", ROOT)
    assert isinstance(permissions, dict)
    permission = next(item for item in permissions["agents"] if item["agent_id"] == "abuse-notification-agent")
    assert permission["maximum_permission"] == "execute_high_impact"
    assert "最大权限是 `execute_high_impact`" in body + read(PROMPT)
    for denial in permission["explicit_denials"]:
        assert f"`{denial}`" in body
    for line in IDENTITY_LINES:
        assert read(PROMPT).count(line) == 1


def test_notification_actions_exactly_project_schema_and_approval_registry() -> None:
    skill = read(SKILL)
    schema = load_json_strict(ROOT / "schemas/notification-request.schema.json", ROOT)
    approvals = load_yaml_strict(ROOT / "configs/approval_matrix.yaml", ROOT)
    assert isinstance(schema, dict) and isinstance(approvals, dict)
    expected_actions = schema["properties"]["action_type"]["enum"]
    registered = {
        item["action_type"]: item
        for item in approvals["action_approvals"]
        if item["action_type"] in expected_actions
    }
    lines = [line for line in section(skill, "Registered notification actions").splitlines() if line.startswith("|")]
    assert lines[:2] == [
        "| action | exact_scope fields | approval class | ordered roles | reversible |",
        "|---|---|---|---|---|",
    ]
    assert len(lines) == len(expected_actions) + 2
    observed = []
    for line in lines[2:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        action = cells[0].strip("`")
        observed.append(action)
        expected_fields = ["notice_id", "recipient_ref", "template_version", "body_hash"]
        if action == "send_corrective_notification":
            expected_fields.insert(1, "original_notice_id")
        assert [value.strip("`") for value in cells[1].split(", ")] == expected_fields
        assert cells[2].strip("`") == registered[action]["approval_class"] == "two_person_irreversible"
        assert [value.strip("`") for value in cells[3].split(" + ")] == registered[action]["approver_roles"]
        assert cells[4] == "false"
    assert observed == expected_actions


def test_notification_workflow_is_double_approved_idempotent_and_auditable() -> None:
    skill = read(SKILL)
    workflow = section(skill, "Authorization state machine")
    assert "draft -> awaiting_approval -> approved -> send_authorized -> executor attempt" in workflow
    for phrase in (
        "formal `incident_id`", "at least `likely-malicious`", "direct accused-party contact requires `confirmed-malicious`",
        "exactly two", "distinct `approver_id`", "`incident_commander` + `legal_compliance_approver`",
        "same `scope_hash`", "non-expired", "recipient and frozen final body",
        "exactly one `send_authorized` record per `idempotency_key`",
        "retry returns the existing authorization and cannot authorize or send a second copy",
        "`notification_authorized`", "never a new audit enum",
        "authorization_id", "recipient_ref", "body_hash", "idempotency_key", "executor_ref",
        "executor event ID", "attempted_at", "result", "appeal channel remains in the frozen hashed body",
    ):
        assert phrase in workflow
    assert "before approvals the output is draft-only" in workflow
    assert "warning is optional" in workflow
    assert "never delays containment, blocking harmful traffic, evidence preservation, or service recovery" in workflow


def test_notification_state_graph_is_executable_and_closed() -> None:
    statuses = ("draft", "awaiting_approval", "approved", "sent", "failed", "revoked")
    expected = {
        ("draft", "awaiting_approval"), ("draft", "revoked"),
        ("awaiting_approval", "approved"), ("awaiting_approval", "revoked"),
        ("approved", "sent"), ("approved", "failed"), ("approved", "revoked"),
    }
    observed = {
        (current, desired)
        for current in statuses
        for desired in statuses
        if validate_notification_transition(current, desired)
    }
    assert observed == expected


def test_notification_authorization_claim_is_atomic_and_idempotent() -> None:
    request = approved_notification()
    store = InMemoryAuthorizationStore(clock=lambda: NOW)
    default_service = authorization_service(store)

    with pytest.raises(AuthorizationDenied) as blocked:
        default_service.claim(
            request,
            body=BODY,
            executor_ref="deployment-mail-executor-01",
        )
    assert {issue.code for issue in blocked.value.issues} == {"authorization.registry_unavailable"}
    assert store.records() == ()

    generated_ids = iter((AUTHORIZATION_ID, "123e4567-e89b-42d3-a456-426614174099"))
    configured_service = authorization_service(
        store,
        registry=_ConfiguredSyntheticRegistry(),
        authorization_id_factory=lambda: next(generated_ids),
    )
    first = configured_service.claim(
        request,
        body=BODY,
        executor_ref="deployment-mail-executor-01",
    )
    retry = configured_service.claim(
        request,
        body=BODY,
        executor_ref="deployment-mail-executor-01",
    )
    assert first.created is True and retry.created is False
    assert first.record == retry.record
    assert first.record == {
        "record_type": "send_authorized",
        "authorization_id": AUTHORIZATION_ID,
        "notification_id": NOTICE_ID,
        "incident_id": INCIDENT_ID,
        "recipient_ref": "official-abuse-contact-01",
        "template_version": "1.0.0",
        "body_hash": raw_bytes_sha256(BODY),
        "scope_hash": request["scope_hash"],
        "idempotency_key": request["idempotency_key"],
        "approval_refs": [APPROVAL_ONE_ID, APPROVAL_TWO_ID],
        "executor_ref": "deployment-mail-executor-01",
        "authorized_at": "2030-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:30:00Z",
        "request_expires_at": "2030-01-01T01:00:00Z",
        "audit_event": "notification_authorized",
    }
    assert len(store.records()) == 1

    first.record["approval_refs"][0] = "caller-mutated"
    records_copy = store.records()
    records_copy[0]["approval_refs"][1] = "records-copy-mutated"
    assert store.records()[0]["approval_refs"] == [APPROVAL_ONE_ID, APPROVAL_TWO_ID]

    protocol = load_yaml_strict(ROOT / "configs/agent_protocol.yaml", ROOT)
    assert isinstance(protocol, dict)
    assert first.record["audit_event"] in protocol["registries"]["audit_event"]
    assert "send_authorized" not in protocol["registries"]["audit_event"]


def test_notification_authorization_registry_cannot_mutate_frozen_request() -> None:
    request = approved_notification()
    store = InMemoryAuthorizationStore(clock=lambda: NOW)
    claim = authorization_service(
        store,
        registry=_MutatingSyntheticRegistry(),
        authorization_id_factory=lambda: AUTHORIZATION_ID,
    ).claim(
        request,
        body=BODY,
        executor_ref="deployment-mail-executor-01",
    )
    assert request["recipient_ref"] == "official-abuse-contact-01"
    assert request["approval"]["human_approvals"][0]["approval_id"] == APPROVAL_ONE_ID
    assert claim.record["recipient_ref"] == "official-abuse-contact-01"
    assert claim.record["approval_refs"] == [APPROVAL_ONE_ID, APPROVAL_TWO_ID]


def test_notification_authorization_registry_errors_fail_closed() -> None:
    store = InMemoryAuthorizationStore(clock=lambda: NOW)
    with pytest.raises(AuthorizationDenied) as denied:
        authorization_service(
            store,
            registry=_RaisingConfiguredRegistry(),
            authorization_id_factory=lambda: AUTHORIZATION_ID,
        ).claim(
            approved_notification(),
            body=BODY,
            executor_ref="deployment-mail-executor-01",
        )
    assert {issue.code for issue in denied.value.issues} >= {
        "authorization.registry_error",
        "authorization.registry_unavailable",
    }
    assert store.records() == ()


def test_notification_authorization_store_rechecks_earliest_expiry() -> None:
    after_approval_expiry = datetime(2030, 1, 1, 0, 30, tzinfo=timezone.utc)
    store = InMemoryAuthorizationStore(clock=lambda: after_approval_expiry)
    with pytest.raises(AuthorizationDenied) as denied:
        authorization_service(
            store,
            registry=_ConfiguredSyntheticRegistry(),
            authorization_id_factory=lambda: AUTHORIZATION_ID,
        ).claim(
            approved_notification(),
            body=BODY,
            executor_ref="deployment-mail-executor-01",
        )
    assert {issue.code for issue in denied.value.issues} == {
        "authorization.expired_before_persist"
    }
    assert store.records() == ()


def test_notification_authorization_concurrent_claims_create_once() -> None:
    store = InMemoryAuthorizationStore(clock=lambda: NOW)
    service = authorization_service(store, registry=_ConfiguredSyntheticRegistry())
    request = approved_notification()

    def claim_once() -> object:
        return service.claim(
            request,
            body=BODY,
            executor_ref="deployment-mail-executor-01",
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        claims = list(executor.map(lambda _: claim_once(), range(32)))
    assert sum(claim.created for claim in claims) == 1
    assert len({claim.record["authorization_id"] for claim in claims}) == 1
    assert len(store.records()) == 1

    conflicting = store.records()[0]
    conflicting["recipient_ref"] = "different-official-contact"
    with pytest.raises(ValueError, match="different authorization"):
        store.create_or_return(conflicting)

    duplicate_authorization_id = store.records()[0]
    duplicate_authorization_id["idempotency_key"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError, match="authorization_id already binds"):
        store.create_or_return(duplicate_authorization_id)


def test_notification_authorization_uuid_is_canonicalized() -> None:
    store = InMemoryAuthorizationStore(clock=lambda: NOW)
    claim = authorization_service(
        store,
        registry=_ConfiguredSyntheticRegistry(),
        authorization_id_factory=lambda: "{" + AUTHORIZATION_ID.upper() + "}",
    ).claim(
        approved_notification(),
        body=BODY,
        executor_ref="deployment-mail-executor-01",
    )
    assert claim.record["authorization_id"] == AUTHORIZATION_ID


@pytest.mark.parametrize(
    ("mutation", "body", "expected_code"),
    (
        ("duplicate_approver", BODY, "approval.approver_not_distinct"),
        ("expired_approval", BODY, "approval.expired"),
        ("approval_scope", BODY, "approval.scope_hash_mismatch"),
        ("recipient", BODY, "notification.idempotency_mismatch"),
        ("body_bytes", BODY + b"changed", "notification.body_hash_mismatch"),
    ),
)
def test_notification_authorization_rejects_tampering(
    mutation: str, body: bytes, expected_code: str
) -> None:
    request = approved_notification()
    approvals = request["approval"]["human_approvals"]
    if mutation == "duplicate_approver":
        approvals[1]["approver_id"] = approvals[0]["approver_id"]
    elif mutation == "expired_approval":
        approvals[1]["expires_at"] = "2030-01-01T00:00:00Z"
    elif mutation == "approval_scope":
        approvals[1]["scope_hash"] = "sha256:" + "b" * 64
    elif mutation == "recipient":
        request["recipient_ref"] = "different-official-contact"

    with pytest.raises(AuthorizationDenied) as denied:
        store = InMemoryAuthorizationStore(clock=lambda: NOW)
        authorization_service(
            store,
            registry=_ConfiguredSyntheticRegistry(),
            authorization_id_factory=lambda: AUTHORIZATION_ID,
        ).claim(
            request,
            body=body,
            executor_ref="deployment-mail-executor-01",
        )
    assert expected_code in {issue.code for issue in denied.value.issues}


def test_notification_current_configuration_is_fail_closed() -> None:
    skill = read(SKILL)
    policy = load_yaml_strict(ROOT / "configs/notification_policy.yaml", ROOT)
    runtime = load_yaml_strict(ROOT / "configs/runtime.example.yaml", ROOT)
    assert isinstance(policy, dict) and isinstance(runtime, dict)
    assert policy["enabled"] is False
    assert policy["recipients"] == policy["channels"] == policy["templates"] == []
    assert policy["frequency"] == {
        "configured": False,
        "value": None,
        "unit": None,
        "required_before_production": True,
    }
    assert runtime["configured"] is False and runtime["production_gate"]["configured"] is False
    for phrase in (
        "`enabled: false`", "recipients, channels, and templates are empty", "frequency is unconfigured",
        "runtime production gate is unconfigured", "authorization registry is unavailable",
        "unsent blocked draft only", "cannot create a current `send_authorized` record",
        "no SMTP/API credentials", "deployment-provided executor",
    ):
        assert phrase in skill


def test_notification_recipient_verification_and_refusals_are_locked() -> None:
    combined = read(SKILL) + read(PROMPT)
    for phrase in (
        "contracted security contact", "RIR/RDAP", "official Abuse/CERT channel",
        "security.txt", "registrar/registry or national CERT", "human selection",
        "guessed or personal email", "automatic sending", "impersonation", "threats",
        "payment demands", "reverse connection", "active scan", "hack-back",
        "definitive criminal conclusion", "minimum disclosure", "no attachments",
    ):
        assert phrase in combined
    for phrase in ("may guess an email", "automatic sending is allowed", "may connect back", "is a criminal"):
        assert phrase not in combined


def test_notification_consumes_only_base_evidence_reference() -> None:
    skill = read(SKILL)
    incident_schema = load_json_strict(ROOT / "schemas/incident-event.schema.json", ROOT)
    notification_schema = load_json_strict(ROOT / "schemas/notification-request.schema.json", ROOT)
    assert isinstance(incident_schema, dict) and isinstance(notification_schema, dict)
    evidence = incident_schema["$defs"]["evidenceReference"]
    assert evidence["required"] == [
        "evidence_id", "incident_id", "storage_ref", "content_hash", "collected_at", "storage_version"
    ]
    assert notification_schema["properties"]["evidence"]["items"]["$ref"].endswith("#/$defs/evidenceReference")
    evidence_section = section(skill, "Evidence and disclosure")
    for field in evidence["required"]:
        assert f"`{field}`" in evidence_section
    assert "base evidence reference only" in evidence_section
    assert "does not assume a forensic custody Schema" in evidence_section


def test_notification_templates_are_complete_conditional_and_minimized() -> None:
    required_placeholders = {
        "incident_id", "notice_id", "window_start", "window_end", "timezone", "affected_service",
        "redacted_request_pattern", "redacted_evidence_summary", "appeal_security_channel", "template_version",
    }
    for key in ("abuse", "provider"):
        text = read(ASSETS[key])
        assert required_placeholders <= set(re.findall(r"\{\{([a-z_]+)\}\}", text))
        for phrase in (
            "请停止相关流量并保全日志", "相关行为可能违反", "可能涉及",
            "具体法律性质、是否违法、是否达到法定标准及责任均由有权机关依法认定",
            "Aegis-Mesh-General", "正文哈希见 send_authorized 授权记录",
        ):
            assert phrase in text
        for forbidden in ("已构成犯罪", "必须付款", "我们是公安", "{{body_hash}}", "{{sent_at}}", "{{approver_id}}"):
            assert forbidden not in text
        assert "附件" not in text


def test_body_hash_and_post_approval_audit_have_no_self_reference() -> None:
    skill = read(SKILL)
    hashing = section(skill, "Body hash closure")
    for phrase in (
        "raw bytes of the final rendered body", "`sha256:<64 lowercase hex>`",
        "body never embeds its own `body_hash`", "placeholder digest is forbidden",
        "approval identities, `authorized_at`, actual send time, and executor result live only in the authorization/audit envelope",
        "changing the frozen body invalidates `body_hash`, `scope_hash`, approvals, and idempotency",
        "A correction is a separately approved irreversible notification, not rollback",
    ):
        assert phrase in hashing


def test_inbound_response_is_same_session_only_and_non_disclosing() -> None:
    html = read(ASSETS["inbound"])
    assert html.lstrip().lower().startswith("<!doctype html>")
    for phrase in ("403 Forbidden", "429 Too Many Requests", "WAF Challenge", "{{incident_id}}", "{{security_channel}}"):
        assert phrase in html
    assert "same inbound session only" in html
    for forbidden in ("detection rule", "internal topology", "reverse connection", "fetch(", "XMLHttpRequest", "<script"):
        assert forbidden not in html


def test_inbound_renderer_escapes_untrusted_text_context() -> None:
    hostile_channel = '<img src=x onerror="alert(1)">&\"\''
    rendered = render_inbound_notice(
        incident_id=INCIDENT_ID,
        security_channel=hostile_channel,
    )
    assert hostile_channel not in rendered
    assert "<img" not in rendered and "onerror=\"" not in rendered
    for escaped in ("&lt;img", "&gt;", "&amp;", "&quot;", "&#x27;"):
        assert escaped in rendered
    assert "{{" not in rendered and "}}" not in rendered
    with pytest.raises(TypeError):
        render_inbound_notice(
            template="<script>alert(1)</script>{{incident_id}}{{security_channel}}",
            incident_id=INCIDENT_ID,
            security_channel="security-channel-01",
        )


def test_inbound_renderer_rejects_template_byte_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        notification_authorization,
        "_INBOUND_TEMPLATE_HASH",
        "sha256:" + "0" * 64,
    )
    with pytest.raises(ValueError, match="trusted package bytes"):
        render_inbound_notice(
            incident_id=INCIDENT_ID,
            security_channel="security-channel-01",
        )


def test_prc_legal_reference_uses_fixed_official_sources_and_review_gate() -> None:
    legal = read(LEGAL)
    assert "reviewed_at: 2026-07-29" in legal
    urls = set(re.findall(r"https://[^\s)>]+", legal))
    assert urls == {
        "https://www.cac.gov.cn/2025-12/29/c_1768735112911946.htm",
        "https://www.npc.gov.cn/npc/c1773/c1848/c21114/wlaqfxz/wlaqfxz002/202511/t20251103_449242.html",
        "https://www.npc.gov.cn/npc/c2/c30834/202506/t20250627_446254.html",
        "https://www.court.gov.cn/fabu/xiangqing/3085.html",
        "https://www.court.gov.cn/fabu/xiangqing/283891.html",
    }
    for phrase in (
        "网络安全法第二十九条", "刑法第二百八十五条第一款", "普通业务系统不得默认套用第一款",
        "刑法第二百八十五条第二款", "刑法第二百八十六条", "治安管理处罚法第三十三条",
        "法释〔2011〕19号", "指导案例145号", "未造成系统功能实质性破坏或者不能正常运行",
        "Only competent authorities", "每次真实发送前", "重新复核", "legal/compliance reviewer",
        "不得作确定违法、情节严重、罪名或责任结论",
    ):
        assert phrase in legal


def test_notification_package_contains_no_embedded_transport_credentials() -> None:
    combined = "\n".join(read(path) for path in (SKILL, PROMPT, LEGAL, *ASSETS.values()))
    for pattern in (
        r"smtp://", r"smtps://", r"(?i)api[_-]?key\s*[:=]", r"(?i)client[_-]?secret\s*[:=]",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    ):
        assert re.search(pattern, combined) is None


FORENSIC_ROOT = ROOT / "forensics"
FORENSIC_SCHEMAS = {
    "source-fingerprint": FORENSIC_ROOT / "schemas/source-fingerprint.schema.json",
    "evidence-event": FORENSIC_ROOT / "schemas/evidence-event.schema.json",
    "chain-of-custody": FORENSIC_ROOT / "schemas/chain-of-custody.schema.json",
}
FORENSIC_EXAMPLES = {
    "source-fingerprint": FORENSIC_ROOT / "templates/source-fingerprint.example.yaml",
    "chain-of-custody": FORENSIC_ROOT / "templates/evidence-manifest.example.yaml",
}


def forensic_policy() -> dict:
    value = load_yaml_strict(ROOT / "configs/forensics_policy.yaml", ROOT)
    assert isinstance(value, dict)
    return value


def forensic_example(name: str) -> dict:
    value = load_yaml_strict(FORENSIC_EXAMPLES[name], ROOT)
    assert isinstance(value, dict)
    return value


def forensic_schema_errors(name: str, instance: dict) -> list:
    return validation_core.validate_forensic_schema_instance(name, instance, ROOT)


def custody_event_hash(event: dict) -> str:
    return validation_core.compute_custody_event_hash(event)


def source_fingerprint_hash(fingerprint: dict) -> str:
    return validation_core.compute_source_fingerprint_hash(fingerprint)


def test_forensic_inventory_is_closed_and_records_are_never_committed() -> None:
    expected = {
        FORENSIC_ROOT / "FORENSICS_POLICY.md",
        *FORENSIC_SCHEMAS.values(),
        *FORENSIC_EXAMPLES.values(),
        FORENSIC_ROOT / "records/.gitignore",
    }
    observed = {path for path in FORENSIC_ROOT.rglob("*") if path.is_file()}
    assert observed == expected
    assert read(FORENSIC_ROOT / "records/.gitignore") == "*\n!.gitignore\n"


def test_forensic_schemas_are_strict_offline_and_reuse_base_evidence_reference() -> None:
    base_evidence_ref = "urn:aegis-mesh:schema:incident-event:1.0.0#/$defs/evidenceReference"
    for name, path in FORENSIC_SCHEMAS.items():
        document = load_json_strict(path, ROOT)
        assert isinstance(document, dict)
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert document["$id"] == f"urn:aegis-mesh:schema:forensics:{name}:1.0.0"
        assert document["type"] == "object" and document["additionalProperties"] is False
        serialized = json.dumps(document)
        assert "http://" not in serialized
        assert "https://" not in serialized.replace(document["$schema"], "")
    source_schema = load_json_strict(FORENSIC_SCHEMAS["source-fingerprint"], ROOT)
    chain_schema = load_json_strict(FORENSIC_SCHEMAS["chain-of-custody"], ROOT)
    assert base_evidence_ref in json.dumps(source_schema)
    assert base_evidence_ref in json.dumps(chain_schema)


def test_source_fingerprint_example_has_complete_schema_and_semantic_binding() -> None:
    required = {
        "fingerprint_id", "incident_id", "first_seen", "last_seen", "classification",
        "confidence", "supporting_evidence", "contradicting_evidence", "source_ip",
        "source_ip_basis", "source_port", "asn", "network_prefix", "network_org",
        "coarse_region", "hosting_vpn_proxy_tor_signals", "reverse_dns", "protocol",
        "tls_version", "cipher_suite", "ja3_ja4", "transport_fingerprint",
        "pseudonymized_user_agent", "request_family", "rates", "status_codes",
        "challenge_result", "cdn_waf_trace_ids", "pseudonymized_account_session_device",
        "raw_evidence_ref", "content_hash", "collected_by", "collected_at",
    }
    schema = load_json_strict(FORENSIC_SCHEMAS["source-fingerprint"], ROOT)
    assert required <= set(schema["required"])
    item = forensic_example("source-fingerprint")
    assert forensic_schema_errors("source-fingerprint", item) == []
    assert validation_core.validate_source_fingerprint(item, forensic_policy()) == []
    assert item["source_ip"] == "198.51.100.24"
    assert item["raw_evidence_ref"]["content_hash"] == item["content_hash"]
    assert item["raw_evidence_ref"]["incident_id"] == item["incident_id"]
    assert item["fingerprint_version"] == 1 and item["supersedes_fingerprint_hash"] is None
    assert item["fingerprint_hash"] == source_fingerprint_hash(item)
    assert datetime.fromisoformat(item["first_seen"].replace("Z", "+00:00")) <= datetime.fromisoformat(
        item["last_seen"].replace("Z", "+00:00")
    )


def test_source_fingerprint_schema_rejects_raw_identity_and_unknown_fields() -> None:
    item = forensic_example("source-fingerprint")
    for field in ("password", "authorization_header", "full_cookie", "plaintext_token", "person_name"):
        invalid = deepcopy(item)
        invalid[field] = "must-not-be-accepted"
        assert forensic_schema_errors("source-fingerprint", invalid)

    sensitive_values = (
        "Authori" + "zation: ApiKey synthetic-value",
        "Authori" + "zation: AWS4-HMAC-SHA256 Credential=synthetic",
        "api_" + "token=synthetic-value",
        "id_" + "token=synthetic-value",
        "to" + "ken: synthetic-value",
    )
    for sensitive_value in sensitive_values:
        sensitive_sample = deepcopy(item)
        sensitive_sample["network_org"] = sensitive_value
        sensitive_sample["fingerprint_hash"] = source_fingerprint_hash(sensitive_sample)
        codes = {issue.code for issue in validation_core.validate_source_fingerprint(sensitive_sample, forensic_policy())}
        assert "forensics.sensitive_value" in codes


def test_source_fingerprint_semantics_reject_tampering_and_proxy_misbinding() -> None:
    item = forensic_example("source-fingerprint")
    invalid = deepcopy(item)
    invalid["content_hash"] = "sha256:" + "b" * 64
    invalid["network_prefix"] = "203.0.113.0/24"
    invalid["source_ip_basis"] = {
        "method": "trusted_proxy_chain",
        "trusted_proxy_ref": None,
        "forwarded_chain_hops": 0,
    }
    codes = {issue.code for issue in validation_core.validate_source_fingerprint(invalid, forensic_policy())}
    assert {
        "forensics.content_hash_binding", "forensics.fingerprint_hash",
        "forensics.network_prefix_binding", "forensics.proxy_basis",
    } <= codes


def test_custody_example_is_append_only_hash_linked_and_default_blocked() -> None:
    manifest = forensic_example("chain-of-custody")
    assert forensic_schema_errors("chain-of-custody", manifest) == []
    assert validation_core.validate_chain_of_custody(manifest, forensic_policy()) == []
    assert manifest["append_only"] is True
    storage = manifest["storage_contract"]
    assert storage["configured"] is False
    assert storage["provider"] is None and storage["immutable_store_ref"] is None
    assert storage["production_gate"] is False
    previous = None
    for event in manifest["events"]:
        assert event["previous_event_hash"] == previous
        assert event["event_hash"] == custody_event_hash(event)
        previous = event["event_hash"]
    assert manifest["chain_head_hash"] == previous


def test_custody_schema_has_exact_actions_and_one_approval_reference() -> None:
    schema = load_json_strict(FORENSIC_SCHEMAS["evidence-event"], ROOT)
    assert schema["properties"]["action"]["enum"] == ["collection", "transform", "access", "export", "delete"]
    for field in (
        "actor", "timestamp", "action", "reason", "approval_reference", "input_hash",
        "output_hash", "storage_version", "transformation_note",
    ):
        assert field in schema["required"]


def test_custody_semantics_reject_tampering_hold_delete_and_production_claim() -> None:
    manifest = forensic_example("chain-of-custody")
    invalid = deepcopy(manifest)
    invalid["events"][1]["previous_event_hash"] = "sha256:" + "f" * 64
    invalid["events"][2]["action"] = "delete"
    invalid["events"][2]["approval_reference"] = "approval://synthetic/two-person-01"
    invalid["legal_hold"]["state"] = "enabled"
    invalid["storage_contract"]["production_gate"] = True
    invalid["storage_contract"]["provider"] = "contradictory-provider"
    invalid["events"][1]["input_hash"] = "sha256:" + "e" * 64
    codes = {issue.code for issue in validation_core.validate_chain_of_custody(invalid, forensic_policy())}
    assert {
        "forensics.previous_hash", "forensics.event_hash", "forensics.legal_hold",
        "forensics.production_gate",
        "forensics.storage_unconfigured", "forensics.content_continuity",
    } <= codes
    assert forensic_schema_errors("chain-of-custody", invalid)

    collection_mismatch = deepcopy(manifest)
    collection_mismatch["events"][0]["storage_ref"] = "evidence://synthetic-store/other/version-9"
    collection_mismatch["events"][0]["storage_version"] = "version-9"
    collection_mismatch["events"][0]["timestamp"] = "2026-12-31T22:59:00Z"
    collection_mismatch["events"][0]["output_hash"] = "sha256:" + "c" * 64
    assert "forensics.collection_binding" in {
        issue.code for issue in validation_core.validate_chain_of_custody(collection_mismatch, forensic_policy())
    }

    missing_authorization = deepcopy(manifest)
    missing_authorization["events"][2]["action"] = "export"
    assert "forensics.approval_reference" in {
        issue.code for issue in validation_core.validate_chain_of_custody(missing_authorization, forensic_policy())
    }

    authorized_export = deepcopy(manifest)
    export_event = authorized_export["events"][2]
    export_event["action"] = "export"
    export_event["approval_reference"] = "approval://synthetic/two-person-01"
    export_event["transformation_note"] = "No transformation; synthetic authorized export record."
    export_event["event_hash"] = custody_event_hash(export_event)
    authorized_export["chain_head_hash"] = export_event["event_hash"]
    assert forensic_schema_errors("chain-of-custody", authorized_export) == []
    assert validation_core.validate_chain_of_custody(authorized_export, forensic_policy()) == []


def test_forensic_policy_locks_identity_scope_ownership_and_corrections() -> None:
    policy = read(FORENSIC_ROOT / "FORENSICS_POLICY.md")
    config = forensic_policy()
    assert config["classification_transitions"] == {
        "observed": ["suspicious", "false-positive", "closed"],
        "suspicious": ["likely-malicious", "false-positive", "closed"],
        "likely-malicious": ["confirmed-malicious", "false-positive", "closed"],
        "confirmed-malicious": ["false-positive", "closed"],
        "false-positive": ["closed"],
        "closed": [],
    }
    assert config["retention"]["configured"] is False
    assert config["rbac"] == {"default_effect": "deny", "grants": []}
    assert config["pseudonymization"] == {"enabled": True, "direct_identity_inference_allowed": False}
    assert config["export"]["approval_class"] == "two_person_irreversible"
    assert config["delete"]["approval_class"] == "two_person_irreversible"
    for phrase in (
        "single IP, ASN, region, TLS, JA3, JA4, or transport fingerprint cannot establish a person's identity",
        "passive telemetry already collected from owned or explicitly authorized assets only",
        "No active intrusion, hack-back, counterattack, scanning of non-owned assets, or personal identity inference",
        "Observability Agent and registered collectors append raw evidence-reference metadata",
        "Threat Intelligence Agent appends versioned derived source fingerprints",
        "Incident Response Agent appends custody and lifecycle events",
        "Corrections create a new version linked to the superseded hash; no record is overwritten",
        "Legal Hold blocks ordinary deletion",
        "export remains denied until two-person irreversible approval",
        "delete remains denied until two-person irreversible approval and provider verification",
        "Git is not an evidence store",
    ):
        assert phrase in policy
    combined = policy + "\n" + "\n".join(read(path) for path in FORENSIC_EXAMPLES.values())
    for forbidden in (
        "Authorization: Bearer", "Cookie:", "password:", "plaintext_token",
    ):
        assert forbidden not in combined


def test_notification_scenarios_keep_evidence_recipient_and_compensation_boundaries() -> None:
    document = load_yaml_strict(ROOT / "scenarios/verified-abuse-notice.yaml", ROOT)
    cases = {case["scenario_id"]: case for case in document["cases"]}
    assert set(cases) == {f"SCN-{index:02d}" for index in range(6, 12)}
    corpus = "\n".join(str(case) for case in cases.values()).lower()
    for phrase in (
        "untrusted evidence", "source fingerprint", "nat", "cloud-provider abuse",
        "scope hash", "idempotent", "rir", "personal email", "recipient-verification",
    ):
        assert phrase in corpus
    assert "no extra approval role" in corpus
