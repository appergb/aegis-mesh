"""Fail-closed, transport-free authorization claim contract for notifications."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import re
from threading import Lock
from typing import Protocol
from uuid import RFC_4122, UUID, uuid4

from scripts.validation_core import (
    SemanticIssue,
    raw_bytes_sha256,
    validate_approval_set,
    validate_recovery_contract,
    validate_schema_instance,
)


REGISTERED_AUTHORIZATION_AUDIT_EVENT = "notification_authorized"
SEND_AUTHORIZED_RECORD_TYPE = "send_authorized"
_REGISTRY_UNAVAILABLE = "authorization.registry_unavailable"
_EXECUTOR_ID_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-"
)
_BINDING_FIELDS = (
    "record_type",
    "notification_id",
    "incident_id",
    "recipient_ref",
    "template_version",
    "body_hash",
    "scope_hash",
    "idempotency_key",
    "approval_refs",
    "executor_ref",
    "expires_at",
    "request_expires_at",
    "audit_event",
)
_INBOUND_PLACEHOLDERS = frozenset({"incident_id", "security_channel"})
_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_INBOUND_TEMPLATE = _PACKAGE_ROOT / "skills/abuse-notification-agent/assets/inbound-403-notice.html"
_INBOUND_TEMPLATE_HASH = "sha256:9dbbda02d920b004b25287c91919a14139b20e1c6eb8efd97c9d0308c79d8471"


def _issue(code: str, pointer: str, message: str) -> SemanticIssue:
    return SemanticIssue(
        path="notification-authorization",
        json_pointer=pointer,
        code=code,
        message=message,
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sample_clock(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("authorization clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("authorization expiry must be an RFC3339 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("authorization expiry must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class NotificationAuthorizationRegistry(Protocol):
    """Deployment-owned immutable registry; never construct it from request data.

    A configured implementation must authenticate both approver identities and their
    current roles/decisions, authenticate the executor, and validate the recipient,
    channel, template, frequency limit, legal review and runtime production gate.
    """

    configured: bool

    def validate_authorization(
        self,
        request: Mapping[str, object],
        *,
        executor_ref: str,
        now: datetime,
    ) -> Sequence[SemanticIssue]:
        """Return fail-closed issues after authenticating every external gate."""


@dataclass(frozen=True)
class UnavailableNotificationAuthorizationRegistry:
    """Repository default: no authenticated deployment registry exists."""

    configured: bool = False

    def validate_authorization(
        self,
        request: Mapping[str, object],
        *,
        executor_ref: str,
        now: datetime,
    ) -> Sequence[SemanticIssue]:
        return ()


@dataclass(frozen=True)
class AuthorizationClaim:
    record: dict[str, object]
    created: bool


class AuthorizationDenied(ValueError):
    def __init__(self, issues: Sequence[SemanticIssue]) -> None:
        self.issues = tuple(sorted(issues))
        super().__init__("; ".join(f"{issue.code}@{issue.json_pointer}" for issue in self.issues))


class AtomicAuthorizationStore(Protocol):
    """Durable adapters must enforce unique key and expiry with database time."""

    def create_or_return(self, candidate: Mapping[str, object]) -> AuthorizationClaim:
        """Atomically create or return while requiring expires_at > transaction time."""


class InMemoryAuthorizationStore:
    """Thread-safe reference store for contract tests; never a production adapter."""

    def __init__(self, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock
        self._lock = Lock()
        self._records: dict[str, dict[str, object]] = {}
        self._authorization_ids: dict[str, str] = {}

    def create_or_return(self, candidate: Mapping[str, object]) -> AuthorizationClaim:
        materialized = deepcopy(dict(candidate))
        key = materialized.get("idempotency_key")
        if not isinstance(key, str):
            raise ValueError("candidate lacks idempotency_key")
        with self._lock:
            try:
                transaction_time = _sample_clock(self._clock)
                expires_at = _parse_timestamp(materialized.get("expires_at"))
            except (TypeError, ValueError):
                raise AuthorizationDenied(
                    (_issue("authorization.store_clock_invalid", "/expires_at", "Store could not verify authorization expiry."),)
                ) from None
            if expires_at <= transaction_time:
                raise AuthorizationDenied(
                    (_issue("authorization.expired_before_persist", "/expires_at", "Authorization expired before atomic persistence."),)
                )
            existing = self._records.get(key)
            if existing is not None:
                if any(existing.get(field) != materialized.get(field) for field in _BINDING_FIELDS):
                    raise ValueError("idempotency key already binds a different authorization")
                return AuthorizationClaim(record=deepcopy(existing), created=False)
            authorization_id = materialized.get("authorization_id")
            if not isinstance(authorization_id, str):
                raise ValueError("candidate lacks authorization_id")
            existing_key = self._authorization_ids.get(authorization_id)
            if existing_key is not None and existing_key != key:
                raise ValueError("authorization_id already binds a different idempotency key")
            self._records[key] = materialized
            self._authorization_ids[authorization_id] = key
            return AuthorizationClaim(record=deepcopy(materialized), created=True)

    def records(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            return tuple(deepcopy(record) for record in self._records.values())


def _load_fixed_inbound_template() -> str:
    if _INBOUND_TEMPLATE.is_symlink() or not _INBOUND_TEMPLATE.is_file():
        raise ValueError("fixed inbound template is missing or symbolic")
    raw = _INBOUND_TEMPLATE.read_bytes()
    if raw_bytes_sha256(raw) != _INBOUND_TEMPLATE_HASH:
        raise ValueError("fixed inbound template hash does not match the trusted package bytes")
    try:
        template = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("fixed inbound template is not strict UTF-8") from exc
    placeholders = re.findall(r"\{\{([a-z_]+)\}\}", template)
    if set(placeholders) != _INBOUND_PLACEHOLDERS or any(
        placeholders.count(name) != 1 for name in _INBOUND_PLACEHOLDERS
    ):
        raise ValueError("inbound template placeholders are not closed")
    if "{{{" in template or "}}}" in template:
        raise ValueError("raw or triple-brace rendering is forbidden")
    return template


def render_inbound_notice(*, incident_id: str, security_channel: str) -> str:
    """Render only the hash-pinned package template with text-context escaping."""

    if not all(isinstance(value, str) and value for value in (incident_id, security_channel)):
        raise ValueError("template values must be non-empty strings")
    try:
        parsed_incident_id = UUID(incident_id)
    except ValueError as exc:
        raise ValueError("incident_id must be a UUID") from exc
    if parsed_incident_id.variant != RFC_4122 or parsed_incident_id.version is None:
        raise ValueError("incident_id must be an RFC 4122 UUID")
    template = _load_fixed_inbound_template()
    values = {
        "incident_id": escape(str(parsed_incident_id), quote=True),
        "security_channel": escape(security_channel, quote=True),
    }
    rendered = template
    for name, value in values.items():
        rendered = rendered.replace("{{" + name + "}}", value)
    return rendered


def _valid_executor_ref(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and set(value) <= _EXECUTOR_ID_CHARACTERS
    )


def _uuid_text(factory: Callable[[], object]) -> str:
    value = str(factory())
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ValueError("authorization ID factory must return a UUID") from exc
    if parsed.variant != RFC_4122 or parsed.version is None:
        raise ValueError("authorization ID must be an RFC 4122 UUID")
    return str(parsed)


class NotificationAuthorizationService:
    """Long-lived authorization boundary assembled only by trusted deployment code."""

    def __init__(
        self,
        *,
        root: Path,
        store: AtomicAuthorizationStore,
        registry: NotificationAuthorizationRegistry | None = None,
        clock: Callable[[], datetime] = _utc_now,
        authorization_id_factory: Callable[[], object] = uuid4,
    ) -> None:
        self._root = root
        self._store = store
        self._registry = registry if registry is not None else UnavailableNotificationAuthorizationRegistry()
        self._clock = clock
        self._authorization_id_factory = authorization_id_factory

    def _validate(
        self,
        snapshot: Mapping[str, object],
        *,
        body: bytes,
        executor_ref: str,
        now: datetime,
    ) -> list[SemanticIssue]:
        issues: list[SemanticIssue] = []
        if not isinstance(body, bytes):
            issues.append(_issue("notification.body_bytes_required", "/body_hash", "Final body must be raw bytes."))
        if snapshot.get("notification_status") != "approved":
            issues.append(_issue("notification.not_approved", "/notification_status", "Only an approved request can be claimed."))
        if not _valid_executor_ref(executor_ref):
            issues.append(_issue("notification.executor_invalid", "/executor_ref", "Executor reference is not a registered identifier."))
        issues.extend(validate_schema_instance("notification-request", snapshot, self._root))
        approval_issues = validate_approval_set(snapshot, now=now)

        try:
            configured = self._registry.configured
            if configured is True:
                registry_issues = tuple(
                    self._registry.validate_authorization(
                        deepcopy(snapshot), executor_ref=executor_ref, now=now
                    )
                )
                if any(not isinstance(issue, SemanticIssue) for issue in registry_issues):
                    raise TypeError("registry returned a non-SemanticIssue value")
                approval_issues = [
                    issue for issue in approval_issues if issue.code != _REGISTRY_UNAVAILABLE
                ]
                issues.extend(registry_issues)
        except Exception:
            issues.append(
                _issue("authorization.registry_error", "/", "Trusted notification registry failed closed.")
            )

        issues.extend(approval_issues)
        issues.extend(validate_recovery_contract(snapshot))
        if isinstance(body, bytes) and snapshot.get("body_hash") != raw_bytes_sha256(body):
            issues.append(_issue("notification.body_hash_mismatch", "/body_hash", "Request body hash does not bind the final raw bytes."))
        return sorted(issues)

    def claim(
        self,
        request: Mapping[str, object],
        *,
        body: bytes,
        executor_ref: str,
    ) -> AuthorizationClaim:
        """Validate twice and atomically create-or-return without network I/O."""

        try:
            snapshot = deepcopy(dict(request))
            validation_time = _sample_clock(self._clock)
        except Exception:
            raise AuthorizationDenied(
                (_issue("notification.snapshot_or_clock_failed", "/", "Request or trusted clock could not be frozen."),)
            ) from None

        issues = self._validate(
            snapshot, body=body, executor_ref=executor_ref, now=validation_time
        )
        if issues:
            raise AuthorizationDenied(issues)

        try:
            authorization_id = _uuid_text(self._authorization_id_factory)
            commit_time = _sample_clock(self._clock)
        except (TypeError, ValueError):
            raise AuthorizationDenied(
                (_issue("notification.commit_identity_or_clock_failed", "/", "Trusted ID generator or commit clock failed closed."),)
            ) from None
        issues = self._validate(snapshot, body=body, executor_ref=executor_ref, now=commit_time)
        if issues:
            raise AuthorizationDenied(issues)

        approvals = snapshot["approval"]["human_approvals"]  # type: ignore[index]
        records_by_role = {record["approver_role"]: record for record in approvals}
        ordered_roles = ("incident_commander", "legal_compliance_approver")
        approval_refs = [records_by_role[role]["approval_id"] for role in ordered_roles]
        authority_expiry = min(
            [_parse_timestamp(snapshot["expires_at"])]
            + [_parse_timestamp(records_by_role[role]["expires_at"]) for role in ordered_roles]
        )
        record: dict[str, object] = {
            "record_type": SEND_AUTHORIZED_RECORD_TYPE,
            "authorization_id": authorization_id,
            "notification_id": snapshot["notification_id"],
            "incident_id": snapshot["incident_id"],
            "recipient_ref": snapshot["recipient_ref"],
            "template_version": snapshot["template_version"],
            "body_hash": snapshot["body_hash"],
            "scope_hash": snapshot["scope_hash"],
            "idempotency_key": snapshot["idempotency_key"],
            "approval_refs": approval_refs,
            "executor_ref": executor_ref,
            "authorized_at": _timestamp(commit_time),
            "expires_at": _timestamp(authority_expiry),
            "request_expires_at": snapshot["expires_at"],
            "audit_event": REGISTERED_AUTHORIZATION_AUDIT_EVENT,
        }
        return self._store.create_or_return(record)
