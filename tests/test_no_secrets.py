from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache"}
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)* )?PRIVATE KEY-----"
)
BEARER_OR_JWT = re.compile(
    r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:export\s+)?(?:[{,]\s*)?[\"']?"
    r"(?P<key>[a-z0-9_-]*(?:password|api[_-]?key|secret|token)[a-z0-9_-]*)"
    r"[\"']?\s*[:=]\s*[\"']?([^\s\"'#,}]+)"
)
CREDENTIAL_URL = re.compile(r"https?://[^\s/:]+:[^\s/@]+@[^\s]+", re.IGNORECASE)
SAFE_VALUES = {"null", "none", "false", "example", "placeholder", "changeme"}
NON_CREDENTIAL_KEY_PARTS = {
    "configured",
    "days",
    "enabled",
    "expires",
    "expiry",
    "hours",
    "interval",
    "metadata",
    "minutes",
    "policy",
    "ref",
    "reference",
    "rotation",
    "seconds",
    "timeout",
    "ttl",
}


def repository_text_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0 and result.stdout:
        return [
            ROOT / raw.decode("utf-8")
            for raw in result.stdout.split(b"\0")
            if raw and (ROOT / raw.decode("utf-8")).is_file()
        ]
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not (set(path.relative_to(ROOT).parts) & SKIP_PARTS)
    ]


def detect_secret_literals(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return []

    findings: list[str] = []
    if PRIVATE_KEY.search(text):
        findings.append("private key")
    if BEARER_OR_JWT.search(text):
        findings.append("bearer/JWT literal")
    if CREDENTIAL_URL.search(text):
        findings.append("credential-bearing URL")
    for match in SENSITIVE_ASSIGNMENT.finditer(text):
        key_parts = set(re.split(r"[_-]+", match.group("key").lower()))
        if key_parts & NON_CREDENTIAL_KEY_PARTS:
            continue
        value = match.group(2)
        if (
            value.lower() not in SAFE_VALUES
            and not value.startswith("${")
            and not value.startswith("secret://")
            and "example.invalid" not in value
        ):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"line {line}: secret assignment")
    return findings


def test_repository_contains_no_secret_literals() -> None:
    findings: list[str] = []
    for path in repository_text_files():
        relative = path.relative_to(ROOT)
        findings.extend(f"{relative}: {finding}" for finding in detect_secret_literals(path))
    assert findings == []


def test_secret_detector_covers_private_key_variants_and_assignments(tmp_path: Path) -> None:
    examples = (
        "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\nmaterial",
        "-----BEGIN " + "DSA PRIVATE KEY-----\nmaterial",
        '{"api_' + 'key": "live-value-that-is-not-a-placeholder"}',
        "export API_" + "KEY=live-value-that-is-not-a-placeholder",
        "AWS_" + "SECRET_ACCESS_KEY=live-value-that-is-not-a-placeholder",
        "secret_" + "value: live-value-that-is-not-a-placeholder",
    )
    for index, example in enumerate(examples):
        candidate = tmp_path / f"candidate-{index}.key"
        candidate.write_text(example, encoding="utf-8")
        assert detect_secret_literals(candidate), example


def test_secret_detector_allows_explicit_safe_values(tmp_path: Path) -> None:
    candidate = tmp_path / "safe.yaml"
    candidate.write_text(
        "api_" + "key: null\nsecret: secret://runtime/reference\npassword: ${RUNTIME_PASSWORD}\n"
        "token_ttl_seconds: 300\npassword_policy: strong\nsecret_rotation_days: 30\n"
        "secret_ref: vault-item-name\n",
        encoding="utf-8",
    )
    assert detect_secret_literals(candidate) == []
