from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE = ROOT / "docs/architecture.md"
CUSTOMIZATION = ROOT / "docs/customization.md"
DEPLOYMENT = ROOT / "docs/deployment.md"

AGENTS = (
    "main-security-orchestrator",
    "qr-security-agent",
    "ddos-defense-agent",
    "api-security-agent",
    "infrastructure-agent",
    "kubernetes-agent",
    "database-agent",
    "observability-agent",
    "incident-response-agent",
    "disaster-recovery-agent",
    "threat-intelligence-agent",
    "abuse-notification-agent",
)


def test_agent_manifest_is_closed_and_well_formed() -> None:
    assert len(AGENTS) == 12
    assert len(set(AGENTS)) == len(AGENTS)
    assert all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) for name in AGENTS)


def test_open_source_bootstrap_files_exist() -> None:
    required = (
        ROOT / ".python-version",
        ROOT / ".gitignore",
        ROOT / "pyproject.toml",
        ROOT / "requirements-validation.lock",
        ARCHITECTURE,
        CUSTOMIZATION,
        DEPLOYMENT,
        ROOT / "LICENSE",
        ROOT / "SECURITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CODE_OF_CONDUCT.md",
        ROOT / "CHANGELOG.md",
        ROOT / "Makefile",
        ROOT / "setup.sh",
    )
    assert all(path.is_file() for path in required)


def test_python_version_is_exact() -> None:
    assert (ROOT / ".python-version").read_text(encoding="utf-8") == "3.11.15\n"


def test_general_architecture_documents_are_materialized() -> None:
    assert "Aegis Mesh" in ARCHITECTURE.read_text(encoding="utf-8")
    assert "framework-neutral" in ARCHITECTURE.read_text(encoding="utf-8")
    assert "deployment profile" in CUSTOMIZATION.read_text(encoding="utf-8")
    assert "production blocked" in DEPLOYMENT.read_text(encoding="utf-8")


def test_project_metadata_and_direct_dependencies_are_locked() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "aegis-mesh-agent"
    assert project["version"] == "0.1.0"
    assert project["requires-python"] == "==3.11.15"
    assert set(project["dependencies"]) == {
        "jsonschema>=4,<5",
        "rfc8785==0.1.4",
        "ruamel.yaml>=0.18,<0.19",
    }
    assert project["optional-dependencies"] == {
        "test": ["pytest>=8,<10"],
        "detection": [
            "pySigma==1.4.0",
            "pySigma-backend-elasticsearch==2.1.0",
            "pySigma-pipeline-sysmon==2.0.0",
            "yara-python==4.5.4",
        ],
    }


def test_validation_lock_is_hash_complete_and_auditable() -> None:
    lock = (ROOT / "requirements-validation.lock").read_text(encoding="utf-8")
    assert "--default-index https://pypi.org/simple" in lock.splitlines()[1]

    starts = list(re.finditer(r"(?m)^([a-z0-9][a-z0-9._-]*)==([^ \\\n]+) \\$", lock))
    assert len(starts) == 31
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(lock)
        block = lock[match.start():end]
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?: \\\n|\n)", block)
        assert hashes, f"{match.group(1)} lacks a valid SHA-256 hash"

    expected_packages = {
        "attrs": "26.1.0",
        "certifi": "2026.7.22",
        "charset-normalizer": "3.4.9",
        "diskcache": "5.6.3",
        "diskcache-stubs": "5.6.3.6.20240818",
        "idna": "3.18",
        "iniconfig": "2.3.0",
        "jinja2": "3.1.6",
        "jq": "1.12.0",
        "jsonschema": "4.26.0",
        "jsonschema-specifications": "2025.9.1",
        "markupsafe": "3.0.3",
        "packaging": "26.2",
        "pluggy": "1.6.0",
        "pygments": "2.20.0",
        "pyparsing": "3.3.2",
        "pysigma": "1.4.0",
        "pysigma-backend-elasticsearch": "2.1.0",
        "pysigma-pipeline-sysmon": "2.0.0",
        "pytest": "9.1.1",
        "pyyaml": "6.0.3",
        "referencing": "0.37.0",
        "requests": "2.34.2",
        "rfc8785": "0.1.4",
        "rpds-py": "2026.6.3",
        "ruamel-yaml": "0.18.17",
        "ruamel-yaml-clib": "0.2.15",
        "types-pyyaml": "6.0.12.20260724",
        "typing-extensions": "4.16.0",
        "urllib3": "2.7.0",
        "yara-python": "4.5.4",
    }
    observed = {match.group(1): match.group(2) for match in starts}
    assert observed == expected_packages

    required_hashes = {
        "520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48",
        "e04db8cce4f0fd7dc8a3a64bc6d3ecaa49b7939d55ee42b12c7152d143eced47",
        "d4b6ed1566fd8cca05a5d175d6d5dc644e0a863b94eab4025679c9550de1b881",
        "84575bbde5dd891882306ca1f6ce16bdc592da2e511ac8960012af2efb9d120b",
        "4c682170f3d5cb3a73aa1bd0dc9ab1c0957437b937b7a83ff6d7ffd366415b9c",
        "9d9acf6f8135bcee03f47b1096ad69f4a2788abe37dd070aab6e9dd816742ecc",
    }
    assert required_hashes <= set(re.findall(r"--hash=sha256:([0-9a-f]{64})", lock))


def test_validator_and_scenario_files_exist() -> None:
    scenario_names = {
        "qr-issuance-spike.yaml", "legitimate-opening-surge.yaml", "api-abuse.yaml",
        "database-degradation.yaml", "region-failure.yaml", "verified-abuse-notice.yaml",
        "wazuh-read-triage.yaml", "wazuh-write-denied.yaml",
        "unauthorized-external-target-denied.yaml", "incident-ioc-enrichment.yaml",
        "sensitive-url-reputation-denied.yaml", "existing-public-url-report.yaml",
        "vulnfeed-payment-denied.yaml", "vulnfeed-epss-kev.yaml", "attack-chain-gaps.yaml",
        "detection-rule-validation.yaml", "stride-incomplete.yaml",
    }
    assert {path.name for path in (ROOT / "scenarios").iterdir()} == scenario_names
    assert (ROOT / "scripts/validate_package.py").is_file()
    assert (ROOT / "scripts/validate_forward_results.py").is_file()
