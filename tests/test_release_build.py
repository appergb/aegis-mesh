from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def _untracked_credential_sentinel(value: str) -> str:
    """Build a scanner sentinel without embedding a credential-shaped literal."""
    return "".join(("API", "_KEY=", value, "\n"))


def _candidate(tmp_path: Path) -> Path:
    candidate = tmp_path / "candidate"
    (candidate / "scripts").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts/build_release.py", candidate / "scripts/build_release.py")
    shutil.copy2(ROOT / "pyproject.toml", candidate / "pyproject.toml")
    return candidate


def test_release_build_fails_closed_without_git_even_with_sensitive_sentinel(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    sentinel = candidate / ".env"
    sentinel.write_text(
        _untracked_credential_sentinel("must-never-enter-release"), encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, "scripts/build_release.py"],
        cwd=candidate,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "requires Git and a non-empty tracked file list" in result.stderr
    assert not (candidate / "dist").exists()


def test_release_build_uses_only_git_tracked_files(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=candidate, check=True)
    subprocess.run(
        ["git", "add", "pyproject.toml", "scripts/build_release.py"],
        cwd=candidate,
        check=True,
    )
    (candidate / ".env").write_text(
        _untracked_credential_sentinel("must-never-enter-release"), encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, "scripts/build_release.py"],
        cwd=candidate,
        capture_output=True,
        text=True,
        check=True,
    )
    manifest = (candidate / "dist/aegis-mesh-0.1.0.manifest.json").read_text(encoding="utf-8")
    assert ".env" not in manifest
    assert "pyproject.toml" in manifest


def test_release_tag_must_exactly_match_project_version() -> None:
    script = ROOT / "scripts/check_release_tag.py"
    accepted = subprocess.run(
        [sys.executable, str(script), "--tag", "v0.1.0"], capture_output=True, text=True
    )
    rejected = subprocess.run(
        [sys.executable, str(script), "--tag", "v0.1.0-unreviewed"], capture_output=True, text=True
    )
    assert accepted.returncode == 0
    assert rejected.returncode != 0
    assert "must be exactly v0.1.0" in rejected.stderr
