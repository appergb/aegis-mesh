#!/usr/bin/env python3
"""Build and verify deterministic Aegis Mesh source archives."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
def _version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _source_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=False, capture_output=True
        )
    except FileNotFoundError as exc:
        raise RuntimeError("release build requires Git and a non-empty tracked file list") from exc
    if result.returncode != 0 or not result.stdout:
        raise RuntimeError("release build requires Git and a non-empty tracked file list")

    files: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(raw.decode("utf-8"))
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError(f"unsafe tracked release path: {relative}")
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"tracked release path is missing or symbolic: {relative}")
        files.append(path)
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(files: list[Path]) -> dict[str, str]:
    return {path.relative_to(ROOT).as_posix(): _sha256(path) for path in files}


def build() -> tuple[Path, Path, Path]:
    version = _version()
    prefix = f"aegis-mesh-{version}"
    files = _source_files()
    DIST.mkdir(exist_ok=True)
    manifest_path = DIST / f"{prefix}.manifest.json"
    manifest_path.write_text(
        json.dumps(_manifest(files), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    tar_path = DIST / f"{prefix}.tar.gz"
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in files:
            relative = path.relative_to(ROOT)
            info = archive.gettarinfo(str(path), arcname=str(PurePosixPath(prefix) / relative.as_posix()))
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    with tar_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            compressed.write(tar_buffer.getvalue())

    zip_path = DIST / f"{prefix}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = PurePosixPath(prefix) / path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(str(relative), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if path.stat().st_mode & 0o111 else 0o644) << 16
            archive.writestr(info, path.read_bytes())

    checksum_path = DIST / f"{prefix}.sha256"
    checksum_path.write_text(
        f"{_sha256(tar_path)}  {tar_path.name}\n{_sha256(zip_path)}  {zip_path.name}\n"
        f"{_sha256(manifest_path)}  {manifest_path.name}\n",
        encoding="utf-8",
    )
    return tar_path, zip_path, manifest_path


def verify() -> None:
    version = _version()
    prefix = f"aegis-mesh-{version}"
    checksum_path = DIST / f"{prefix}.sha256"
    if not checksum_path.is_file():
        raise SystemExit("checksum file is missing; run the build first")
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        path = DIST / name
        if not path.is_file() or _sha256(path) != expected:
            raise SystemExit(f"checksum verification failed: {name}")
    print(f"verified {checksum_path.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify()
    else:
        outputs = build()
        print("built " + ", ".join(path.name for path in outputs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
