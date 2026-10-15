#!/usr/bin/env python3
"""Assemble the rootless and rootful x8A4 Debian release packages."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise SystemExit(f"Required source directory does not exist: {source}")
    shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True)


def build_package(
    *,
    package: str,
    version: str,
    architecture: str,
    rootful: bool,
    build_dir: Path,
    include_dir: Path,
    output_dir: Path,
) -> Path:
    root_marker = "_rootful" if rootful else ""
    filename = f"{package}_{version}{root_marker}_{architecture}.deb"
    prefix = Path("usr") if rootful else Path("var/jb/usr")

    with tempfile.TemporaryDirectory(prefix="x8a4-package-") as temporary:
        staging = Path(temporary)
        control_dir = staging / "DEBIAN"
        control_dir.mkdir()
        data_root = staging / prefix
        (data_root / "lib").mkdir(parents=True)
        (data_root / "bin").mkdir(parents=True)

        if package == "libx8a4-1":
            dylib = build_dir / "libx8A4.1.dylib"
            cli = build_dir / "x8A4_CLI"
            for binary in (dylib, cli):
                if not binary.is_file():
                    raise SystemExit(f"Build output is missing: {binary}")
            shutil.copy2(dylib, data_root / "lib" / dylib.name)
            (data_root / "lib" / "libx8A4.dylib").symlink_to(dylib.name)
            shutil.copy2(cli, data_root / "bin" / "x8A4")
            (data_root / "bin" / "x8A4").chmod(0o755)
            depends = "libkrw0 (>= 1.1.2)"
            description = "x8A4 runtime library and command line utility"
        else:
            copy_tree(include_dir, data_root / "include")
            depends = f"libx8a4-1 (= {version})"
            description = "x8A4 development headers"

        fields = [
            f"Package: {package}",
            f"Version: {version}",
            f"Architecture: {architecture}",
            "Maintainer: x8A4 contributors <x8a4@users.noreply.github.com>",
            "Section: Utilities",
            "Priority: optional",
            f"Depends: {depends}",
            "Homepage: https://github.com/Cryptiiiic/x8A4",
            f"Description: {description}",
            " Kernel access and a full jailbreak are required at runtime.",
            "",
        ]
        (control_dir / "control").write_text("\n".join(fields), encoding="utf-8")
        package_path = output_dir / filename
        subprocess.run(
            ["dpkg-deb", "--build", "--root-owner-group", str(staging), str(package_path)],
            check=True,
        )
    return package_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--include-dir", type=Path, default=Path("Include"))
    parser.add_argument("--output-dir", type=Path, default=Path("release-packages"))
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9][0-9A-Za-z.+~:-]*", args.version):
        raise SystemExit("Version must be a valid numeric Debian package version")
    build_dir = args.build_dir.resolve()
    include_dir = args.include_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    for rootful, architecture in ((False, "iphoneos-arm64"), (True, "iphoneos-arm")):
        for package in ("libx8a4-1", "libx8a4-dev"):
            result = build_package(
                package=package,
                version=args.version,
                architecture=architecture,
                rootful=rootful,
                build_dir=build_dir,
                include_dir=include_dir,
                output_dir=output_dir,
            )
            print(result)


if __name__ == "__main__":
    main()
