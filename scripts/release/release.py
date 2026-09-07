"""Package and verify the executable described by a Cargo manifest."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

import tomllib


def configuration(manifest, target):
    document = tomllib.loads(manifest.read_text(encoding="utf-8"))
    package = document["package"]
    repository = package["repository"]
    if isinstance(repository, dict):
        for parent in manifest.resolve().parents:
            root = parent / "Cargo.toml"
            if root.is_file():
                workspace = tomllib.loads(root.read_text(encoding="utf-8")).get(
                    "workspace", {}
                )
                if "repository" in workspace.get("package", {}):
                    repository = workspace["package"]["repository"]
                    break
        else:
            raise ValueError("workspace repository is missing")
    binaries = document.get("bin", [{"name": package["name"]}])
    if len(binaries) != 1:
        raise ValueError("release packaging requires exactly one binary")
    metadata = package["metadata"]["binstall"]
    metadata = metadata | metadata.get("overrides", {}).get(target, {})
    values = {
        "repo": repository.rstrip("/"),
        "name": package["name"],
        "version": package["version"],
        "target": target,
        "bin": binaries[0]["name"],
        "binary-ext": ".exe" if "windows" in target else "",
    }

    def render(template):
        return re.sub(r"\{\s*([\w-]+)\s*\}", lambda match: values[match[1]], template)

    url = render(metadata["pkg-url"])
    binary = render(metadata["bin-dir"])
    if Path(binary).name != binary or "/" in binary or "\\" in binary:
        raise ValueError("the release binary must be at the archive root")
    return {
        "package": package["name"],
        "version": package["version"],
        "binary": binary,
        "archive": url.rsplit("/", 1)[1],
        "tag": url.split("/releases/download/", 1)[1].split("/", 1)[0],
        "repository": repository.removeprefix("https://github.com/"),
        "format": metadata["pkg-fmt"],
    }


def package_binary(config, binary, output):
    if not binary.is_file() or binary.stat().st_size == 0:
        raise ValueError(f"missing or empty executable: {binary}")
    output.mkdir(parents=True, exist_ok=True)
    archive = output / config["archive"]
    if config["format"] == "zip":
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.write(binary, config["binary"])
    elif config["format"] == "tgz":
        with tarfile.open(archive, "w:gz") as bundle:
            info = bundle.gettarinfo(binary, arcname=config["binary"])
            info.mode = 0o755
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with binary.open("rb") as executable:
                bundle.addfile(info, executable)
    else:
        raise ValueError(f"unsupported archive format: {config['format']}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    print(f"Packaged {archive}", flush=True)
    return archive


def smoke(binary, package):
    args = (
        []
        if package in {"protoc-gen-protovalidate-buffa", "sqlc-gen-sqlx"}
        else ["--help"]
    )
    result = subprocess.run(
        [str(binary.resolve()), *args],
        input=b"",
        capture_output=True,
        timeout=30,
        check=True,
    )
    if not result.stdout:
        raise ValueError(f"{binary} returned an empty smoke-test response")
    print(f"Smoke test passed: {binary}", flush=True)


def verify_archive(config, output):
    archive = output / config["archive"]
    expected = archive.with_name(archive.name + ".sha256").read_text().split()[0]
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError(f"checksum mismatch: {archive}")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        if config["format"] == "zip":
            with zipfile.ZipFile(archive) as bundle:
                if bundle.namelist() != [config["binary"]]:
                    raise ValueError("unexpected files in release archive")
                bundle.extractall(directory)
        else:
            with tarfile.open(archive) as bundle:
                if bundle.getnames() != [config["binary"]]:
                    raise ValueError("unexpected files in release archive")
                bundle.extractall(directory, filter="data")
        smoke(directory / config["binary"], config["package"])


def verify_install(config, target):
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        binstall = directory / "binstall"
        subprocess.run(
            [
                "cargo-binstall",
                "--no-confirm",
                "--disable-telemetry",
                "--disable-strategies",
                "compile,quick-install",
                "--targets",
                target,
                "--install-path",
                str(binstall),
                "--no-track",
                f"{config['package']}@{config['version']}",
            ],
            check=True,
        )
        smoke(binstall / config["binary"], config["package"])
        destination = directory / "mise"
        tool = f"github:{config['repository']}[asset_pattern={config['archive']}]@{config['tag']}"
        subprocess.run(["mise", "install-into", tool, str(destination)], check=True)
        matches = list(destination.rglob(config["binary"]))
        if len(matches) != 1:
            raise ValueError(f"expected one mise executable, found {matches}")
        smoke(matches[0], config["package"])
        if (
            hashlib.sha256(matches[0].read_bytes()).digest()
            != hashlib.sha256((binstall / config["binary"]).read_bytes()).digest()
        ):
            raise ValueError("mise and cargo-binstall installed different executables")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["metadata", "package", "verify-archive", "verify-install"]
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    config = configuration(args.manifest, args.target)
    if args.command == "metadata":
        print(json.dumps(config))
        if output := os.environ.get("GITHUB_OUTPUT"):
            with Path(output).open("a", encoding="utf-8") as stream:
                stream.writelines(f"{key}={value}\n" for key, value in config.items())
    elif args.command == "package":
        if args.binary is None:
            parser.error("package requires --binary")
        package_binary(config, args.binary, args.output)
    elif args.command == "verify-archive":
        verify_archive(config, args.output)
    else:
        verify_install(config, args.target)


if __name__ == "__main__":
    main()
