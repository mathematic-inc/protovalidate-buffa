import hashlib
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import release


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "tool"
        self.binary.write_bytes(Path(sys.executable).read_bytes())
        self.config = {
            "archive": "tool-1.2.3-target.tar.gz",
            "binary": "tool",
            "format": "tgz",
        }

    def test_tar_preserves_binary_and_executable_permissions(self):
        archive = release.package_binary(self.config, self.binary, self.root / "dist")
        with tarfile.open(archive) as bundle:
            self.assertEqual(bundle.getnames(), ["tool"])
            self.assertEqual(bundle.getmember("tool").mode, 0o755)
            self.assertEqual(
                bundle.extractfile("tool").read(), self.binary.read_bytes()
            )
        digest, filename = (
            archive.with_name(archive.name + ".sha256").read_text().split()
        )
        self.assertEqual(digest, hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(filename, archive.name)

    def test_zip_preserves_windows_executable_name(self):
        config = self.config | {
            "archive": "tool-1.2.3-target.zip",
            "binary": "other-name.exe",
            "format": "zip",
        }
        archive = release.package_binary(config, self.binary, self.root / "dist")
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(bundle.namelist(), ["other-name.exe"])
            self.assertEqual(bundle.read("other-name.exe"), self.binary.read_bytes())

    def test_empty_executable_is_rejected(self):
        self.binary.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty executable"):
            release.package_binary(self.config, self.binary, self.root / "dist")

    def test_modified_archive_is_rejected_before_execution(self):
        archive = release.package_binary(self.config, self.binary, self.root / "dist")
        with archive.open("ab") as stream:
            stream.write(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            release.verify_archive(self.config, self.root / "dist")

    def test_component_tags_and_binary_names_are_resolved(self):
        manifest = self.root / "Cargo.toml"
        manifest.write_text("""[package]
name = "crate-name"
version = "1.2.3"
repository = "https://github.com/owner/repo"
[[bin]]
name = "executable"
[package.metadata.binstall]
pkg-url = "{ repo }/releases/download/crate-name-v{ version }/{ name }-{ version }-{ target }.tar.gz"
bin-dir = "{ bin }{ binary-ext }"
pkg-fmt = "tgz"
[package.metadata.binstall.overrides.aarch64-pc-windows-msvc]
pkg-url = "{ repo }/releases/download/crate-name-v{ version }/{ name }-{ version }-{ target }.zip"
pkg-fmt = "zip"
""")
        config = release.configuration(manifest, "aarch64-pc-windows-msvc")
        self.assertEqual(config["binary"], "executable.exe")
        self.assertEqual(config["tag"], "crate-name-v1.2.3")
        self.assertEqual(
            config["archive"], "crate-name-1.2.3-aarch64-pc-windows-msvc.zip"
        )
        self.assertEqual(config["format"], "zip")


if __name__ == "__main__":
    unittest.main()
