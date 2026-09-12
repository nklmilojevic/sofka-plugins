#!/usr/bin/env python3
"""Checks for catalog.py. Run with `python3 scripts/test_catalog.py`."""

from __future__ import annotations

import argparse
import copy
import io
import zstandard
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import blake3
import catalog

FIXTURE = catalog.ROOT / "fixtures" / "index.json"
SCHEMA = json.loads(catalog.SCHEMA.read_text(encoding="utf-8"))
MANIFEST = catalog.PLUGINS / "resource-summary" / "plugin.toml"
FAILURES: list[str] = []


# Exactly what catalog.py reports as a validation failure rather than a crash.
REFUSALS = (KeyError, OSError, subprocess.CalledProcessError, ValueError)


def rejects(message: str, call) -> None:
    try:
        call()
    except REFUSALS:
        return
    FAILURES.append(f"accepted {message}")


def accepts(message: str, call) -> None:
    try:
        call()
    except REFUSALS as error:
        FAILURES.append(f"rejected {message}: {error}")


def index(**changes: object) -> dict[str, object]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    value["plugins"][0]["versions"][0].update(changes)
    return value


def manifest(package: dict[str, object] | None = None, **changes: object) -> dict[str, object]:
    import tomllib

    value = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    for field, setting in changes.items():
        if setting is None:
            value["plugin"].pop(field, None)
        else:
            value["plugin"][field] = setting
    for field, setting in (package or {}).items():
        if setting is None:
            value["package"].pop(field, None)
        else:
            value["package"][field] = setting
    return value


def check_index_rules() -> None:
    accepts("the published fixture", lambda: catalog.validate_index(index()))
    rejects("an invalid version range", lambda: catalog.validate_index(index(sofka="latest")))
    rejects("an empty version range", lambda: catalog.validate_index(index(sofka="")))
    rejects("a pre-catalog sofka release", lambda: catalog.validate_index(index(sofka=">=0.25.5")))
    rejects("an unbounded sofka range", lambda: catalog.validate_index(index(sofka="*")))
    rejects("a nonboolean mutation flag", lambda: catalog.validate_index(index(mutating="false")))
    rejects("a nonboolean confirmation flag", lambda: catalog.validate_index(index(confirm=1)))
    rejects("an invalid execution target", lambda: catalog.validate_index(index(target="cluster")))
    rejects("an invalid output mode", lambda: catalog.validate_index(index(output="terminal")))
    rejects("an empty command", lambda: catalog.validate_index(index(command="   ")))
    rejects("a plaintext README", lambda: catalog.validate_index(index(readme="http://example.invalid")))
    rejects("a withdrawal without a reason", lambda: catalog.validate_index(index(status="withdrawn")))


def check_version_ranges() -> None:
    """The accepted range syntax must match sofka's semver parser exactly. A
    range CI accepts but the client rejects makes the client refuse the whole
    catalog, not just that entry. Each expectation below was confirmed against
    semver::VersionReq::parse."""
    accepted = [
        ">=0.26.0",
        ">=1.2.3, <2.0.0",
        "^1.2",
        "~1",
        "*",
        "=1.2.3",
        "<=2",
        ">1.0",
        ">= 1.2.3",
        ">=0",
        ">=1.2.3-alpha.1",
        ">=1.2.3-0alpha",
        ">=1.2.3+build.01",
        ">=1.0.0-rc.1+b.2",
        ">=1.*",
        "1.*.*",
        "X",
    ]
    rejected = [
        # Semantic versioning forbids leading zeros in numeric identifiers.
        ">=01.2.3",
        ">=1.02.3",
        ">=1.2.3-alpha.01",
        ">=00",
        "latest",
        "1.2.3.4",
        ">=1.2.3-",
        "v1.2.3",
        "1.*.3",
        ">=*",
        "1.2-beta",
        "1.2+meta",
        "*-beta",
        "1.*.3-beta",
        "1.2.18446744073709551616",
    ]
    for value in accepted:
        if not catalog.valid_version_requirement(value):
            FAILURES.append(f"rejected the valid range {value!r}")
    for value in rejected:
        if catalog.valid_version_requirement(value):
            FAILURES.append(f"accepted {value!r}, which sofka's parser rejects")

    for value in [">=0.26.0", ">=0.26, <1.0.0", "^0.26", ">0.26.0", ">=1"]:
        if not catalog.requires_supported_sofka(value):
            FAILURES.append(f"rejected the supported sofka range {value!r}")
    for value in [">=0.25.5", ">=0.26.0-alpha.1", "<1.0.0", "*"]:
        if catalog.requires_supported_sofka(value):
            FAILURES.append(f"accepted the pre-0.26 sofka range {value!r}")

    for value in ["0.1.0", "1.2.3-alpha.1+build.01", f"{2**64 - 1}.0.0"]:
        if not catalog.valid_version(value):
            FAILURES.append(f"rejected the valid version {value!r}")
    for value in ["01.2.3", "1.2.3-alpha..1", "1.2", f"{2**64}.0.0"]:
        if catalog.valid_version(value):
            FAILURES.append(f"accepted the invalid version {value!r}")


def check_schema_rules() -> None:
    accepts("the published fixture", lambda: catalog.validate_schema(index(), SCHEMA, SCHEMA, "index"))
    rejects("a nonboolean mutation flag", lambda: catalog.validate_schema(index(mutating="false"), SCHEMA, SCHEMA, "index"))
    rejects("an unknown release field", lambda: catalog.validate_schema(index(surprise=1), SCHEMA, SCHEMA, "index"))
    rejects("an invalid execution target", lambda: catalog.validate_schema(index(target="cluster"), SCHEMA, SCHEMA, "index"))
    rejects("a short source commit", lambda: catalog.validate_schema(index(source_commit="0" * 39), SCHEMA, SCHEMA, "index"))
    rejects(
        "a schema keyword this validator does not apply",
        lambda: catalog.validate_schema({}, {"type": "object", "dependentRequired": {}}, SCHEMA, "index"),
    )


def check_manifest_rules() -> None:
    accepts("the published manifest", lambda: catalog.validate_manifest("resource-summary", manifest()))
    rejects("shell = true", lambda: catalog.validate_manifest("resource-summary", manifest(shell=True)))
    rejects("a reserved palette command", lambda: catalog.validate_manifest("resource-summary", manifest(palette="xray")))
    rejects("an uppercase palette command", lambda: catalog.validate_manifest("resource-summary", manifest(palette="Summary")))
    rejects("an unknown manifest field", lambda: catalog.validate_manifest("resource-summary", manifest(sudo=True)))
    rejects("an uncaptured output mode", lambda: catalog.validate_manifest("resource-summary", manifest(output="terminal")))
    rejects("an invalid target", lambda: catalog.validate_manifest("resource-summary", manifest(target="cluster")))
    rejects("an empty command", lambda: catalog.validate_manifest("resource-summary", manifest(command="")))
    rejects("an unknown [package] field", lambda: catalog.validate_manifest("resource-summary", manifest(package={"surprise": 1})))
    rejects("an invalid timeout", lambda: catalog.validate_manifest("resource-summary", manifest(timeout="10w")))
    rejects("a port-forward without a report", lambda: catalog.validate_manifest("resource-summary", manifest(port_forward="8080", output="popup")))
    rejects("a manifest with neither palette nor key", lambda: catalog.validate_manifest("resource-summary", manifest(palette=None)))
    rejects(
        "an undeclared input placeholder",
        lambda: catalog.validate_manifest("resource-summary", manifest(args=["${input.missing}"])),
    )
    rejects(
        "a default outside its input type",
        lambda: catalog.validate_manifest(
            "resource-summary", manifest(inputs={"detail": {"type": "boolean", "default": "yes"}})
        ),
    )
    rejects(
        "a bound on a string input",
        lambda: catalog.validate_manifest(
            "resource-summary", manifest(inputs={"detail": {"type": "string", "max": 5}})
        ),
    )


def commit(repository: pathlib.Path, index: dict[str, object], message: str) -> str:
    (repository / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    run = lambda *argv: subprocess.run(argv, cwd=repository, check=True, capture_output=True)
    run("git", "add", "index.json")
    run("git", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()


def check_immutability() -> None:
    with tempfile.TemporaryDirectory() as directory:
        repository = pathlib.Path(directory)
        for argv in (
            ("git", "init", "--quiet", "-b", "main"),
            ("git", "config", "user.email", "catalog@example.invalid"),
            ("git", "config", "user.name", "catalog"),
        ):
            subprocess.run(argv, cwd=repository, check=True, capture_output=True)
        published = json.loads(FIXTURE.read_text(encoding="utf-8"))
        base = commit(repository, published, "publish")

        original, catalog.ROOT = catalog.ROOT, repository
        try:
            def head(change) -> str:
                value = copy.deepcopy(published)
                change(value["plugins"][0])
                return commit(repository, value, "change")

            def repoint(plugin):
                plugin["versions"][0]["artifacts"][0]["blake3"] = "9" * 64

            rejects("a repointed digest", lambda: catalog.assert_immutable(base, head(repoint)))
            rejects(
                "a dropped version",
                lambda: catalog.assert_immutable(base, head(lambda plugin: plugin["versions"].clear())),
            )
            rejects(
                "a moved source commit",
                lambda: catalog.assert_immutable(
                    base, head(lambda plugin: plugin["versions"][0].update(source_commit="a" * 40))
                ),
            )
            rejects(
                "a withdrawal without a reason",
                lambda: catalog.assert_immutable(
                    base, head(lambda plugin: plugin["versions"][0].update(status="withdrawn"))
                ),
            )
            accepts(
                "an explained withdrawal",
                lambda: catalog.assert_immutable(
                    base,
                    head(
                        lambda plugin: plugin["versions"][0].update(
                            status="withdrawn", withdrawal_reason="reported defect"
                        )
                    ),
                ),
            )
            accepts(
                "a renamed plugin and an added version",
                lambda: catalog.assert_immutable(
                    base,
                    head(
                        lambda plugin: plugin.update(
                            display_name="Renamed",
                            versions=plugin["versions"]
                            + [{**copy.deepcopy(plugin["versions"][0]), "version": "0.2.0"}],
                        )
                    ),
                ),
            )
        finally:
            catalog.ROOT = original


def check_selection() -> None:
    """Only a change that can affect a plugin selects it for building."""
    real = subprocess.check_output

    def fake(command, **kwargs):
        if command[:3] == ["git", "diff", "--name-only"]:
            return fake.paths
        return real(command, **kwargs)

    subprocess.check_output = fake
    try:
        # A change outside plugins/ that can reach Rust selects every plugin.
        every = catalog.plugin_ids()
        expected = {
            "index.json\n": [],
            "index.schema.json\n": [],
            "README.md\n": [],
            "CONTRIBUTING.md\n": [],
            "plugins/resource-summary/src/main.rs\n": ["resource-summary"],
            "plugins/resource-summary/README.md\n": ["resource-summary"],
            ".github/workflows/ci.yaml\n": every,
            "scripts/catalog.py\n": every,
            "Cargo.lock\n": every,
            "Cargo.toml\n": every,
            "xtask/src/main.rs\n": every,
            "plugins/absent-plugin/plugin.toml\n": [],
        }
        for paths, selected in expected.items():
            fake.paths = paths
            actual = catalog.changed_plugins("a", "b", "test")
            if actual != selected:
                FAILURES.append(f"selected {actual} for {paths.strip()}, expected {selected}")
        # Publishing selects only the plugin directories that changed.
        fake.paths = "Cargo.lock\n"
        if catalog.changed_plugins("a", "b", "publish") != []:
            FAILURES.append("publish mode selected a plugin for a lockfile-only change")
    finally:
        subprocess.check_output = real


def check_packaging() -> None:
    """Archives must be byte-identical across runs and carry only the files and
    modes the installer expects."""
    with tempfile.TemporaryDirectory() as directory:
        out = pathlib.Path(directory)
        binary = out / "adapter"
        binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        built = []
        for run in range(2):
            target = out / f"package-{run}.tar.zst"
            catalog.package(
                argparse.Namespace(
                    plugin="resource-summary",
                    target="x86_64-unknown-linux-gnu",
                    binary=str(binary),
                    output=str(target),
                )
            )
            built.append(target.read_bytes())
        if built[0] != built[1]:
            FAILURES.append("packaging is not reproducible")

        with tarfile.open(fileobj=io.BytesIO(zstandard.ZstdDecompressor().decompress(built[0], max_output_size=64 << 20))) as archive:
            members = {member.name: member for member in archive.getmembers()}
        expected = {
            "plugin.toml": 0o644,
            "README.md": 0o644,
            "LICENSE-MIT": 0o644,
            "LICENSE-APACHE": 0o644,
            catalog.ADAPTER: 0o755,
        }
        if set(members) != set(expected):
            FAILURES.append(f"archive holds {sorted(members)}, expected {sorted(expected)}")
        for name, mode in expected.items():
            member = members.get(name)
            if member is None:
                continue
            if member.mode != mode:
                FAILURES.append(f"{name} has mode {member.mode:o}, expected {mode:o}")
            if not member.isfile():
                FAILURES.append(f"{name} is not a regular file")
            if member.mtime or member.uid or member.gid or member.uname or member.gname:
                FAILURES.append(f"{name} carries build-host metadata")

        rejects(
            "an unsupported target",
            lambda: catalog.package(
                argparse.Namespace(
                    plugin="resource-summary",
                    target="powerpc-unknown-linux-gnu",
                    binary=str(binary),
                    output=str(out / "bad.tar.zst"),
                )
            ),
        )
        # The workflows name asset files from this, so it must stay parseable.
        import io as _io, contextlib
        printed = _io.StringIO()
        with contextlib.redirect_stdout(printed):
            catalog.version(argparse.Namespace(plugin="resource-summary"))
        if printed.getvalue().strip() != catalog.manifest("resource-summary")["package"]["version"]:
            FAILURES.append(f"version printed {printed.getvalue()!r}")

        rejects(
            "a missing adapter binary",
            lambda: catalog.package(
                argparse.Namespace(
                    plugin="resource-summary",
                    target="x86_64-unknown-linux-gnu",
                    binary=str(out / "absent"),
                    output=str(out / "bad.tar.zst"),
                )
            ),
        )


def check_index_generation() -> None:
    """update-index records the digests of the exact published bytes."""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        assets = root / "dist"
        assets.mkdir()
        metadata = catalog.publication("resource-summary")
        version = metadata["version"]
        payload = {}
        for platform in metadata["platforms"]:
            name = f"resource-summary-{version}-{platform}.tar.zst"
            payload[platform] = f"bytes for {platform}".encode()
            (assets / name).write_bytes(payload[platform])
        index = root / "index.json"
        index.write_text(json.dumps({"schema_version": 1, "generated_at": "x", "plugins": []}))

        original_index, catalog.INDEX = catalog.INDEX, index
        try:
            commit = "c" * 40
            arguments = argparse.Namespace(
                commit=commit, assets=str(assets), plugins=["resource-summary"]
            )
            accepts("a first publication", lambda: catalog.update_index(arguments))
            written = json.loads(index.read_text())
            accepts("the generated index", lambda: catalog.validate_index(written))
            accepts(
                "the generated index against the schema",
                lambda: catalog.validate_schema(written, SCHEMA, SCHEMA, "index"),
            )
            release = written["plugins"][0]["versions"][0]
            if release["source_commit"] != commit:
                FAILURES.append("generated release does not record the source commit")
            if release["status"] != "active" or "withdrawal_reason" in release:
                FAILURES.append("generated release is not a plain active record")
            if f"/blob/{commit}/" not in release["readme"]:
                FAILURES.append("generated README link is not pinned to the source commit")
            for artifact in release["artifacts"]:
                bytes_ = payload[artifact["platform"]]
                if artifact["blake3"] != blake3.blake3(bytes_).hexdigest():
                    FAILURES.append(f"{artifact['platform']} digest is not the published bytes")
                if artifact["size"] != len(bytes_):
                    FAILURES.append(f"{artifact['platform']} size is not the published length")
                if not artifact["url"].startswith(
                    f"{catalog.RELEASE_ROOT}resource-summary-v{version}/"
                ):
                    FAILURES.append(f"{artifact['platform']} URL is not a release asset")

            # Re-running with identical bytes is a no-op; different bytes are not.
            accepts("an identical re-publication", lambda: catalog.update_index(arguments))
            for platform in metadata["platforms"]:
                name = f"resource-summary-{version}-{platform}.tar.zst"
                (assets / name).write_bytes(b"different bytes")
            rejects("a re-publication with different bytes", lambda: catalog.update_index(arguments))

            (assets / f"resource-summary-{version}-{metadata['platforms'][0]}.tar.zst").unlink()
            rejects("a missing published asset", lambda: catalog.update_index(arguments))
        finally:
            catalog.INDEX = original_index


def check_source_rules() -> None:
    """The checked-in sources, and the catalog metadata derived from them."""
    index = json.loads(catalog.INDEX.read_text(encoding="utf-8"))
    accepts("the checked-in sources", lambda: catalog.validate_sources(index))
    rejects(
        "an index entry with no source directory",
        lambda: catalog.validate_sources(
            {"plugins": [{"id": "absent-plugin", "versions": []}]}
        ),
    )
    # There is one authored file per package; nothing is written down twice.
    for plugin in catalog.plugin_ids():
        if (catalog.PLUGINS / plugin / "publication.json").exists():
            FAILURES.append(f"{plugin} still carries publication.json")
    # The mapping is what matters, not the values a package happens to carry.
    for plugin in catalog.plugin_ids():
        authored = catalog.manifest(plugin)
        package, definition = authored["package"], authored["plugin"]
        derived = catalog.publication(plugin)
        expected = {
            "id": plugin,
            "display_name": definition["name"],
            "description": package["description"],
            "publisher": ", ".join(package["authors"]),
            "repository": package["repository"],
            "version": package["version"],
            "sofka": package["sofka"],
            "license": package["license"],
            "readme": package["readme"],
            "tags": package.get("tags", []),
            "platforms": package["platforms"],
            "command": definition["command"],
            "target": definition.get("target", "selection"),
            "output": definition["output"],
            "mutating": definition["mutating"],
            "confirm": definition.get("confirm", False),
            "dangerous": definition.get("dangerous", False),
            "network_load": definition.get("network_load", False),
            "requirements": package.get("requirements", [
                {"name": name, "install": definition.get("install", "")}
                for name in definition.get("requires", [])
            ]),
        }
        if set(derived) != set(expected):
            FAILURES.append(f"{plugin} derives {sorted(set(derived) ^ set(expected))} unexpectedly")
        for field, value in expected.items():
            if derived.get(field) != value:
                FAILURES.append(f"{plugin} {field} derived as {derived.get(field)!r}, expected {value!r}")
    rejects("a package directory with no manifest", lambda: catalog.manifest("absent-plugin"))
    with tempfile.TemporaryDirectory() as directory:
        bare = pathlib.Path(directory) / "bare"
        bare.mkdir()
        (bare / "plugin.toml").write_text(
            'schema_version = 1\n[plugin]\nname = "Bare"\npalette = "bare"\n'
            'command = "./adapter"\noutput = "report"\nmutating = false\n',
            encoding="utf-8",
        )
        original, catalog.PLUGINS = catalog.PLUGINS, bare.parent
        try:
            rejects("a manifest with no [package] table", lambda: catalog.manifest("bare"))
        finally:
            catalog.PLUGINS = original
    metadata = catalog.publication("resource-summary")
    accepts(
        "the checked-in package metadata",
        lambda: catalog.validate_execution(metadata, "resource-summary package", published=False),
    )
    for field, value in (
        ("sofka", "latest"),
        ("output", "terminal"),
        ("target", "cluster"),
        ("mutating", "false"),
        ("readme", "http://example.invalid"),
        ("license", ""),
    ):
        broken = dict(metadata)
        broken[field] = value
        rejects(
            f"a package with an invalid {field}",
            lambda broken=broken: catalog.validate_execution(broken, "package"),
        )


def main() -> None:
    check_index_rules()
    check_schema_rules()
    check_version_ranges()
    check_manifest_rules()
    check_source_rules()
    check_selection()
    check_packaging()
    check_index_generation()
    check_immutability()
    for failure in FAILURES:
        print(f"catalog validation {failure}", file=sys.stderr)
    print(f"{len(FAILURES)} failures", file=sys.stderr)
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
