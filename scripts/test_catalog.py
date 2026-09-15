#!/usr/bin/env -S uv run --locked python
"""Checks for catalog.py. Run with `uv run --locked python scripts/test_catalog.py`."""

from __future__ import annotations

import argparse
import copy
import contextlib
import io
import zstandard
import json
import pathlib
import re
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
            value["commands"][0].pop(field, None)
        else:
            value["commands"][0][field] = setting
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


def command_index() -> dict[str, object]:
    value = index()
    value["schema_version"] = 2
    release = value["plugins"][0]["versions"][0]
    first = {field: release.pop(field) for field in catalog.EXECUTION_FIELDS}
    first.update(name="Status", palette="cert-manager-status", args=["status"], scopes=["certificates"])
    second = dict(first, name="Renew", palette="cert-manager-renew", args=["renew"], mutating=True, confirm=True)
    release.update(sofka=">=0.27.0", commands=[first, second])
    return value


def check_command_packages() -> None:
    import copy

    accepts("command catalog", lambda: catalog.validate_index(command_index()))
    accepts("command catalog schema", lambda: catalog.validate_schema(command_index(), SCHEMA, SCHEMA, "index"))
    mixed = command_index()
    old = index()["plugins"][0]["versions"][0]
    old["version"] = "0.0.1"
    mixed["plugins"][0]["versions"].append(old)
    accepts("old releases in schema 2", lambda: catalog.validate_index(mixed))
    accepts("old releases in schema 2 schema", lambda: catalog.validate_schema(mixed, SCHEMA, SCHEMA, "index"))
    for label, mutate in [
        ("schema 1 with commands", lambda v, r: v.update(schema_version=1)),
        ("empty commands", lambda v, r: r.update(commands=[])),
        ("mixed execution fields", lambda v, r: r.update(mutating=False)),
        ("old client range", lambda v, r: r.update(sofka=">=0.26.0")),
        ("duplicate palette", lambda v, r: r["commands"][1].update(palette="cert-manager-status")),
        ("duplicate name", lambda v, r: r["commands"][1].update(name="Status")),
        ("second command mutation type", lambda v, r: r["commands"][1].update(mutating="false")),
        ("second command missing mutation", lambda v, r: r["commands"][1].pop("mutating")),
        ("second command invalid scopes", lambda v, r: r["commands"][1].update(scopes="certificates")),
    ]:
        value = command_index()
        mutate(value, value["plugins"][0]["versions"][0])
        rejects(label, lambda value=value: catalog.validate_index(value))
    wrong_schema = command_index()
    wrong_schema["schema_version"] = 1
    rejects("schema 1 command arrays in JSON Schema", lambda: catalog.validate_schema(wrong_schema, SCHEMA, SCHEMA, "index"))
    value = manifest()
    second = copy.deepcopy(value["commands"][0])
    second.update(name="Another command", palette="another-command", mutating=True, confirm=True)
    value["commands"].append(second)
    accepts("two manifest commands", lambda: catalog.validate_manifest("example", value))
    for label, change in [
        ("duplicate manifest palette", {"palette": value["commands"][0]["palette"]}),
        ("invalid second manifest command", {"output": "terminal"}),
    ]:
        invalid = copy.deepcopy(value)
        invalid["commands"][1].update(change)
        rejects(label, lambda invalid=invalid: catalog.validate_manifest("example", invalid))
    invalid = copy.deepcopy(value)
    invalid["plugin"] = invalid["commands"][0]
    rejects("mixed manifest formats", lambda: catalog.validate_manifest("example", invalid))
    invalid = copy.deepcopy(value)
    invalid["commands"] = []
    rejects("empty manifest commands", lambda: catalog.validate_manifest("example", invalid))


def check_package_titles_and_shared_requirements() -> None:
    source = MANIFEST.read_text().replace('display_name = "Resource summary"', 'display_name = "Certificate tools"')
    source = source.replace('requires = []', 'requires = ["cmctl"]\ninstall = "Install cmctl"')
    second = '''
[[commands]]
name = "Renew certificate"
palette = "cert-manager-renew"
command = "./adapter"
requires = ["cmctl", "kubectl"]
install = "Install cmctl"
output = "report"
mutating = true
confirm = true
'''
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        package = root / "certificate-tools"
        package.mkdir()
        original, catalog.PLUGINS = catalog.PLUGINS, root
        def publish(text):
            (package / "plugin.toml").write_text(text)
            return catalog.publication("certificate-tools")
        try:
            single = publish(source)
            multiple = publish(source + second)
            if single["display_name"] != "Certificate tools" or multiple["display_name"] != single["display_name"]:
                FAILURES.append("package title changed when a command was added")
            prefix, first = source.split("[[commands]]", 1)
            reordered = publish(prefix + second + "\n[[commands]]" + first)
            if reordered["display_name"] != "Certificate tools":
                FAILURES.append("package title changed when commands were reordered")
            expected = [{"name": "cmctl", "install": "Install cmctl"}, {"name": "kubectl", "install": "Install cmctl"}]
            if multiple["requirements"] != expected:
                FAILURES.append(f"shared requirements published as {multiple['requirements']!r}")
            rejects("conflicting command installation instructions", lambda: publish(source + second.replace("Install cmctl", "Install another tool")))
            explicit = '[package]\nrequirements = [{name = "cmctl", install = "Install the package tool", alternatives = ["kubectl-cm"]}, {name = "cmctl", install = "Install the package tool", alternatives = ["kubectl-cm"]}]'
            override = publish((source + second).replace("[package]", explicit))
            if override["requirements"] != [{"name": "cmctl", "install": "Install the package tool", "alternatives": ["kubectl-cm"]}]:
                FAILURES.append("explicit shared requirement metadata was lost or duplicated")
            conflicting = '[package]\nrequirements = [{name = "cmctl", install = "Install cmctl", alternatives = ["kubectl-cm"]}, {name = "cmctl", install = "Install cmctl"}]'
            rejects("conflicting package requirement alternatives", lambda: publish(source.replace("[package]", conflicting)))
            conflicting = '[package]\nrequirements = [{name = "cmctl", install = "Install cmctl"}, {name = "cmctl", install = "Install another tool"}]'
            rejects("conflicting package requirement instructions", lambda: publish(source.replace("[package]", conflicting)))
            identical = '[package]\nrequirements = [{name = "cmctl", install = "Install cmctl"}, {name = "cmctl", install = "Install cmctl", alternatives = []}]'
            if publish(source.replace("[package]", identical))["requirements"] != [{"name": "cmctl", "install": "Install cmctl"}]:
                FAILURES.append("an empty alternatives list prevented requirement aggregation")
            untitled = source.replace('display_name = "Certificate tools"\n', "")
            if publish(untitled)["display_name"] != "Resource summary":
                FAILURES.append("single-command package lost its display-name fallback")
            rejects("multiple commands without a package title", lambda: publish(untitled + second))
            for invalid in ['""', '"   "', 'false']:
                rejects("an invalid package title", lambda invalid=invalid: publish(source.replace('display_name = "Certificate tools"', f'display_name = {invalid}')))
            rejects("package title on an older Sofka client", lambda: publish(re.sub(r'sofka = "[^"]+"', 'sofka = ">=0.27.0"', source)))
            accepts("an untitled package for Sofka 0.27.0", lambda: publish(re.sub(r'sofka = "[^"]+"', 'sofka = ">=0.27.0"', untitled)))
        finally:
            catalog.PLUGINS = original
    value = command_index()
    value["plugins"][0]["versions"][0]["requirements"] = [{"name": "cmctl", "install": "Install cmctl"}] * 2
    rejects("duplicate published command requirements", lambda: catalog.validate_index(value))
    value["plugins"][0]["versions"][0]["requirements"][1] = {"name": "cmctl", "install": "Install another tool"}
    rejects("conflicting published command requirements", lambda: catalog.validate_index(value))


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

    for value in [">=0.27.1", "=0.27.1", "^0.27.1", "~0.27.1", ">0.27.0", ">0.27", ">=0.28", "1.*", ">=1", ">=0.27.1, <1", ">=0.27.1-alpha, >=0.27.1"]:
        if not catalog.requires_supported_sofka(value, (0, 27, 1, True)):
            FAILURES.append(f"rejected the package-title range {value!r}")
    for value in ["*", ">=0.27.0", "=0.26.0", "^0.27", "0.27.*", "~0.27.0", "<1", "<=0.27.1", ">0.26", ">=0.27.1-alpha", ">0.27.0, <0.27.1-beta", "latest"]:
        if catalog.requires_supported_sofka(value, (0, 27, 1, True)):
            FAILURES.append(f"accepted the incompatible package-title range {value!r}")

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
            "plugins/chaos-kill/plugin.toml\n": ["chaos-kill"],
            "plugins/oha/plugin.toml\n": ["oha"],
            "plugins/popeye/plugin.toml\n": ["popeye"],
            "plugins/trivy/plugin.toml\n": ["trivy"],
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


def check_pr_merge_catalog() -> None:
    with tempfile.TemporaryDirectory() as directory:
        repository = pathlib.Path(directory)
        run = lambda *argv: subprocess.run(argv, cwd=repository, check=True, capture_output=True)
        run("git", "init", "--quiet", "-b", "main")
        run("git", "config", "user.email", "catalog@example.invalid")
        run("git", "config", "user.name", "catalog")
        initial = commit(repository, {"plugins": []}, "empty catalog")
        run("git", "switch", "-c", "feature")
        (repository / "README.md").write_text("Plugin documentation.\n", encoding="utf-8")
        run("git", "add", "README.md")
        run("git", "-c", "commit.gpgsign=false", "commit", "-m", "documentation")
        feature = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
        run("git", "switch", "main")
        plugin = repository / "plugins" / "resource-summary"
        plugin.mkdir(parents=True)
        (plugin / "plugin.toml").write_text(MANIFEST.read_text(encoding="utf-8"), encoding="utf-8")
        run("git", "add", "plugins")
        published = json.loads(FIXTURE.read_text(encoding="utf-8"))
        base = commit(repository, published, "publish after feature branch")
        run("git", "-c", "commit.gpgsign=false", "merge", "--no-ff", "feature", "-m", "proposed merge")
        merged = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()

        original = catalog.ROOT, catalog.PLUGINS, catalog.INDEX
        catalog.ROOT, catalog.PLUGINS, catalog.INDEX = repository, repository / "plugins", repository / "index.json"
        try:
            rejects("the outdated branch catalog", lambda: catalog.assert_immutable(base, feature))
            accepts("the merged catalog with newer base entries", lambda: catalog.assert_unpublished(argparse.Namespace(base=base, head=merged)))
            if catalog.changed_plugins(base, merged, "publish"):
                FAILURES.append("the proposed merge selected a plugin added only on the base branch")
            if catalog.index_at(initial)["plugins"]:
                FAILURES.append("the regression branch did not start with an empty catalog")
            removed = commit(repository, {"plugins": []}, "delete published entries")
            rejects("a real catalog deletion after merge", lambda: catalog.assert_unpublished(argparse.Namespace(base=base, head=removed)))
            changed = copy.deepcopy(published)
            changed["plugins"][0]["versions"][0]["artifacts"][0]["blake3"] = "9" * 64
            repointed = commit(repository, changed, "change published digest")
            rejects("a real digest change after merge", lambda: catalog.assert_unpublished(argparse.Namespace(base=base, head=repointed)))
        finally:
            catalog.ROOT, catalog.PLUGINS, catalog.INDEX = original


def check_manual_publication() -> None:
    original_index = catalog.INDEX
    try:
        with tempfile.TemporaryDirectory() as directory:
            catalog.INDEX = pathlib.Path(directory) / "index.json"
            catalog.INDEX.write_text(json.dumps({"plugins": []}), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                catalog.manual_publication(argparse.Namespace(plugin="popeye"))
            plan = json.loads(output.getvalue())
            expected = [
                {"plugin": "popeye", "target": target, "os": catalog.TARGETS[target]}
                for target in catalog.publication("popeye")["platforms"]
            ]
            if plan != {"plugins": ["popeye"], "matrix": {"include": expected}}:
                FAILURES.append("manual publication did not select only Popeye's platforms")
            for plugin in ("", "missing-plugin", "../popeye", "popeye;echo injected"):
                rejects(f"manual publication of {plugin!r}", lambda plugin=plugin: catalog.manual_publication(argparse.Namespace(plugin=plugin)))
            version = catalog.publication("popeye")["version"]
            for status in ("active", "withdrawn"):
                catalog.INDEX.write_text(json.dumps({"plugins": [{"id": "popeye", "versions": [{"version": version, "status": status}]}]}), encoding="utf-8")
                rejects(f"manual publication of an {status} catalog version", lambda: catalog.manual_publication(argparse.Namespace(plugin="popeye")))
    finally:
        catalog.INDEX = original_index


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

        for platform in ("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"):
            target = out / f"{platform}.tar.zst"
            catalog.package(argparse.Namespace(plugin="resource-summary", target=platform, binary=str(binary), output=str(target)))
            data = zstandard.ZstdDecompressor().decompress(target.read_bytes(), max_output_size=64 << 20)
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                if "adapter.exe" not in archive.getnames() or "adapter" in archive.getnames():
                    FAILURES.append(f"{platform}: incorrect executable filename")
                if archive.extractfile("adapter.exe").read() != binary.read_bytes():
                    FAILURES.append(f"{platform}: changed binary bytes")
                if archive.extractfile("plugin.toml").read() != MANIFEST.read_bytes():
                    FAILURES.append(f"{platform}: changed source manifest")

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
        previous = json.loads(FIXTURE.read_text())
        index.write_text(json.dumps(previous))

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
            if catalog.releases(written).get(("resource-summary", "0.1.0")) != catalog.releases(previous).get(("resource-summary", "0.1.0")):
                FAILURES.append("command publication modified the existing release")
            if written["schema_version"] != 2:
                FAILURES.append("command publication did not set catalog schema 2")
            release = catalog.releases(written)[("resource-summary", version)]
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
        package, definitions = authored["package"], authored["commands"]
        derived = catalog.publication(plugin)
        expected = {
            "id": plugin,
            "display_name": package.get("display_name", definitions[0]["name"]),
            "description": package["description"],
            "publisher": ", ".join(package["authors"]),
            "repository": package["repository"],
            "version": package["version"],
            "sofka": package["sofka"],
            "license": package["license"],
            "readme": package["readme"],
            "tags": package.get("tags", []),
            "platforms": package["platforms"],
            "commands": [{
                "name": definition["name"], "palette": definition["palette"],
                "command": definition["command"], "args": definition.get("args", []),
                "scopes": definition.get("scopes", []), "target": definition.get("target", "selection"),
                "output": definition["output"], "mutating": definition["mutating"],
                "confirm": definition.get("confirm", False), "dangerous": definition.get("dangerous", False),
                "network_load": definition.get("network_load", False),
            } for definition in definitions],
            "requirements": package.get("requirements", [
                {"name": name, "install": definition.get("install", "")}
                for definition in definitions
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
    check_command_packages()
    check_package_titles_and_shared_requirements()
    check_schema_rules()
    check_version_ranges()
    check_manifest_rules()
    check_source_rules()
    check_selection()
    check_pr_merge_catalog()
    check_manual_publication()
    check_packaging()
    check_index_generation()
    check_immutability()
    for failure in FAILURES:
        print(f"catalog validation {failure}", file=sys.stderr)
    print(f"{len(FAILURES)} failures", file=sys.stderr)
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
