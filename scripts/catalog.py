#!/usr/bin/env python3
"""Validate, package, and publish the single-file sofka plugin catalog."""

from __future__ import annotations

import argparse
import datetime
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib

# BLAKE3 has no standard-library implementation; the publish workflow installs
# the pinned wheel. Sofka verifies every artifact with the same digest.
import blake3
import zstandard

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGINS = ROOT / "plugins"
INDEX = ROOT / "index.json"
SCHEMA = ROOT / "index.schema.json"
RELEASE_ROOT = "https://github.com/nklmilojevic/sofka-plugins/releases/download/"
# Every package is published under the repository licence; see LICENSE-MIT and
# LICENSE-APACHE, both of which ship inside every archive.
LICENSE = "MIT OR Apache-2.0"
ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ZSTD = zstandard.ZstdCompressor(level=19, write_checksum=True)
U64_MAX = 2**64 - 1
SEMVER = re.compile(
    r"(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))?"
)
COMPARATOR = re.compile(
    r"(?P<op>\^|~|>=|<=|>|<|=)? *"
    r"(?P<major>[0-9]+)"
    r"(?:\.(?P<minor>[0-9]+|[xX*])(?:\.(?P<patch>[0-9]+|[xX*]))?)?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))? *"
)
TARGETS = {
    "x86_64-unknown-linux-gnu": "ubuntu-22.04",
    "aarch64-unknown-linux-gnu": "ubuntu-22.04-arm",
    "aarch64-apple-darwin": "macos-latest",
    "x86_64-apple-darwin": "macos-15-intel",
}
TARGET_MODES = {"selection", "context"}
OUTPUT_MODES = {"popup", "background", "report"}
FLAGS = ("mutating", "confirm", "dangerous", "network_load")

# plugin.toml rules, mirroring sofka's plugins::validate_plugin. Fields come
# from its config::Plugin and plugins::Input.
PLUGIN_FIELDS = {
    "args", "command", "confirm", "dangerous", "inputs", "install", "key",
    "mutating", "name", "network_load", "output", "palette", "port_forward",
    "requires", "scopes", "shell", "target", "timeout",
}
INPUT_FIELDS = {"choices", "default", "max", "min", "type"}
INPUT_TYPES = {"boolean", "duration", "integer", "string"}
PALETTE = re.compile(r"[a-z0-9-]+")
INPUT_NAME = re.compile(r"[a-z0-9_]+")
PLACEHOLDER = re.compile(r"\$\{input\.([a-z0-9_]*)\}")
DURATION = re.compile(r"([0-9]+)([smhd]?)")
UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
SOFKA_MINIMUM = (0, 26, 0, True)

# The palette names sofka's built-in commands own, mirrored from
# PALETTE_COMMANDS and plugin_command_reserved in sofka's src/app/mod.rs. Sofka
# is the authority and refuses a reserved command at load time; this copy only
# moves that refusal forward to review.
RESERVED = frozenset({
    "about", "actions", "adj", "adjacent", "audit", "bell", "bundle",
    "bundle-save", "bundle-write", "can", "can-i", "cani", "cfg", "clusters",
    "config", "context", "contexts", "ctx", "dashboard", "dbg", "dbgclean",
    "debug", "debug-clean", "debug-cleanup", "diag", "diagnose", "diagnostics",
    "diff", "dump", "dumps", "ephemeral", "event", "events", "explain", "fd",
    "find", "fleet", "flux", "forwards", "gitops", "helm", "history", "hm",
    "incident", "info", "journal", "multi", "notify", "pf", "plogs",
    "plugin-cancel", "portforwards", "providerlogs", "pu", "pulse",
    "pvc-browse", "pvc-clean", "pvc-cleanup", "pvc-explore", "q", "q!", "quit",
    "recon", "reconcile", "related", "reload", "rightsize", "sizing", "skin",
    "skins", "snap", "snapshot", "snapshots", "timeline", "tl", "vlogs", "vpa",
    "why", "x", "xray",
})

# The JSON Schema vocabulary index.schema.json is written in. Anything outside
# it is rejected rather than quietly ignored, so the schema cannot grow a
# constraint this validator does not apply.
SCHEMA_KEYWORDS = {
    "$defs", "$id", "$ref", "$schema", "additionalProperties", "const", "enum",
    "format", "items", "maximum", "minItems", "minLength", "minimum",
    "pattern", "properties", "required", "title", "type",
}
DATE_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})")
URI = re.compile(r"[a-z][a-z0-9+.-]*:.+")


def read_json(path: pathlib.Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def plugin_ids() -> list[str]:
    return sorted(path.name for path in PLUGINS.iterdir() if path.is_dir())


ADAPTER = "adapter"
PACKAGE_FIELDS = {"version", "authors", "license", "description", "repository", "readme", "sofka", "platforms", "tags", "requirements"}
REQUIRED_PACKAGE_FIELDS = {"version", "authors", "license", "description", "repository", "readme", "sofka", "platforms"}


def manifest(plugin: str) -> dict[str, object]:
    """The authored `plugin.toml`, validated, as `{"package": ..., "plugin": ...}`."""
    value = tomllib.loads((PLUGINS / plugin / "plugin.toml").read_text(encoding="utf-8"))
    validate_manifest(plugin, value)
    return value


def publication(plugin: str) -> dict[str, object]:
    """The catalog's view of a package: its `[package]` table flattened together
    with the execution fields the index records."""
    value = manifest(plugin)
    package, definition = value["package"], value["plugin"]
    return {
        "id": plugin,
        "display_name": definition["name"],
        "description": package["description"],
        "tags": package.get("tags", []),
        "publisher": ", ".join(package["authors"]),
        "repository": package["repository"],
        "version": package["version"],
        "sofka": package["sofka"],
        "license": package["license"],
        "readme": package["readme"],
        "requirements": package.get("requirements", [
            {"name": name, "install": definition.get("install", "")}
            for name in definition.get("requires", [])
        ]),
        "command": definition["command"],
        "target": definition.get("target", "selection"),
        "output": definition["output"],
        "mutating": definition["mutating"],
        "confirm": definition.get("confirm", False),
        "dangerous": definition.get("dangerous", False),
        "network_load": definition.get("network_load", False),
        "platforms": package["platforms"],
    }


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def required(value: dict[str, object], names: set[str], label: str) -> None:
    missing = sorted(names - value.keys())
    check(not missing, f"{label}: missing {', '.join(missing)}")


def exact_fields(value: dict[str, object], names: set[str], label: str) -> None:
    required(value, names, label)
    unknown = sorted(value.keys() - names)
    check(not unknown, f"{label}: unknown fields {', '.join(unknown)}")


def has_type(value: object, expected: str) -> bool:
    if expected == "boolean":
        return isinstance(value, bool)
    if expected in {"integer", "number"}:
        kind = int if expected == "integer" else (int, float)
        return isinstance(value, kind) and not isinstance(value, bool)
    return isinstance(value, {"object": dict, "array": list, "string": str}[expected])


def validate_schema(value: object, schema: dict[str, object], root: dict[str, object], where: str) -> None:
    """Check a document against the subset of JSON Schema index.schema.json uses."""
    unsupported = sorted(schema.keys() - SCHEMA_KEYWORDS)
    check(not unsupported, f"{where}: schema uses unsupported keywords {', '.join(unsupported)}")
    if "$ref" in schema:
        name = str(schema["$ref"]).removeprefix("#/$defs/")
        defined = root.get("$defs")
        definition = defined.get(name) if isinstance(defined, dict) else None
        check(isinstance(definition, dict), f"{where}: unknown schema reference {schema['$ref']}")
        validate_schema(value, definition, root, where)
        return
    if "type" in schema:
        check(has_type(value, str(schema["type"])), f"{where}: expected {schema['type']}")
    if "const" in schema:
        check(value == schema["const"], f"{where}: expected {schema['const']!r}")
    if "enum" in schema:
        check(value in schema["enum"], f"{where}: expected one of {', '.join(map(str, schema['enum']))}")
    if isinstance(value, str):
        if "pattern" in schema:
            check(re.search(str(schema["pattern"]), value) is not None, f"{where}: does not match {schema['pattern']}")
        if "minLength" in schema:
            check(len(value) >= schema["minLength"], f"{where}: shorter than {schema['minLength']}")
        if schema.get("format") == "date-time":
            check(DATE_TIME.fullmatch(value) is not None, f"{where}: not an RFC 3339 timestamp")
        if schema.get("format") == "uri":
            check(URI.fullmatch(value) is not None, f"{where}: not an absolute URI")
    if isinstance(value, list):
        if "minItems" in schema:
            check(len(value) >= schema["minItems"], f"{where}: needs at least {schema['minItems']} items")
        if "items" in schema:
            for position, item in enumerate(value):
                validate_schema(item, schema["items"], root, f"{where}[{position}]")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema:
            check(value >= schema["minimum"], f"{where}: below {schema['minimum']}")
        if "maximum" in schema:
            check(value <= schema["maximum"], f"{where}: above {schema['maximum']}")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required(value, set(schema.get("required", [])), where)
        if schema.get("additionalProperties") is False:
            unknown = sorted(value.keys() - properties.keys())
            check(not unknown, f"{where}: unknown fields {', '.join(unknown)}")
        for name, item in value.items():
            if name in properties:
                validate_schema(item, properties[name], root, f"{where}.{name}")


def duration(value: object) -> int | None:
    """Seconds, following sofka's providers::parse_lookback."""
    if not isinstance(value, str):
        return None
    match = DURATION.fullmatch(value.strip())
    if match is None:
        return None
    seconds = int(match.group(1)) * UNITS[match.group(2)]
    return seconds if seconds > 0 else None


def valid_number(value: str) -> bool:
    return bool(value) and (value == "0" or not value.startswith("0")) and int(value) <= U64_MAX


def valid_identifier(value: str, prerelease: bool) -> bool:
    parts = value.split(".")
    return all(
        part
        and all(character.isascii() and (character.isalnum() or character == "-") for character in part)
        and not (prerelease and part.isdigit() and len(part) > 1 and part.startswith("0"))
        for part in parts
    )


def valid_version(value: object) -> bool:
    if not isinstance(value, str) or (match := SEMVER.fullmatch(value)) is None:
        return False
    if not all(valid_number(match[name]) for name in ("major", "minor", "patch")):
        return False
    pre, build = match["pre"], match["build"]
    return (pre is None or valid_identifier(pre, True)) and (build is None or valid_identifier(build, False))


def valid_version_requirement(value: object) -> bool:
    """Match semver::VersionReq's grammar and u64 numeric bounds."""
    if not isinstance(value, str):
        return False
    text = value.lstrip(" ")
    if text.rstrip(" ") in {"*", "x", "X"}:
        return True
    parts = text.split(",")
    if not 0 < len(parts) < 32:
        return False
    for part in parts:
        match = COMPARATOR.fullmatch(part.lstrip(" "))
        if match is None or not valid_number(match["major"]):
            return False
        minor, patch = match["minor"], match["patch"]
        if minor is not None and minor not in {"*", "x", "X"} and not valid_number(minor):
            return False
        if patch is not None and patch not in {"*", "x", "X"} and not valid_number(patch):
            return False
        wildcard = minor in {"*", "x", "X"} or patch in {"*", "x", "X"}
        if minor in {"*", "x", "X"} and patch is not None and patch not in {"*", "x", "X"}:
            return False
        pre, build = match["pre"], match["build"]
        if (pre is not None or build is not None) and (patch is None or wildcard):
            return False
        if pre is not None and not valid_identifier(pre, True):
            return False
        if build is not None and not valid_identifier(build, False):
            return False
    return True


def requires_supported_sofka(value: object) -> bool:
    """A package must exclude every sofka release older than 0.26.0.

    VersionReq comparators are ANDed, so the strongest lower-bound comparator
    determines the earliest version the range can admit. The final boolean in
    a bound sorts prereleases below the corresponding stable release.
    """
    if not valid_version_requirement(value) or not isinstance(value, str):
        return False
    if value.lstrip(" ").rstrip(" ") in {"*", "x", "X"}:
        return False
    lower_bounds: list[tuple[int, int, int, bool]] = []
    for part in value.lstrip(" ").split(","):
        match = COMPARATOR.fullmatch(part.lstrip(" "))
        if match is None or match["op"] in {"<", "<="}:
            continue
        minor = match["minor"]
        patch = match["patch"]
        lower_bounds.append((
            int(match["major"]),
            int(minor) if minor is not None and minor not in {"*", "x", "X"} else 0,
            int(patch) if patch is not None and patch not in {"*", "x", "X"} else 0,
            match["pre"] is None,
        ))
    return bool(lower_bounds) and max(lower_bounds) >= SOFKA_MINIMUM


def validate_requirement(requirement: object, label: str) -> None:
    check(isinstance(requirement, dict), f"{label}: invalid requirement")
    fields = {"name", "alternatives", "install"}
    required(requirement, {"name", "install"}, f"{label} requirement")
    check(not (requirement.keys() - fields), f"{label} requirement: unknown fields")
    name = requirement["name"]
    alternatives = requirement.get("alternatives", [])
    check(isinstance(name, str) and name.strip() != "", f"{label}: empty requirement")
    check(isinstance(requirement["install"], str) and requirement["install"].strip() != "", f"{label}: empty requirement")
    check(
        isinstance(alternatives, list)
        and all(isinstance(item, str) and item.strip() for item in alternatives),
        f"{label}: invalid requirement alternatives",
    )
    check(len(set(alternatives)) == len(alternatives) and name not in alternatives, f"{label}: duplicate requirement alternative")


def validate_execution(value: dict[str, object], label: str, published: bool = True) -> None:
    """The runtime fields an authored package and its catalog release record
    share. A manifest names its README by filename; publication turns that into
    a URL at the exact source commit."""
    check(valid_version_requirement(value["sofka"]), f"{label}: invalid sofka version requirement")
    check(requires_supported_sofka(value["sofka"]), f"{label}: sofka requirement must exclude versions older than 0.26.0")
    check(isinstance(value["license"], str) and value["license"].strip() != "", f"{label}: empty license")
    if published:
        check(isinstance(value["readme"], str) and value["readme"].startswith("https://"), f"{label}: README must use HTTPS")
    check(isinstance(value["command"], str) and value["command"].strip() != "", f"{label}: empty command")
    check(value["target"] in TARGET_MODES, f"{label}: target must be selection or context")
    check(value["output"] in OUTPUT_MODES, f"{label}: output must be popup, background or report")
    for flag in FLAGS:
        check(isinstance(value[flag], bool), f"{label}: {flag} must be a boolean")
    check(isinstance(value["requirements"], list), f"{label}: requirements must be an array")
    for requirement in value["requirements"]:
        validate_requirement(requirement, label)


def validate_index(index: dict[str, object]) -> None:
    check(set(index) == {"schema_version", "generated_at", "plugins"}, "index has unknown or missing fields")
    check(index["schema_version"] == 1, "index schema_version must be 1")
    check(isinstance(index["generated_at"], str), "index generated_at must be a string")
    check(isinstance(index["plugins"], list), "index plugins must be an array")
    seen_ids: set[str] = set()
    for plugin in index["plugins"]:
        check(isinstance(plugin, dict), "index plugin must be an object")
        plugin_fields = {"id", "display_name", "description", "tags", "publisher", "repository", "versions"}
        exact_fields(plugin, plugin_fields, "plugin")
        plugin_id = plugin["id"]
        check(isinstance(plugin_id, str) and ID.fullmatch(plugin_id) is not None, f"invalid plugin ID {plugin_id!r}")
        check(plugin_id not in seen_ids, f"duplicate plugin ID {plugin_id}")
        seen_ids.add(plugin_id)
        for field in ("display_name", "description", "publisher"):
            check(isinstance(plugin[field], str) and plugin[field].strip() != "", f"{plugin_id}: empty {field}")
        check(isinstance(plugin["tags"], list) and all(isinstance(tag, str) for tag in plugin["tags"]), f"{plugin_id}: tags must be strings")
        check(isinstance(plugin["repository"], str) and plugin["repository"].startswith("https://"), f"{plugin_id}: repository must use HTTPS")
        check(isinstance(plugin["versions"], list), f"{plugin_id}: versions must be an array")
        seen_versions: set[str] = set()
        for release in plugin["versions"]:
            check(isinstance(release, dict), f"{plugin_id}: version must be an object")
            release_fields = {"version", "sofka", "source_commit", "license", "readme", "requirements", "command", "target", "output", "mutating", "confirm", "dangerous", "network_load", "status", "withdrawal_reason", "artifacts"}
            required(release, release_fields - {"withdrawal_reason"}, f"{plugin_id} version")
            check(not (release.keys() - release_fields), f"{plugin_id} version: unknown fields")
            version = release["version"]
            check(valid_version(version), f"{plugin_id}: invalid version")
            check(version not in seen_versions, f"{plugin_id}: duplicate version {version}")
            seen_versions.add(version)
            check(re.fullmatch(r"[0-9a-f]{40}", str(release["source_commit"])) is not None, f"{plugin_id}@{version}: invalid source commit")
            validate_execution(release, f"{plugin_id}@{version}")
            check(release["status"] in {"active", "withdrawn"}, f"{plugin_id}@{version}: invalid status")
            if release["status"] == "withdrawn":
                reason = release.get("withdrawal_reason")
                check(isinstance(reason, str) and reason.strip() != "", f"{plugin_id}@{version}: withdrawal needs a reason")
            else:
                check("withdrawal_reason" not in release, f"{plugin_id}@{version}: active version has withdrawal_reason")
            artifacts = release["artifacts"]
            check(isinstance(artifacts, list) and artifacts, f"{plugin_id}@{version}: no artifacts")
            platforms: set[str] = set()
            for artifact in artifacts:
                exact_fields(artifact, {"platform", "url", "blake3", "size"}, f"{plugin_id}@{version} artifact")
                platform = artifact["platform"]
                check(platform == "any" or platform in TARGETS, f"{plugin_id}@{version}: unsupported platform {platform}")
                check(platform not in platforms, f"{plugin_id}@{version}: duplicate platform {platform}")
                platforms.add(platform)
                check(str(artifact["url"]).startswith(RELEASE_ROOT), f"{plugin_id}@{version}: external artifact URL")
                check(re.fullmatch(r"[0-9a-f]{64}", str(artifact["blake3"])) is not None, f"{plugin_id}@{version}: invalid digest")
                check(isinstance(artifact["size"], int) and not isinstance(artifact["size"], bool) and 0 < artifact["size"] <= 50 * 1024 * 1024, f"{plugin_id}@{version}: invalid size")


def input_value(spec: dict[str, object], value: str) -> bool:
    """Follow sofka's plugins::Input::validate for a declared input value."""
    kind = spec.get("type")
    number = None
    if kind == "boolean":
        if value not in {"true", "false"}:
            return False
    elif kind == "integer":
        if not value.isdigit():
            return False
        number = int(value)
    elif kind == "duration":
        number = duration(value)
        if number is None:
            return False
    elif kind != "string":
        return False
    if number is not None:
        low, high = spec.get("min"), spec.get("max")
        if isinstance(low, int) and not isinstance(low, bool) and number < low:
            return False
        if isinstance(high, int) and not isinstance(high, bool) and number > high:
            return False
    choices = spec.get("choices") or []
    return not choices or value in choices


def validate_manifest(plugin: str, manifest: dict[str, object]) -> dict[str, object]:
    """Apply the package rules from sofka's plugins::validate_plugin, so a package
    sofka would refuse to load never reaches the catalog."""
    check(set(manifest) <= {"schema_version", "package", "plugin"}, f"{plugin}: unknown plugin.toml tables")
    check(manifest.get("schema_version") == 1, f"{plugin}: plugin.toml schema must be 1")
    package = manifest.get("package")
    check(isinstance(package, dict), f"{plugin}: plugin.toml needs a [package] table to be published")
    required(package, REQUIRED_PACKAGE_FIELDS, f"{plugin} package")
    unknown_package = sorted(package.keys() - PACKAGE_FIELDS)
    check(not unknown_package, f"{plugin} package: unknown fields {', '.join(unknown_package)}")
    requirements = package.get("requirements", [])
    check(isinstance(requirements, list), f"{plugin}: package requirements must be an array")
    for requirement in requirements:
        validate_requirement(requirement, f"{plugin} package")
    definition = manifest.get("plugin")
    check(isinstance(definition, dict), f"{plugin}: plugin.toml needs a [plugin] table")
    unknown = sorted(definition.keys() - PLUGIN_FIELDS)
    check(not unknown, f"{plugin}: unknown manifest fields {', '.join(unknown)}")
    for field in ("name", "command"):
        value = definition.get(field)
        check(isinstance(value, str) and value.strip() != "", f"{plugin}: manifest {field} must not be empty")
    palette = definition.get("palette")
    check(palette is not None or definition.get("key"), f"{plugin}: manifest needs a palette command or a key")
    if palette is not None:
        check(isinstance(palette, str) and PALETTE.fullmatch(palette) is not None, f"{plugin}: palette must contain lowercase letters, digits or hyphens")
        check(palette not in RESERVED, f"{plugin}: palette command {palette!r} is reserved by sofka")
    target = definition.get("target", "selection")
    check(target in TARGET_MODES, f"{plugin}: target must be selection or context")
    check(definition.get("output") in OUTPUT_MODES, f"{plugin}: packages require captured output: popup, background or report")
    check(definition.get("shell") is not True, f"{plugin}: packages must use an executable adapter, not shell = true")
    if "port_forward" in definition:
        check(target == "selection" and definition.get("output") == "report", f"{plugin}: port_forward requires target = selection and output = report")
    if "timeout" in definition:
        check(duration(definition["timeout"]) is not None, f"{plugin}: invalid timeout {definition['timeout']!r}")
    for field in ("args", "requires", "scopes"):
        values = definition.get(field, [])
        check(isinstance(values, list) and all(isinstance(value, str) for value in values), f"{plugin}: {field} must be an array of strings")
    for field in ("confirm", "dangerous", "network_load", "shell"):
        check(isinstance(definition.get(field, False), bool), f"{plugin}: {field} must be a boolean")
    check(isinstance(definition.get("mutating", False), bool), f"{plugin}: mutating must be a boolean")
    inputs = definition.get("inputs", {})
    check(isinstance(inputs, dict), f"{plugin}: inputs must be a table")
    for name, spec in inputs.items():
        label = f"{plugin} input {name!r}"
        check(isinstance(spec, dict), f"{label}: must be a table")
        unknown = sorted(spec.keys() - INPUT_FIELDS)
        check(not unknown, f"{label}: unknown fields {', '.join(unknown)}")
        check(INPUT_NAME.fullmatch(name) is not None, f"{label}: invalid input name")
        check(spec.get("type") in INPUT_TYPES, f"{label}: unsupported input type")
        for bound in ("min", "max"):
            if bound in spec:
                check(isinstance(spec[bound], int) and not isinstance(spec[bound], bool), f"{label}: {bound} must be an integer")
                check(spec["type"] in {"integer", "duration"}, f"{label}: min/max require integer or duration")
        if "min" in spec and "max" in spec:
            check(spec["min"] <= spec["max"], f"{label}: min exceeds max")
        check(isinstance(spec.get("choices", []), list), f"{label}: choices must be an array")
        if "default" in spec:
            check(isinstance(spec["default"], str), f"{label}: default must be a string")
            check(input_value(spec, spec["default"]), f"{label}: invalid default {spec['default']!r}")
    arguments = list(definition.get("args", []))
    if "port_forward" in definition:
        arguments.append(definition["port_forward"])
    for argument in arguments:
        if "${input." in str(argument):
            match = PLACEHOLDER.fullmatch(str(argument))
            check(match is not None and match.group(1) in inputs, f"{plugin}: invalid input placeholder {argument!r}; use a declared input as a whole argument")
    return definition


def validate_sources(index: dict[str, object]) -> None:
    source_ids = set(plugin_ids())
    indexed_ids = {plugin["id"] for plugin in index["plugins"]}
    missing_sources = indexed_ids - source_ids
    check(not missing_sources, f"published plugin source is missing: {', '.join(sorted(missing_sources))}")
    for plugin in plugin_ids():
        path = PLUGINS / plugin
        check(ID.fullmatch(plugin) is not None, f"invalid plugin directory {plugin!r}")
        definition = manifest(plugin)["plugin"]
        metadata = publication(plugin)
        check(valid_version(metadata["version"]), f"{plugin}: invalid version")
        cargo = tomllib.loads((path / "Cargo.toml").read_text(encoding="utf-8"))
        check(cargo["package"]["version"] == metadata["version"], f"{plugin}: Cargo and plugin.toml versions differ")
        cargo_license = cargo["package"].get("license")
        if isinstance(cargo_license, dict) and cargo_license.get("workspace") is True:
            workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
            cargo_license = workspace["workspace"]["package"]["license"]
        check(cargo_license == metadata["license"], f"{plugin}: Cargo and plugin.toml licenses differ")
        validate_execution(metadata, f"{plugin} package", published=False)
        # The archive always names the adapter the same thing, so the manifest
        # has exactly one correct spelling of its own command.
        check(definition["command"] == f"./{ADAPTER}", f"{plugin}: command must be ./{ADAPTER}")
        check("mutating" in definition, f"{plugin}: declare mutating explicitly")
        check(all(not name.startswith("./") for name in definition.get("requires", [])), f"{plugin}: requires must name tools on PATH, not package files")
        if definition.get("requires"):
            check(bool(str(definition.get("install", "")).strip()), f"{plugin}: requires needs install instructions")
        check(metadata["readme"] == "README.md", f"{plugin}: readme must be README.md")
        check((path / "README.md").is_file(), f"{plugin}: missing README.md")
        # Every package is published under the repository's dual licence, which
        # ships in each archive; a package-local copy would only go stale.
        check(not (path / "LICENSE").exists(), f"{plugin}: remove LICENSE; the repository licence covers every package")
        check(metadata["license"] == LICENSE, f"{plugin}: license must be {LICENSE}")
        check(metadata["repository"].startswith("https://github.com/"), f"{plugin}: repository must be a GitHub HTTPS URL")
        check((path / "fixtures" / "request.json").is_file(), f"{plugin}: missing request fixture")
        check((path / "fixtures" / "report.json").is_file(), f"{plugin}: missing report fixture")
        platforms = metadata["platforms"]
        check(isinstance(platforms, list) and platforms, f"{plugin}: no platforms")
        check(all(platform in TARGETS for platform in platforms), f"{plugin}: unsupported platform")


def changed_plugins(base: str, head: str, mode: str) -> list[str]:
    command = ["git", "diff", "--name-only", base, head]
    paths = subprocess.check_output(command, cwd=ROOT, text=True).splitlines()
    changed = {
        parts[1]
        for name in paths
        if len(parts := pathlib.PurePosixPath(name).parts) >= 2 and parts[0] == "plugins"
    }
    if mode == "test" and any(
        name in {"Cargo.toml", "Cargo.lock"}
        or name.startswith(("scripts/", ".github/workflows/"))
        or (name.endswith(".rs") and not name.startswith("plugins/"))
        for name in paths
    ):
        changed.update(plugin_ids())
    known = set(plugin_ids())
    return sorted(changed & known)


def changes(args: argparse.Namespace) -> None:
    plugins = changed_plugins(args.base, args.head, args.mode)
    include = []
    for plugin in plugins:
        metadata = publication(plugin)
        for target in metadata["platforms"]:
            include.append({"plugin": plugin, "target": target, "os": TARGETS[target]})
    print(json.dumps({"plugins": plugins, "matrix": {"include": include}}, separators=(",", ":")))


def index_at(ref: str) -> dict[str, object]:
    """The catalog as of a commit. A ref that is missing from the checkout is an
    error; a ref that predates the catalog is not."""
    listed = subprocess.check_output(["git", "ls-tree", "--name-only", ref, "index.json"], cwd=ROOT, text=True)
    if not listed.strip():
        return {"plugins": []}
    index = json.loads(subprocess.check_output(["git", "show", f"{ref}:index.json"], cwd=ROOT, text=True))
    check(isinstance(index, dict) and isinstance(index.get("plugins"), list), f"{ref}: index.json is not a catalog")
    return index


def releases(index: dict[str, object]) -> dict[tuple[str, str], dict[str, object]]:
    return {
        (plugin["id"], release["version"]): release
        for plugin in index["plugins"]
        for release in plugin["versions"]
    }


def assert_unpublished(args: argparse.Namespace) -> None:
    published = releases(read_json(INDEX))
    for plugin in changed_plugins(args.base, args.head, "publish"):
        version = publication(plugin)["version"]
        check((plugin, version) not in published, f"{plugin}@{version} is already published; increment its version")
    assert_immutable(args.base, args.head)


def assert_immutable(base: str, head: str) -> None:
    """A published version record is permanent. Only withdrawal may be added to
    one, and no release may be dropped: the client pins installations to these
    digests and commits, so an index-only change could otherwise repoint them."""
    before = releases(index_at(base))
    after = releases(index_at(head))
    for key, release in before.items():
        name = "{}@{}".format(*key)
        updated = after.get(key)
        check(updated is not None, f"{name} was dropped from the index; withdraw the version instead")
        fields = (release.keys() | updated.keys()) - {"status", "withdrawal_reason"}
        changed = sorted(field for field in fields if release.get(field) != updated.get(field))
        check(not changed, f"{name} is published; {', '.join(changed)} cannot change")
        check((release["status"], updated["status"]) != ("withdrawn", "active"), f"{name} is withdrawn; withdrawal cannot be reversed")
        if updated["status"] == "withdrawn":
            reason = updated.get("withdrawal_reason")
            check(isinstance(reason, str) and reason.strip() != "", f"{name}: withdrawal needs a reason")


def version(args: argparse.Namespace) -> None:
    """The package release version, for workflows that name asset files."""
    print(manifest(args.plugin)["package"]["version"])


def package(args: argparse.Namespace) -> None:
    plugin = args.plugin
    metadata = publication(plugin)
    check(args.target in metadata["platforms"], f"{plugin}: unsupported target {args.target}")
    binary = pathlib.Path(args.binary)
    check(binary.is_file(), f"missing adapter binary {binary}")
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    files = [
        (PLUGINS / plugin / "plugin.toml", "plugin.toml", 0o644),
        (PLUGINS / plugin / "README.md", "README.md", 0o644),
        (ROOT / "LICENSE-MIT", "LICENSE-MIT", 0o644),
        (ROOT / "LICENSE-APACHE", "LICENSE-APACHE", 0o644),
        (binary, ADAPTER, 0o755),
    ]
    with output.open("wb") as raw:
        # Level 19 at a pinned zstandard: ~20% smaller than gzip on a package
        # this size, and sofka decompresses it two to three times faster.
        with ZSTD.stream_writer(raw, closefd=False) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for source, name, mode in files:
                    data = source.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))


def update_index(args: argparse.Namespace) -> None:
    index = read_json(INDEX)
    by_id = {plugin["id"]: plugin for plugin in index["plugins"]}
    assets = pathlib.Path(args.assets)
    for plugin_id in args.plugins:
        metadata = publication(plugin_id)
        version = metadata["version"]
        tag = f"{plugin_id}-v{version}"
        artifacts = []
        for platform in metadata.pop("platforms"):
            name = f"{plugin_id}-{version}-{platform}.tar.zst"
            path = assets / name
            check(path.is_file(), f"missing published asset {name}")
            data = path.read_bytes()
            artifacts.append({
                "platform": platform,
                "url": f"{RELEASE_ROOT}{tag}/{name}",
                "blake3": blake3.blake3(data).hexdigest(),
                "size": len(data),
            })
        identity = {key: metadata.pop(key) for key in ("id", "display_name", "description", "tags", "publisher", "repository")}
        release = dict(metadata)
        release.update({
            "source_commit": args.commit,
            "status": "active",
            "artifacts": artifacts,
        })
        release["readme"] = f"{identity['repository']}/blob/{args.commit}/plugins/{plugin_id}/{release['readme']}"
        plugin = by_id.get(plugin_id)
        if plugin is None:
            plugin = {**identity, "versions": []}
            index["plugins"].append(plugin)
            by_id[plugin_id] = plugin
        else:
            for key, value in identity.items():
                plugin[key] = value
        existing = next((item for item in plugin["versions"] if item["version"] == version), None)
        if existing is not None:
            check(existing == release, f"{plugin_id}@{version} already exists with different bytes")
        else:
            plugin["versions"].append(release)
    index["plugins"].sort(key=lambda plugin: plugin["id"])
    index["generated_at"] = datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    validate_index(index)
    temporary = INDEX.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, INDEX)


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    change = commands.add_parser("changes")
    change.add_argument("--base", required=True)
    change.add_argument("--head", required=True)
    change.add_argument("--mode", choices=("test", "publish"), required=True)
    unpublished = commands.add_parser("assert-unpublished")
    unpublished.add_argument("--base", required=True)
    unpublished.add_argument("--head", required=True)
    released = commands.add_parser("version")
    released.add_argument("--plugin", required=True)
    packaging = commands.add_parser("package")
    packaging.add_argument("--plugin", required=True)
    packaging.add_argument("--target", required=True)
    packaging.add_argument("--binary", required=True)
    packaging.add_argument("--output", required=True)
    update = commands.add_parser("update-index")
    update.add_argument("--commit", required=True)
    update.add_argument("--assets", required=True)
    update.add_argument("plugins", nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "validate":
            index = read_json(INDEX)
            check(isinstance(index, dict), "index must be an object")
            validate_index(index)
            example = read_json(ROOT / "fixtures" / "index.json")
            check(isinstance(example, dict), "index fixture must be an object")
            validate_index(example)
            schema = read_json(SCHEMA)
            check(isinstance(schema, dict), "schema must be an object")
            validate_schema(index, schema, schema, "index")
            validate_schema(example, schema, schema, "index fixture")
            validate_sources(index)
        elif args.command == "changes":
            changes(args)
        elif args.command == "assert-unpublished":
            assert_unpublished(args)
        elif args.command == "version":
            version(args)
        elif args.command == "package":
            package(args)
        elif args.command == "update-index":
            update_index(args)
    except (KeyError, OSError, subprocess.CalledProcessError, tomllib.TOMLDecodeError, ValueError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
