# Contributing plugins

Every package runs with the sofka user's permissions and inherited environment.
Review reduces risk, but does not provide a process sandbox or guarantee that an
external tool has no defects.

A plugin pull request must include its source, `plugin.toml`, README,
request/report fixtures, and tests. `plugin.toml` is the only authored
metadata: its `[package]` table names the version, authors, licence,
repository, supported sofka versions, and platforms, and publication generates
the catalog entry from it. The package ID is its directory name, and the
packaged adapter is `adapter` on Linux and macOS, and `adapter.exe` on Windows.
Keep the authored `command` as `./adapter`; Sofka resolves the Windows suffix.

Use manifest schema `2` and one or more `[[commands]]` entries. Each command has
its own full `palette` name, resource scopes, inputs, and safety flags. Keep input
tables under the command that uses them, with `[commands.inputs.NAME]`. Do not
add a `[plugin]` table. Command names, palette names, and nonempty key chords
must be unique within a package. All commands use `./adapter`; use `args` to
select the action when an adapter provides several actions.

Set `[package].display_name` to the package title shown in the catalog. The title
does not depend on the number or order of commands. A package with several
commands must declare this field. For a package with one command, the command's
name remains the fallback when the field is absent.

Publication combines command requirements by executable name. Repeated records
with the same metadata become one record. Conflicting installation instructions
or alternatives cause validation to fail. An explicit `[package].requirements`
list takes precedence over command requirements and follows the same rules.

Command packages require Sofka `>=0.27.1`. Publish them only after the Sofka
release that includes manifest schema 2 support. Installation, update, and
removal apply to the whole package. The adapter request and report protocols
still use schema version `1`.

Publication writes catalog schema `2`, with execution settings in each release's
`commands` array. Existing release records keep their original fields and bytes.
Older Sofka clients cannot read catalog schema 2. The new client reads both
catalog versions and both manifest versions.

Every package is published under this repository's `MIT OR Apache-2.0`; both
licence files ship inside every archive, so a package carries no licence file of
its own and `[package].license` must declare exactly that licence.
Maintainers review adapter behavior, execution and mutation flags, dependencies,
metadata, and workflow changes. Tests must use fixtures and must not need
production credentials.

Package IDs use lowercase ASCII letters, digits, and hyphens. Published versions
are immutable: CI compares the proposed merge result against the base branch
and rejects any change to an existing `index.json` record except a withdrawal.
Both plugin selection and catalog checks use this merge result, so an older PR
branch does not report newer base-branch entries as deleted. Increment the semantic
package version for every source or manifest change. Keep package versions, the
catalog schema version, and `plugin.toml` schema versions independent.

Use the [local development setup](README.md#local-development) for Nix, uv, and
direnv. Before opening a pull request, run `uv run --locked python scripts/catalog.py validate`
and `uv run --locked python scripts/test_catalog.py`. The development environment
and CI use Python 3.12.
Validation applies `index.schema.json` and the same manifest rules sofka applies
when it loads a package, so a package sofka would refuse never reaches review.

To withdraw a version, change its status in `index.json` to `withdrawn`, add a
`withdrawal_reason`, and open a pull request. Do not delete its release assets.
Sofka will refuse new installations while continuing to report existing ones.

Runtime requirements belong in `plugin.toml` and the package README.
Installers copy ready-to-run packages; they never install external tools or run
adapter code.
