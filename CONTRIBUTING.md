# Contributing plugins

Every package runs with the sofka user's permissions and inherited environment.
Review reduces risk, but does not provide a process sandbox or guarantee that an
external tool has no defects.

A plugin pull request must include its source, `plugin.toml`, README,
request/report fixtures, and tests. `plugin.toml` is the only authored
metadata: its `[package]` table names the version, authors, licence,
repository, supported sofka versions, and platforms, and publication generates
the catalog entry from it. The package ID is its directory name, and the
packaged adapter is always `adapter`, so `command` is `./adapter`.
Every package is published under this repository's `MIT OR Apache-2.0`; both
licence files ship inside every archive, so a package carries no licence file of
its own and `[package].license` must declare exactly that licence.
Maintainers review adapter behavior, execution and mutation flags, dependencies,
metadata, and workflow changes. Tests must use fixtures and must not need
production credentials.

Package IDs use lowercase ASCII letters, digits, and hyphens. Published versions
are immutable: CI compares every existing `index.json` record against the base
branch and rejects any change to one except a withdrawal. Increment the semantic
package version for every source or manifest change. Keep package versions, the
catalog schema version, and `plugin.toml` schema versions independent.

Before opening a pull request, run `python3 scripts/catalog.py validate` and
`python3 scripts/test_catalog.py`. Both need Python 3.11 or newer; CI pins 3.12.
Validation applies `index.schema.json` and the same manifest rules sofka applies
when it loads a package, so a package sofka would refuse never reaches review.

To withdraw a version, change its status in `index.json` to `withdrawn`, add a
`withdrawal_reason`, and open a pull request. Do not delete its release assets.
Sofka will refuse new installations while continuing to report existing ones.

Runtime requirements belong in `plugin.toml` and the package README.
Installers copy ready-to-run packages; they never install external tools or run
adapter code.
