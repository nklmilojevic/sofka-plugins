# Instructions for agents

This repository contains Sofka plugin packages and the official catalog.
Use these instructions for all work here. Keep shared instructions in this file;
`CLAUDE.md` imports it.

## Writing and work scope

- Use ASD-STE100 Simplified Technical English in user-facing text and comments.
- Do not use em dashes.
- Complete the requested work and required checks. Keep optional changes separate.
- Search specific paths first with `rg`. Read only the files needed for the task.
- Reuse valid results. Run independent checks together when safe.
- Use subagents only when the user or a task skill requires them.
- Preserve unrelated changes. Keep sandbox and approval controls. Do not print secrets.

## Start with an existing package

Read [CONTRIBUTING.md](CONTRIBUTING.md) for package and publication rules.
Use one relevant package as a starting point:

- `plugins/resource-summary`: a small report adapter without external tools.
- `plugins/popeye` or `plugins/trivy`: external tools, saved reports, bounded reads,
  and error handling.
- `plugins/oha`: a managed port-forward and network load.
- `plugins/chaos-kill`: resource changes, confirmation, and a safe dry-run default.

Read the [Sofka authoring guide](https://github.com/nklmilojevic/sofka/blob/main/docs/plugin-authoring.md)
when the request or report protocol needs clarification. The `sofka` repository
owns runtime behavior; this repository owns package source and catalog publication.

## Add or change a package

1. Use `plugins/<id>/`, with lowercase letters, digits, and hyphens in the ID.
2. Add `Cargo.toml`, `plugin.toml`, `README.md`, `src/main.rs`, and
   `fixtures/request.json` plus `fixtures/report.json`. Add saved tool output when
   a fixture needs it.
3. Name the Rust crate `sofka-plugin-<id>`. Add it to the root Cargo workspace.
   Use the workspace edition and license. Keep `publish = false`.
4. Use manifest schema `2`, a `[package]` table, and `[[commands]]` entries.
   Copy the required package fields from an existing manifest. Declare a stable
   `display_name` and require Sofka `>=0.27.1` when this field is present.
5. Use one package for related commands. Each command has its own full `palette`
   name, scopes, inputs, timeout, and safety flags. Names, palette names, and
   nonempty key chords must be unique within the package.
6. Set each executable to `./adapter`. For several actions, select the action with
   `args` and handle it in the adapter. Place `[commands.inputs.NAME]` tables below
   the command that uses them. Do not use `[plugin]` or `[[plugins]]` in a package.
7. Declare external tools in `requires`, with installation instructions in
   `install` and the README. Shared requirements must have consistent metadata.
   Use `[package].requirements` to specify a package-wide list or alternatives.
8. For a change to package source or its manifest, use an unpublished version in
   both Cargo.toml and plugin.toml. Regenerate Cargo.lock with Cargo when needed;
   do not edit it by hand. A new package normally starts at `0.1.0`.

Do not add a package-local license file. Publication includes the root MIT and
Apache license files. Do not create a separate publication metadata file.

## Adapter behavior

- Read one request from stdin and write one JSON report to stdout. Request and
  report schema versions remain `1`, separate from manifest schema `2`.
- Send diagnostics to stderr and exit with a failure status on errors.
- Bound request, replay-file, and subprocess reads. Continue to drain subprocess
  pipes after the capture limit, or stop the process with a clear error. Propagate
  read failures and subprocess failures.
- Pass tool arguments separately. Packages cannot use `shell = true` or terminal
  output. Do not detach child processes from Sofka's process group.
- Declare `mutating` explicitly for each command. Use `confirm` for resource
  changes. Declare `network_load` for load tests. Validate the selected API group,
  kind, name, namespace, and context before a command changes a resource.
- Keep fixtures deterministic and independent of a cluster. Use saved input or
  mocked tools. Do not run live resource changes unless the user requests them.

## Checks

Install the pinned Python dependencies from `scripts/requirements.txt` in an
isolated environment. For package or catalog changes, run from the repository root:

```sh
python3 scripts/catalog.py validate
python3 scripts/test_catalog.py
```

For Rust or Cargo changes, also run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Build each changed adapter and run it on its request fixture. Compare the parsed
JSON output with its report fixture. Test each action when a package has several
commands. Cover invalid inputs and tool failures as well as successful output.

For manifest or protocol changes, use a compatible Sofka build to validate the
staged package with `--validate-plugin DIR` and the report with
`--validate-plugin-report FILE`. Report missing external tools or any stubs used.
Never run an adapter merely to discover its metadata.

After committing package changes, run `scripts/catalog.py assert-unpublished`
with the PR base and head refs. CI in `.github/workflows/ci.yaml` is the authority
for required checks. Repeat checks after relevant changes or failures; reuse
results for code that has not changed.

## Publication and handoff

- `plugin.toml` is the source of authored metadata. `scripts/catalog.py` generates
  release metadata, archive sizes, and digests.
- Do not replace published assets or edit published release records. Withdraw a
  bad version and publish a new version. Keep legacy records intact.
- Merge and release required Sofka support before publishing packages that need it.
- Package publication creates a separate catalog PR. Do not add invented release
  URLs, commits, sizes, or digests to `index.json`.
- Keep PR descriptions short: the problem, resulting behavior, checks, and limits.
  Report whether live tools or a cluster were used.
