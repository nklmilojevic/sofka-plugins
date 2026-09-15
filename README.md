# sofka-plugins

This repository contains official, reviewed plugin packages for
[sofka](https://github.com/nklmilojevic/sofka).

Sofka reads the complete catalog from [`index.json`](index.json) once per
command. Package source remains under `plugins/<id>/`; compiled archives are
GitHub Release assets and are never committed to Git.

| Package                                        | Needs                                                                                                   |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [`cert-manager`](plugins/cert-manager)         | [cmctl](https://cert-manager.io/docs/reference/cmctl/) and `kubectl` on `PATH`; **renews certificates** |
| [`chaos-kill`](plugins/chaos-kill)             | `kubectl` on `PATH` — **deletes pods**                                                                  |
| [`oha`](plugins/oha)                           | [oha](https://github.com/hatoo/oha) on `PATH`                                                           |
| [`popeye`](plugins/popeye)                     | [Popeye](https://github.com/derailed/popeye) on `PATH`                                                  |
| [`trivy`](plugins/trivy)                       | [Trivy](https://trivy.dev) on `PATH`                                                                    |
| [`resource-summary`](plugins/resource-summary) | nothing                                                                                                 |

Packages use manifest schema `2` and require Sofka `>=0.27.1`. Each package can
contain several `[[commands]]` entries with separate inputs, scopes, and safety
settings. Publish these versions after Sofka adds schema 2 support.

The complete scope, design, and acceptance criteria are in
[sofka issue #502](https://github.com/nklmilojevic/sofka/issues/502).
The agreed proposal is in
[discussion #501](https://github.com/nklmilojevic/sofka/discussions/501).

See the existing [plugin authoring guide](https://github.com/nklmilojevic/sofka/blob/main/docs/plugin-authoring.md)
for the current package format.

## Local development

The Nix flake provides Rust, Cargo, Clippy, rustfmt, rust-analyzer, Python 3.12,
uv, Git, jq, and the Nix formatter. `flake.lock` pins the tool versions.

```sh
nix develop
uv sync --locked
uv run --locked python scripts/catalog.py validate
uv run --locked python scripts/test_catalog.py
```

Use `nix develop .#tools` when you also need kubectl, cmctl, oha, popeye, and
trivy. The default shell is enough for fixture tests.

For automatic setup, install direnv and enable its hook in your shell. Run
`direnv allow` in this directory after you review `.envrc`. It loads the Nix
shell, runs `uv sync --locked`, and activates `.venv`. nix-direnv is optional
and can cache the Nix environment. Dependency-file changes reload the environment.

Without Nix, install a Rust toolchain with Clippy and rustfmt, then use
`uv sync --locked`. uv selects Python 3.12 from `.python-version`.

Declare Python dependencies in `pyproject.toml` and commit `uv.lock`.
After a dependency change, update the lock and local environment:

```sh
uv lock
uv sync --locked
```

CI and publication also run Python through `uv run --locked`. `.venv`, `.direnv`, and
Nix result links are ignored by Git. See [AGENTS.md](AGENTS.md) for the plugin
workflow and required checks.

## Publishing a package

### Windows support

The Windows targets follow the published upstream tool binaries, checked on
2026-09-15:

| Adapter          | Required tool                                                                                                                                               | Windows x86_64 | Windows ARM64            |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- | ------------------------ |
| Resource summary | None                                                                                                                                                        | Yes            | Yes                      |
| cert-manager     | [cmctl 2.5.0](https://github.com/cert-manager/cmctl/releases/tag/v2.5.0), [kubectl 1.37.0](https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/) | Yes            | Yes                      |
| Chaos kill       | kubectl 1.37.0                                                                                                                                              | Yes            | Yes                      |
| Popeye           | [Popeye 0.22.1](https://github.com/derailed/popeye/releases/tag/v0.22.1)                                                                                    | Yes            | Yes                      |
| Trivy            | [Trivy 0.74.0](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0)                                                                                  | Yes            | No upstream ARM64 binary |
| HTTP benchmark   | [oha 1.16.0](https://github.com/hatoo/oha/releases/tag/v1.16.0)                                                                                             | Yes            | No upstream ARM64 binary |

Install the Windows tools listed by each package and put their `.exe` files on
`PATH`. ARM64 support is not declared for Trivy or oha based on x86_64 emulation.
CI runs adapter unit tests and saved fixtures on native runners. It checks the
packaged executable again after extraction. No live tool or cluster operation
is part of these tests.

Windows archives keep the `<plugin>-<version>-<target>.tar.zst` name and contain
`adapter.exe` with the static Microsoft C runtime. The authored manifest keeps
`command = "./adapter"`; Sofka resolves the suffix.

These package versions require Sofka 0.27.4 or later. Release the required Sofka
Windows plugin support before merging the package change: a merge that changes
package sources starts publication. Published catalog entries and assets stay
unchanged until new versions are published.

### Publication steps

1. Add or change one directory under `plugins/` and increment its semantic
   version in both `Cargo.toml` and the `[package]` table of `plugin.toml`.
2. Open a pull request. CI validates and builds only the changed packages for
   their supported platforms.
3. After merge, CI creates immutable release assets for each changed package.
4. CI opens a second pull request adding the exact asset sizes and BLAKE3
   digests to `index.json`. The package becomes discoverable only after that PR
   is reviewed and merged.

Changing only `index.json`, for example to withdraw a release, does not compile
any adapters. Published assets are never replaced; fixes use a new package
version.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the review and withdrawal rules.

To recover a failed publication with the current workflow, open Actions >
Publish changed plugins > Run workflow. Select `main` and enter one plugin ID,
such as `popeye`. The workflow validates and builds that package, publishes its
archives, and opens a catalog PR. Unknown IDs and versions already in the
catalog are rejected. Manual runs on other branches are skipped.

Rerunning an old run uses its original commit and workflow. Use the manual
trigger when recovery needs a workflow fix that was merged later.

Publication uses the automatic `GITHUB_TOKEN` with Contents and Pull requests
write permissions. No separate token secret is required. In the repository's
Settings > Actions > General > Workflow permissions, enable **Allow GitHub
Actions to create and approve pull requests**.

When the workflow creates or updates a catalog pull request, a maintainer with
write access must select **Approve workflows to run** on that pull request.
Wait for CI to pass, then review and merge the catalog change. See
[GitHub's token documentation](https://docs.github.com/en/actions/concepts/security/github_token).

Protect `main`, require the CI checks and code-owner review, and restrict
workflow changes to maintainers. Pull-request jobs have read-only permissions
and receive no publication credentials.
