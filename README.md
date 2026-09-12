# sofka-plugins

This repository contains official, reviewed plugin packages for
[sofka](https://github.com/nklmilojevic/sofka).

Sofka reads the complete catalog from [`index.json`](index.json) once per
command. Package source remains under `plugins/<id>/`; compiled archives are
GitHub Release assets and are never committed to Git.

| Package                                        | Needs   |
| ---------------------------------------------- | ------- |
| [`resource-summary`](plugins/resource-summary) | nothing |

The complete scope, design, and acceptance criteria are in
[sofka issue #502](https://github.com/nklmilojevic/sofka/issues/502).
The agreed proposal is in
[discussion #501](https://github.com/nklmilojevic/sofka/discussions/501).

See the existing [plugin authoring guide](https://github.com/nklmilojevic/sofka/blob/main/docs/plugin-authoring.md)
for the current package format.

## Publishing a package

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

Add a fine-grained `CATALOG_GITHUB_TOKEN` Actions secret with Contents and Pull
requests read/write access to this repository. It lets the post-merge workflow
publish releases and open an index pull request whose event runs normal CI.
Protect `main`, require the CI checks and code-owner review, and restrict
workflow changes to maintainers. Pull-request jobs have read-only permissions
and receive no publication credentials.
