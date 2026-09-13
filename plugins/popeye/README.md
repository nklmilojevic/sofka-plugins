# Popeye scan

Runs [Popeye](https://github.com/derailed/popeye) against the context and
namespace sofka is showing, and renders its JSON report as a sofka report: a
summary, then one section per linter with that linter's tally and findings.

Enter `:popeye` in sofka. The scan is read-only — it never changes a cluster —
so it stays available in read-only mode.

## Dependencies

Requires Sofka 0.27.2 or newer for live plugin activity.

Popeye itself, as `popeye` on `PATH`. Install it from the
[Popeye installation guide](https://github.com/derailed/popeye#installation).
Sofka reports the requirement and where to get it; it never installs external
tools for you.

The adapter runs Popeye with `--out json --force-exit-zero --log-level 0 --logs
none`, and with `--context` and `--namespace` taken from the sofka session, or
`--all-namespaces` when sofka is showing all namespaces. Popeye reads the same
kubeconfig sofka does and scans with your permissions.

## Live activity

The adapter reports scan start and completion on stderr and forwards available
Popeye diagnostics while the scan runs. Sofka's activity popup also shows elapsed
time. There is no estimated percentage or invented per-linter progress. Logging
flags stay unchanged, so quiet scans may only show the start message until they
finish. Forwarded diagnostics stop after 64 KiB with a notice; the adapter keeps
draining the pipe and preparing the report. Saved reports do not start a scan.
Stdout remains the same JSON report, with no schema change. If activity cannot
be written, capture and report processing continue. Child read and process
failures remain errors.

## Inputs

| Input    | Purpose                                                                     |
| -------- | --------------------------------------------------------------------------- |
| `report` | Render a saved Popeye JSON report from this path instead of running a scan. |

`:popeye report=/absolute/path/to/scan.json` is useful for reviewing a report
captured elsewhere. Sofka runs adapters from the package directory, so relative
paths do not resolve from the shell directory. The packaged fixture test uses
the same replay path internally; its `fixtures/scan.json` is an unedited
`popeye --out json` capture, so the field names it asserts are the ones Popeye
emits.

## Limitations

- A scan of a large cluster takes time. The manifest allows five minutes; sofka
  cancels the run at that point.
- The rendered report is bounded, and the whole report shares one allowance. A
  scan that raises more findings than it can hold ends with a truncation notice,
  and the linters after that point are left out. For an all-namespace scan,
  retry one namespace at a time; otherwise inspect the full Popeye JSON output.
- Findings come from Popeye. This package renders them; it does not add checks
  of its own, and a reviewed package is not a guarantee that Popeye has no
  defects.
