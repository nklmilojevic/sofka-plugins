# Trivy scan

Runs [Trivy](https://trivy.dev) against the context and namespace sofka is
showing, and renders its Kubernetes report as a sofka report: a summary of
findings by severity, then one section per affected resource listing its
vulnerabilities, misconfigurations, and secrets.

Enter `:trivy` in sofka. The scan is read-only — it never changes a cluster —
so it stays available in read-only mode.

## Dependencies

Requires Sofka 0.27.2 or newer for live plugin activity.

Trivy 0.63 or newer, as `trivy` on `PATH`. The minimum version is required for
the telemetry control used by this package. See the
[Trivy installation guide](https://trivy.dev/latest/getting-started/installation/).
Sofka reports the requirement and where to get it; it never installs external
tools for you.

The adapter runs `trivy kubernetes --format json --report all`, with
telemetry, the version check, and the node collector turned off. It passes
`--no-progress`, but Trivy 0.74 still emits Kubernetes worker progress on stderr.
It pins a zero findings exit code and a 29-minute Trivy timeout below
sofka's 30-minute deadline. `--include-namespaces` comes from the sofka session,
and the kubeconfig context is passed after `--`. Trivy reads the same kubeconfig
sofka does and scans with your permissions.

The adapter sends plain-text diagnostics to stderr while the scan runs. Sofka
shows these messages in its activity view. Stdout remains one JSON report with
the same schema. Trivy's Kubernetes progress bars
have no separators when sent to a pipe. The adapter converts recognized ASCII
bars into short updates, for example `Trivy progress: 8 / 81 (9.88%) 1 p/s`.
Repeated identical updates are omitted. Counts come from Trivy's work queue;
they do not prove that all queued scans have finished. Unknown diagnostic formats
are passed through unchanged.

Live diagnostics stop after 64 KiB of normalized text with a truncation notice,
but the scan continues. The adapter keeps the last 64 KiB for error reporting.
A failed activity write does not discard the report or the captured diagnostics.
Child read and process failures remain errors. Normalized progress records are
not selected as error summaries, so progress alone cannot hide a JSON parse error.

## Inputs

| Input    | Default | Purpose                                                                    |
| -------- | ------- | -------------------------------------------------------------------------- |
| `scan`   | `all`   | Use `misconfig` for a faster misconfiguration-only scan.                   |
| `report` | empty   | Render a saved Trivy JSON report from this path instead of running a scan. |

`:trivy report=/absolute/path/to/scan.json` is useful for reviewing a report
captured elsewhere. Sofka runs adapters from the package directory, so relative
paths do not resolve from the shell directory. The packaged fixture test uses
the same replay path internally; its `fixtures/scan.json` is a real
`trivy kubernetes --format json --report all` capture, reduced by keeping fewer
entries rather than by editing any of them, so the field names it asserts are
the ones Trivy emits.

## Limitations

- A full scan pulls and inspects every image it finds. The first run downloads
  Trivy's vulnerability database, so it needs network access, time, and cache
  space. The manifest allows 30 minutes; narrow it with a namespace or use
  `scan=misconfig` for a fast pass that skips image vulnerability scanning.
- There is no offline input. The adapter does not expose Trivy's offline or
  database-update flags; use a saved JSON report to render an externally run
  offline scan.
- Resources with no findings are left out. A cluster-wide scan touches every
  workload, and listing the clean ones would bury the findings.
- The rendered report is bounded, and the whole report shares one allowance. A
  scan with more findings than it can hold ends with a truncation notice. The
  summary continues counting the complete input and marks the rendered detail
  partial; scan one namespace at a time to see more sections.
- Findings come from Trivy. This package renders them; it does not add checks of
  its own, and a reviewed package is not a guarantee that Trivy has no defects.
