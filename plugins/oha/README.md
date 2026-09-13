# HTTP benchmark

Sends HTTP load at the selected pod or service with [oha](https://github.com/hatoo/oha)
and renders the result: throughput, latency percentiles, status codes, and
errors.

Select a pod or service and enter `:oha`. Sofka asks for confirmation first,
every time.

## This one generates traffic

This plugin puts a workload under sustained load, so its manifest sets
`network_load = true`. Sofka treats that
as it would a destructive action: it confirms before each run, marks the
confirmation dialog, and refuses entirely in read-only mode. Point it at
production only when you mean to.

The `duration` input is capped at five minutes, and the six-minute plugin
deadline leaves time for the forward and report handoff. Connections are capped
at 1,000 and the default rate limit is 100 requests per second.

## How it reaches the workload

Sofka opens a `kubectl port-forward` to the port you name, waits for it to
answer, and tells the adapter which local port to use. The adapter never shells
out to kubectl and never guesses whether a cluster address is routable from
your machine. An existing saved forward for the same target and port is reused
rather than duplicated, and the forward is closed when the run ends.
Every connection travels through the Kubernetes API server and kubelet as part
of that port-forward, so high connection or request rates also load the control
plane path — not only the selected workload.

## Dependencies

Requires Sofka 0.27.2 or newer for live plugin activity.

oha 1.9.0 or newer, on `PATH`; that release introduced the `--output-format`
form used for JSON reports. See the
[oha installation guide](https://github.com/hatoo/oha#installation). Sofka
reports the requirement and where to get it; it never installs external tools
for you.

## Live activity

The adapter writes plain-text activity to stderr. Sofka's activity popup shows
the planned duration, configured connections and rate limit,
and elapsed time while oha runs. The rate limit is not measured throughput.
After the planned duration, the message says that oha is still running and the
adapter is waiting for final results. Only the final JSON report contains
measured throughput, latency, and request counts.

Child diagnostics are forwarded as they arrive, up to 64 KiB. The adapter keeps
draining after that limit and shows a truncation notice. Duration updates stop
after six minutes, even if a manually invoked process runs longer. The manifest
and report schemas are unchanged. The adapter does not print the target URL in
activity messages.

## Inputs

| Input         | Default | Purpose                                   |
| ------------- | ------- | ----------------------------------------- |
| `port`        | `80`    | Remote port to forward and benchmark.     |
| `duration`    | `10s`   | How long to send load, up to 300 seconds. |
| `connections` | `20`    | Concurrent connections.                   |
| `rate`        | `100`   | Overall request limit per second.         |
| `path`        | `/`     | Request path.                             |

`:oha port=8080 duration=30s connections=50 rate=100 path=/healthz`

## Limitations

- HTTP only, one URL, no request body or custom headers.
- The report is oha's. This package renders it; it adds no measurement of its
  own, and a reviewed package is not a guarantee that oha has no defects.
- A run that completes no requests still reports, because its error counts are
  usually what explains the failure.
