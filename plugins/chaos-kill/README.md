# Chaos kill

Deletes pods belonging to the selected workload and waits for it to become
ready again, reporting how long that took — or that it never did.

Select a Deployment, StatefulSet, or DaemonSet and enter `:chaos-kill`.

## This deletes running pods

Sofka can already delete a pod. What this adds is the measurement afterwards: a
workload that does not come back, or takes minutes to, is the finding.

Every safeguard sofka has is turned on:

- **`dry_run` defaults to `true`.** The first run tells you which pods it would
  delete and stops. Only `dry_run=false` — the exact string — deletes anything.
- **`mutating = true`**, so it is refused outright in read-only mode.
- **`confirm = true` and `dangerous = true`**, so sofka confirms before every
  run and marks the dialog.
- **Scoped to workloads that replace their own pods.** A bare pod has nothing
  to recover it, so killing one is a delete, not a test.
- **Never cluster-wide.** A namespace is required; the adapter refuses without
  one.
- A `plugin:chaos-kill` [guardrail](https://github.com/nklmilojevic/sofka/blob/main/docs/safety.md)
  can deny it per namespace. Put one on production.

## What it picks

The oldest running pods controlled by the selected workload, in creation order,
skipping any that are already terminating or not yet running. A Deployment is
matched through its owned ReplicaSets; StatefulSets and DaemonSets own their
pods directly. A debug pod that merely shares the workload labels is never
eligible.

It reads `spec.selector.matchLabels` to find them. A selector using
`matchExpressions` is refused rather than approximated — guessing would delete
the wrong pods.

## Live activity

The adapter reports ownership and identity checks, dry-run selection, deletion
requests, and recovery observations on stderr for Sofka's activity popup. Recovery
updates use the controller's observed ready and desired replica counts plus elapsed
time. A ready controller is not reported as recovered until replacement pods also
pass the existing identity and readiness checks. Failed measurements and timeouts
are reported as such, not as successful recovery.

Activity is bounded to 64 KiB plus a truncation notice. If diagnostics cannot be
written, recovery measurement continues. No extra cluster requests are made for
activity, and all deletion, dry-run, confirmation, and namespace safeguards stay
unchanged. Stdout remains the same JSON report with no schema change.

## Inputs

| Input     | Default | Purpose                                           |
| --------- | ------- | ------------------------------------------------- |
| `dry_run` | `true`  | Report what would be deleted, delete nothing.     |
| `count`   | `1`     | How many pods to delete, up to 10.                |
| `wait`    | `120s`  | How long to wait for recovery, up to 300 seconds. |

`:chaos-kill dry_run=false count=2 wait=60s`

`count` must be lower than the workload's desired replica count. The adapter
refuses a setting that could delete every desired replica.

## Dependencies

Requires Sofka 0.27.2 or newer for live plugin activity.

`kubectl` on `PATH`. It runs with your credentials and against the context
sofka is showing.

## Limitations

- Readiness comes from the workload's own status. A Deployment reporting ready
  replicas is not proof that traffic is being served correctly.
- It deletes pods; it does not partition networks, exhaust CPU, or inject
  latency. For those, use a purpose-built chaos platform.
- Recovery time includes image pulls, so a cold node makes a healthy workload
  look slow.
- Pod identity is checked, not locked. `kubectl delete` names a pod and cannot
  require that it is still the same pod, so the chosen pods are re-read and
  their UIDs compared immediately before the delete. A StatefulSet that
  replaced a pod under its original name in that last instant would still be
  hit; the run is refused outright if the check sees the swap.
