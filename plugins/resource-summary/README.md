# Resource summary

`resource-summary` shows the selected object's context, kind, namespace, and
name as a sofka report. Run `:resource-summary detail=true` to include its
labels.

The adapter reads only the request sofka sends on standard input. It does not
contact Kubernetes, mutate resources, use credentials, or require an external
tool. Its main purpose is to exercise the complete reviewed catalog publication
and installation workflow with a small useful package.

## Limitations

- This reports only identity, context, and labels already present in the sofka
  request. It does not fetch related resources or live cluster state.
- Label values that are not strings are rendered as empty values.

Responsible maintainer: Nikola Milojević (`@nklmilojevic`).
