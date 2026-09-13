# cert-manager

Three commands for [cert-manager](https://cert-manager.io) resources, in one
package:

| Command                 | Select a                   | Does                                                          | Changes the cluster |
| ----------------------- | -------------------------- | ------------------------------------------------------------- | ------------------- |
| `:cert-manager-status`  | Certificate                | Runs `cmctl status certificate` and shows the result.         | No                  |
| `:cert-manager-inspect` | `kubernetes.io/tls` Secret | Decodes the X.509 certificate in `tls.crt` and shows it.      | No                  |
| `:cert-manager-renew`   | Certificate                | Runs `cmctl renew`, which marks the Certificate for issuance. | Yes, with confirmation |

With rows marked (`space`) each command runs once per marked resource.

## Certificate status

Shows what `cmctl status certificate` knows about the selected Certificate: its
conditions, DNS names, issuer, the TLS secret it produced, and, while an
issuance is in flight, the CertificateRequest, ACME Order and Challenges.

cmctl prints indented text, not JSON, so the adapter reads that text:

- Top-level `Key: Value` lines (name, namespace, creation, validity and renewal
  times) become the **Summary** table, after the context sofka passed in.
- Top-level `Key:` headers (Conditions, DNS Names, Issuer, Secret,
  CertificateRequest, Order, Challenges) become sections holding their
  indented lines.
- Anything else, such as "No CertificateRequest found for this Certificate",
  lands in a **Notes** section rather than being dropped.

If a newer cmctl rearranges its output the report still renders; unfamiliar
lines end up as notes.

## Inspect TLS secret

Shows the certificate inside the selected `kubernetes.io/tls` Secret: the names
it is valid for, its validity period, issuer and subject, algorithms, serial
number, SHA-256 fingerprint, and its CRL and OCSP URLs.

The adapter decodes the first certificate in `tls.crt` itself instead of
running `cmctl inspect secret`. cmctl always contacts the CRL and OCSP URLs
embedded in the certificate, so a Secret written by someone else could make
your machine send requests to addresses of their choice. The report has the
same sections cmctl prints, without cmctl's **Debugging** block (trust store
check, CRL status, OCSP status). Nothing leaves your machine.

The Secret does not have to be managed by cert-manager; any `kubernetes.io/tls`
Secret with a `tls.crt` works. A Secret of another type is refused. The
private key is never read or shown.

Sofka sends the selected Secret with its data. If the data is absent, the
adapter reads the Secret once with `kubectl get secret -o json`.

## Renew certificate

Marks the selected Certificate for immediate renewal with `cmctl renew`.
cert-manager then creates a new CertificateRequest and replaces the TLS secret
once it is issued; the current certificate keeps working in the meantime.

`cmctl renew` sets the `Issuing` condition on the Certificate, so:

- **`mutating = true`**: refused in read-only mode.
- **`confirm = true`**: sofka asks before every run.
- A `plugin:cert-manager-renew` [guardrail](https://github.com/nklmilojevic/sofka/blob/main/docs/safety.md)
  can deny it per context or namespace.

It is not marked dangerous. Nothing is deleted and the existing certificate
stays valid until the new one is in place. The main cost is issuer quota: a
public ACME issuer such as Let's Encrypt rate-limits duplicate certificates,
so renewing the same Certificate repeatedly can leave it stuck until the limit
resets.

The report shows that the renewal was requested, not that it succeeded. Follow
it with `:cert-manager-status` on the same Certificate, which shows the
CertificateRequest and, for ACME issuers, the Order and Challenges. cmctl
returns an error for a Certificate that is already issuing; the report shows
that error unchanged.

## What the adapter checks before it runs a tool

Sofka's `certificates` scope matches the resource plural only. On a cluster
with another Certificate API, such as Knative's, the same plural can show
objects cmctl knows nothing about. Before every action the adapter checks the
object sofka selected:

- `status` and `renew` require `apiVersion` in the `cert-manager.io` group and
  `kind: Certificate`.
- `inspect` requires a core `v1` `Secret` of type `kubernetes.io/tls`.
- Name and namespace must be present and match the object's metadata.

Anything else is refused with an error that names what was selected.

## Inputs

| Command                 | Input     | Default | Purpose                                                                        |
| ----------------------- | --------- | ------- | ------------------------------------------------------------------------------ |
| `:cert-manager-status`  | `replay`  | none    | Render saved `cmctl status certificate` output from this path instead of running cmctl. |
| `:cert-manager-inspect` | `replay`  | none    | Render saved `cmctl inspect secret` output from this path instead of decoding the Secret. |
| `:cert-manager-renew`   | `dry_run` | `false` | Show the cmctl command that would run and renew nothing.                       |

```text
:cert-manager-status replay=/absolute/path/to/status.txt
:cert-manager-renew dry_run=true
```

Sofka runs adapters from the package directory, so a relative `replay` path
does not resolve from your shell directory. A replay file is read up to 1 MiB;
a larger file is an error. The packaged fixture test uses the same replay path
internally.

## Dependencies

- `cmctl` on `PATH` for `status` and `renew`, from
  https://cert-manager.io/docs/reference/cmctl/. It runs with your credentials
  against the context sofka is showing; when sofka has no explicit context,
  cmctl uses the kubeconfig's current one.
- `kubectl` on `PATH` for `inspect`, only used when the request does not
  carry the Secret data.

## Limitations

- The status report is only as detailed as cmctl's text output. cmctl does not
  show the Order's authorizations or challenges for non-ACME issuers, because
  there are none.
- `inspect` shows the first certificate in `tls.crt`, the leaf. Intermediates
  in the bundle are not listed. It does not check the chain, revocation, or
  whether your machine trusts the certificate.
- A tool that writes more than 1 MiB is an error; the adapter does not render
  a truncated report. Sofka refuses reports over 1 MiB in any case.
