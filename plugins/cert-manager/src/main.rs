//! cert-manager. One adapter behind three sofka commands: `status` runs
//! `cmctl status certificate` for the selected Certificate, `renew` runs
//! `cmctl renew` for it, and `inspect` decodes the X.509 certificate inside the
//! selected `kubernetes.io/tls` Secret.
//!
//! The first command argument selects the action. No argument means `status`,
//! so the CI fixture step, which runs the adapter without arguments, tests
//! the status pair.
//!
//! `inspect` does not call `cmctl inspect secret`. That command always contacts
//! the CRL and OCSP URLs embedded in the certificate, so a Secret written by
//! someone else could make this machine send requests to addresses of their
//! choice. The adapter parses the certificate itself and prints the same
//! sections cmctl prints, without the Debugging block.
//!
//! cmctl has no machine-readable output for `status`, so the adapter reads the
//! indented `Key: Value` text it prints. Top-level pairs become a summary
//! table, top-level headers become sections with their indented lines, and
//! anything the parser does not recognise is kept as a note rather than
//! dropped. The offline inspector writes its text in cmctl's shape so the same
//! parser renders both, and a saved `cmctl inspect secret` output still replays.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write as _};
use std::process::{Command, Stdio};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use x509_parser::prelude::*;
use x509_parser::signature_algorithm::SignatureAlgorithm;

const REQUEST_MAX_BYTES: usize = 1024 * 1024;
/// Sofka refuses a report over 1 MiB, so a tool that writes more than that
/// cannot produce a usable report either. The adapter still drains the pipe.
const OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const STDERR_MAX_BYTES: usize = 64 * 1024;
const REPLAY_MAX_BYTES: usize = 1024 * 1024;
const CMCTL: &str = "cmctl";
const CMCTL_INSTALL: &str = "https://cert-manager.io/docs/reference/cmctl/#installation";
const KUBECTL: &str = "kubectl";
const KUBECTL_INSTALL: &str = "https://kubernetes.io/docs/tasks/tools/";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Action {
    Status,
    Inspect,
    Renew,
}

impl Action {
    /// The command arguments sofka passes from the manifest. Sofka appends
    /// nothing, so anything beyond the action is a manifest mistake.
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let action = match args.next().as_deref() {
            None | Some("status") => Action::Status,
            Some("inspect") => Action::Inspect,
            Some("renew") => Action::Renew,
            Some(other) => {
                return Err(format!(
                    "unknown action {other:?}; use status, inspect or renew"
                ));
            }
        };
        if let Some(extra) = args.next() {
            return Err(format!("unexpected argument {extra:?}"));
        }
        Ok(action)
    }
}

#[derive(Deserialize)]
struct Request {
    schema_version: u32,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
    #[serde(default)]
    object: Option<Value>,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), String> {
    let action = Action::parse(std::env::args().skip(1))?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(REQUEST_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > REQUEST_MAX_BYTES {
        return Err("request exceeds 1 MiB".into());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid request: {e}"))?;
    let output = serde_json::to_vec(&run(action, &request)?).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|e| e.to_string())
}

fn run(action: Action, request: &Request) -> Result<Value, String> {
    if request.schema_version != 1 {
        return Err("unsupported request schema_version".into());
    }
    match action {
        Action::Status => status(request),
        Action::Inspect => inspect(request),
        Action::Renew => renew(request),
    }
}

// --------------------------------------------------------------- selection --

/// The resource sofka selected, after the checks every action shares. Sofka
/// matches scopes on the resource plural only, so the object itself has to
/// prove it is the kind the action expects.
struct Target<'a> {
    namespace: &'a str,
    name: &'a str,
    object: &'a Value,
}

fn target<'a>(request: &'a Request, what: &str) -> Result<Target<'a>, String> {
    let name = request.name.as_str();
    if name.is_empty() {
        return Err(format!("no {what} selected"));
    }
    let namespace = request.namespace.as_deref().unwrap_or("");
    if namespace.is_empty() {
        return Err(format!("{what} {name} has no namespace"));
    }
    let object = request
        .object
        .as_ref()
        .filter(|object| object.is_object())
        .ok_or_else(|| {
            format!("the request has no object for {what} {namespace}/{name}; cannot verify it")
        })?;
    for (field, expected) in [("name", name), ("namespace", namespace)] {
        let actual = object["metadata"][field]
            .as_str()
            .ok_or_else(|| format!("the selected object has no metadata.{field}"))?;
        if actual != expected {
            return Err(format!(
                "the selected object is {field} {actual:?}, the request names {expected:?}"
            ));
        }
    }
    Ok(Target {
        namespace,
        name,
        object,
    })
}

fn describe_object(object: &Value) -> String {
    let api_version = object["apiVersion"].as_str().unwrap_or("<no apiVersion>");
    let kind = object["kind"].as_str().unwrap_or("<no kind>");
    format!("{kind} from {api_version}")
}

/// A cert-manager Certificate. Knative and others also serve a `certificates`
/// plural, and cmctl would act on the cert-manager object of the same name.
fn certificate(request: &Request) -> Result<Target<'_>, String> {
    let target = target(request, "Certificate")?;
    let api_version = target.object["apiVersion"].as_str().unwrap_or("");
    let kind = target.object["kind"].as_str().unwrap_or("");
    if kind != "Certificate" || !api_version.starts_with("cert-manager.io/") {
        return Err(format!(
            "{}/{} is a {}, not a cert-manager.io Certificate",
            target.namespace,
            target.name,
            describe_object(target.object)
        ));
    }
    Ok(target)
}

fn tls_secret(request: &Request) -> Result<Target<'_>, String> {
    let target = target(request, "Secret")?;
    let api_version = target.object["apiVersion"].as_str().unwrap_or("");
    let kind = target.object["kind"].as_str().unwrap_or("");
    if kind != "Secret" || api_version != "v1" {
        return Err(format!(
            "{}/{} is a {}, not a Secret",
            target.namespace,
            target.name,
            describe_object(target.object)
        ));
    }
    let secret_type = target.object["type"].as_str().unwrap_or("<no type>");
    if secret_type != "kubernetes.io/tls" {
        return Err(format!(
            "Secret {}/{} has type {secret_type}, not kubernetes.io/tls",
            target.namespace, target.name
        ));
    }
    Ok(target)
}

// ----------------------------------------------------------------- actions --

fn status(request: &Request) -> Result<Value, String> {
    let target = certificate(request)?;
    let text = match replay(request)? {
        Some(text) => text,
        None => {
            let args = arguments(&["status", "certificate"], request);
            execute_tool(CMCTL, &args, CMCTL_INSTALL)?
        }
    };
    Ok(render_status(request, &target, &text))
}

fn inspect(request: &Request) -> Result<Value, String> {
    let target = tls_secret(request)?;
    let text = match replay(request)? {
        Some(text) => text,
        None => describe_leaf(&certificate_pem(request, &target)?)?,
    };
    Ok(render_inspect(request, &target, &text))
}

fn renew(request: &Request) -> Result<Value, String> {
    let target = certificate(request)?;
    let args = arguments(&["renew"], request);
    if dry_run(request) {
        return Ok(render_renew(request, &target, &args, None));
    }
    let output = execute_tool(CMCTL, &args, CMCTL_INSTALL)?;
    Ok(render_renew(request, &target, &args, Some(&output)))
}

/// Only the exact string "true" skips the renewal, the same rule chaos-kill
/// applies to its dry_run input.
fn dry_run(request: &Request) -> bool {
    request
        .inputs
        .get("dry_run")
        .is_some_and(|value| value == "true")
}

/// Saved tool output to render instead of running anything. Read with a
/// limit: the path is user input and may name something without an end.
fn replay(request: &Request) -> Result<Option<String>, String> {
    let path = request.inputs.get("replay").map_or("", String::as_str);
    if path.is_empty() {
        return Ok(None);
    }
    let file = std::fs::File::open(path)
        .map_err(|e| format!("cannot read saved cmctl output {path}: {e}"))?;
    let mut bytes = Vec::new();
    file.take(REPLAY_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read saved cmctl output {path}: {e}"))?;
    if bytes.len() > REPLAY_MAX_BYTES {
        return Err(format!("saved cmctl output {path} exceeds 1 MiB"));
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

// ------------------------------------------------------------------- tools --

/// `leading` plus the selected name, then the namespace and context flags
/// cmctl and kubectl share.
fn arguments(leading: &[&str], request: &Request) -> Vec<String> {
    let mut args: Vec<String> = leading.iter().map(|arg| arg.to_string()).collect();
    args.push(request.name.clone());
    if let Some(namespace) = request.namespace.as_deref().filter(|n| !n.is_empty()) {
        args.push("--namespace".into());
        args.push(namespace.into());
    }
    // A null context means sofka has no explicit kubeconfig context; the tool
    // then uses the kubeconfig's current one, exactly like sofka did.
    if let Some(context) = request.context.as_deref().filter(|c| !c.is_empty()) {
        args.push("--context".into());
        args.push(context.into());
    }
    args
}

#[derive(Debug)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Read to EOF, keeping at most `limit` bytes. Reading past the limit keeps
/// the child from getting SIGPIPE on a closed pipe; the caller decides what a
/// truncated capture means.
fn bounded_read(mut reader: impl Read, limit: usize) -> std::io::Result<Captured> {
    let mut captured = Captured {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut chunk = [0; 8 * 1024];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let keep = read.min(limit.saturating_sub(captured.bytes.len()));
        captured.bytes.extend_from_slice(&chunk[..keep]);
        if keep < read {
            captured.truncated = true;
        }
    }
    Ok(captured)
}

/// Run `program` with `args`, arguments passed separately. Returns stdout on
/// success. A failed run, a failed read, or more than 1 MiB of stdout is an
/// error, never a partial report.
fn execute_tool(program: &str, args: &[String], install: &str) -> Result<String, String> {
    let command = format!("{program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start {program} ({e}); install it from {install}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("failed to capture {program} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("failed to capture {program} stderr"))?;
    // Drain stderr on its own thread so a chatty tool cannot block on a full
    // pipe while this process waits on stdout.
    let errors = std::thread::spawn(move || bounded_read(stderr, STDERR_MAX_BYTES));
    let output = bounded_read(stdout, OUTPUT_MAX_BYTES);
    let status = child
        .wait()
        .map_err(|e| format!("failed while waiting for {program}: {e}"))?;
    let errors = errors
        .join()
        .map_err(|_| format!("failed while reading {program} stderr"))?
        .map_err(|e| format!("failed while reading {program} stderr: {e}"))?;
    let output = output.map_err(|e| format!("failed while reading {program} stdout: {e}"))?;
    if !status.success() {
        let detail = if errors.bytes.iter().all(u8::is_ascii_whitespace) {
            output.bytes
        } else {
            errors.bytes
        };
        return Err(format!(
            "{command} failed ({status}): {}",
            String::from_utf8_lossy(&detail).trim()
        ));
    }
    if output.truncated {
        return Err(format!(
            "{command} wrote more than 1 MiB; the report would be incomplete"
        ));
    }
    Ok(String::from_utf8_lossy(&output.bytes).into_owned())
}

// ----------------------------------------------------------------- inspect --

/// The PEM bundle in the Secret's `tls.crt`. Sofka sends the selected object
/// with its data; when the data is absent, read the Secret once with kubectl.
fn certificate_pem(request: &Request, target: &Target<'_>) -> Result<Vec<u8>, String> {
    let owned;
    let encoded = match target.object["data"]["tls.crt"].as_str() {
        Some(encoded) => encoded,
        None if target.object.get("data").is_some() => {
            return Err(format!(
                "Secret {}/{} has no tls.crt",
                target.namespace, target.name
            ));
        }
        None => {
            let mut args = arguments(&["get", "secret"], request);
            args.extend(["--output".to_string(), "json".to_string()]);
            let json = execute_tool(KUBECTL, &args, KUBECTL_INSTALL)?;
            owned = serde_json::from_str::<Value>(&json)
                .map_err(|e| format!("kubectl returned an invalid Secret: {e}"))?;
            let secret_type = owned["type"].as_str().unwrap_or("<no type>");
            if owned["kind"].as_str() != Some("Secret") || secret_type != "kubernetes.io/tls" {
                return Err(format!(
                    "kubectl returned a {} of type {secret_type}, not a kubernetes.io/tls Secret",
                    describe_object(&owned)
                ));
            }
            owned["data"]["tls.crt"].as_str().ok_or_else(|| {
                format!("Secret {}/{} has no tls.crt", target.namespace, target.name)
            })?
        }
    };
    base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| format!("tls.crt is not valid base64: {e}"))
}

/// Describe the first certificate in a PEM bundle: the leaf, as cmctl does.
fn describe_leaf(pem: &[u8]) -> Result<String, String> {
    let mut leaf = None;
    for block in Pem::iter_from_buffer(pem) {
        let block = block.map_err(|e| format!("tls.crt is not valid PEM: {e}"))?;
        if block.label == "CERTIFICATE" {
            leaf = Some(block);
            break;
        }
    }
    let leaf = leaf.ok_or("no PEM certificate found in tls.crt")?;
    let (_, certificate) = X509Certificate::from_der(&leaf.contents)
        .map_err(|e| format!("cannot parse the certificate in tls.crt: {e}"))?;
    Ok(describe(&certificate, &leaf.contents))
}

/// cmctl's `inspect secret` text without the Debugging block. Tabs and the
/// empty-list spellings match cmctl's templates, so the parser sees no
/// difference between this and a saved cmctl run.
fn describe(certificate: &X509Certificate<'_>, der: &[u8]) -> String {
    let mut dns = Vec::new();
    let mut uris = Vec::new();
    let mut ips = Vec::new();
    let mut emails = Vec::new();
    if let Ok(Some(extension)) = certificate.subject_alternative_name() {
        for name in &extension.value.general_names {
            match name {
                GeneralName::DNSName(name) => dns.push(name.to_string()),
                GeneralName::URI(uri) => uris.push(uri.to_string()),
                GeneralName::IPAddress(bytes) => ips.push(ip_address(bytes)),
                GeneralName::RFC822Name(email) => emails.push(email.to_string()),
                _ => {}
            }
        }
    }
    let usages = key_usages(certificate);
    let usages = if usages.is_empty() {
        " <none>".to_string()
    } else {
        list(&usages)
    };
    let mut crls = Vec::new();
    let mut ocsp = Vec::new();
    for extension in certificate.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::CRLDistributionPoints(points) => {
                for point in &points.points {
                    if let Some(DistributionPointName::FullName(names)) = &point.distribution_point
                    {
                        crls.extend(names.iter().filter_map(uri));
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(access) => {
                for description in &access.accessdescs {
                    if description.access_method.to_id_string() == "1.3.6.1.5.5.7.48.1"
                        && let Some(location) = uri(&description.access_location)
                    {
                        ocsp.push(location);
                    }
                }
            }
            _ => {}
        }
    }
    let is_ca = certificate
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|extension| extension.value.ca);
    let issuer = certificate.issuer();
    let subject = certificate.subject();

    let mut text = String::new();
    let _ = writeln!(text, "Valid for:");
    let _ = writeln!(text, "\tDNS Names: {}", list(&dns));
    let _ = writeln!(text, "\tURIs: {}", list(&uris));
    let _ = writeln!(text, "\tIP Addresses: {}", list(&ips));
    let _ = writeln!(text, "\tEmail Addresses: {}", list(&emails));
    let _ = writeln!(text, "\tUsages: {usages}");
    let _ = writeln!(text);
    let _ = writeln!(text, "Validity period:");
    let _ = writeln!(
        text,
        "\tNot Before: {}",
        rfc1123(&certificate.validity().not_before)
    );
    let _ = writeln!(
        text,
        "\tNot After: {}",
        rfc1123(&certificate.validity().not_after)
    );
    let _ = writeln!(text);
    for (title, name) in [("Issued By", issuer), ("Issued For", subject)] {
        let _ = writeln!(text, "{title}:");
        let _ = writeln!(
            text,
            "\tCommon Name:\t{}",
            one(&attributes(name.iter_common_name()))
        );
        let _ = writeln!(
            text,
            "\tOrganization:\t{}",
            one(&attributes(name.iter_organization()))
        );
        let _ = writeln!(
            text,
            "\tOrganizationalUnit:\t{}",
            one(&attributes(name.iter_organizational_unit()))
        );
        let _ = writeln!(
            text,
            "\tCountry:\t{}",
            one(&attributes(name.iter_country()))
        );
        let _ = writeln!(text);
    }
    let _ = writeln!(text, "Certificate:");
    let _ = writeln!(
        text,
        "\tSigning Algorithm:\t{}",
        signature_algorithm(&certificate.signature_algorithm)
    );
    let _ = writeln!(
        text,
        "\tPublic Key Algorithm: \t{}",
        public_key_algorithm(&certificate.public_key().algorithm.algorithm)
    );
    let _ = writeln!(
        text,
        "\tSerial Number:\t{}",
        certificate.tbs_certificate.serial
    );
    let _ = writeln!(text, "\tFingerprints: \t{}", fingerprint(der));
    let _ = writeln!(text, "\tIs a CA certificate: {is_ca}");
    let _ = writeln!(text, "\tCRL:\t{}", one(&crls));
    let _ = write!(text, "\tOCSP:\t{}", one(&ocsp));
    text
}

/// cmctl's `printSlice`: a tab-indented list, or `<none>`.
fn list(values: &[String]) -> String {
    if values.is_empty() {
        return "<none>".to_string();
    }
    let mut text = String::new();
    for value in values {
        let _ = write!(text, "\n\t\t- {value}");
    }
    text
}

/// cmctl's `printSliceOrOne`: a single value inline, several as a list.
fn one(values: &[String]) -> String {
    match values {
        [] => "<none>".to_string(),
        [value] => value.clone(),
        _ => list(values),
    }
}

fn attributes<'a>(values: impl Iterator<Item = &'a AttributeTypeAndValue<'a>>) -> Vec<String> {
    values
        .filter_map(|value| value.as_str().ok())
        .map(str::to_string)
        .collect()
}

fn uri(name: &GeneralName<'_>) -> Option<String> {
    match name {
        GeneralName::URI(uri) => Some(uri.to_string()),
        _ => None,
    }
}

fn ip_address(bytes: &[u8]) -> String {
    match <[u8; 4]>::try_from(bytes) {
        Ok(octets) => std::net::Ipv4Addr::from(octets).to_string(),
        Err(_) => match <[u8; 16]>::try_from(bytes) {
            Ok(octets) => std::net::Ipv6Addr::from(octets).to_string(),
            Err(_) => format!("?{}", hex(bytes, "")),
        },
    }
}

/// The key usages in cert-manager's spelling, in the order cmctl prints them:
/// key usage bits low to high, then the extended key usages.
fn key_usages(certificate: &X509Certificate<'_>) -> Vec<String> {
    let mut usages = Vec::new();
    if let Ok(Some(extension)) = certificate.key_usage() {
        let usage = extension.value;
        let flags: [(bool, &str); 9] = [
            (usage.digital_signature(), "digital signature"),
            (usage.non_repudiation(), "content commitment"),
            (usage.key_encipherment(), "key encipherment"),
            (usage.data_encipherment(), "data encipherment"),
            (usage.key_agreement(), "key agreement"),
            (usage.key_cert_sign(), "cert sign"),
            (usage.crl_sign(), "crl sign"),
            (usage.encipher_only(), "encipher only"),
            (usage.decipher_only(), "decipher only"),
        ];
        usages.extend(
            flags
                .iter()
                .filter(|(set, _)| *set)
                .map(|(_, name)| name.to_string()),
        );
    }
    if let Ok(Some(extension)) = certificate.extended_key_usage() {
        let usage = extension.value;
        let flags: [(bool, &str); 7] = [
            (usage.any, "any"),
            (usage.server_auth, "server auth"),
            (usage.client_auth, "client auth"),
            (usage.code_signing, "code signing"),
            (usage.email_protection, "email protection"),
            (usage.time_stamping, "timestamping"),
            (usage.ocsp_signing, "ocsp signing"),
        ];
        usages.extend(
            flags
                .iter()
                .filter(|(set, _)| *set)
                .map(|(_, name)| name.to_string()),
        );
        for oid in &usage.other {
            let name = match oid.to_id_string().as_str() {
                "1.3.6.1.5.5.7.3.5" => "ipsec end system",
                "1.3.6.1.5.5.7.3.6" => "ipsec tunnel",
                "1.3.6.1.5.5.7.3.7" => "ipsec user",
                "1.3.6.1.4.1.311.10.3.3" => "microsoft sgc",
                "2.16.840.1.113730.4.1" => "netscape sgc",
                // Go's parser keeps other usages apart and cmctl never prints them.
                _ => continue,
            };
            usages.push(name.to_string());
        }
    }
    usages
}

/// Go's `x509.SignatureAlgorithm` names, which cmctl prints. An algorithm Go
/// does not name is shown as its OID.
fn signature_algorithm(identifier: &AlgorithmIdentifier<'_>) -> String {
    let oid = identifier.algorithm.to_id_string();
    let name = match oid.as_str() {
        "1.2.840.113549.1.1.4" => "MD5-RSA",
        "1.2.840.113549.1.1.5" => "SHA1-RSA",
        "1.2.840.113549.1.1.11" => "SHA256-RSA",
        "1.2.840.113549.1.1.12" => "SHA384-RSA",
        "1.2.840.113549.1.1.13" => "SHA512-RSA",
        "1.2.840.10040.4.3" => "DSA-SHA1",
        "2.16.840.1.101.3.4.3.2" => "DSA-SHA256",
        "1.2.840.10045.4.1" => "ECDSA-SHA1",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.2.840.113549.1.1.10" => {
            let hash = match SignatureAlgorithm::try_from(identifier) {
                Ok(SignatureAlgorithm::RSASSA_PSS(params)) => {
                    params.hash_algorithm_oid().to_id_string()
                }
                _ => String::new(),
            };
            return match hash.as_str() {
                "2.16.840.1.101.3.4.2.1" => "SHA256-RSAPSS".to_string(),
                "2.16.840.1.101.3.4.2.2" => "SHA384-RSAPSS".to_string(),
                "2.16.840.1.101.3.4.2.3" => "SHA512-RSAPSS".to_string(),
                _ => oid,
            };
        }
        _ => return oid,
    };
    name.to_string()
}

/// Go's `x509.PublicKeyAlgorithm` names.
fn public_key_algorithm(oid: &x509_parser::der_parser::Oid<'_>) -> String {
    match oid.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        "1.2.840.10040.4.1" => "DSA".to_string(),
        "1.2.840.10045.2.1" => "ECDSA".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        other => other.to_string(),
    }
}

/// SHA-256 over the DER certificate, upper-case and colon separated, as
/// cmctl and browsers show it.
fn fingerprint(der: &[u8]) -> String {
    hex(&Sha256::digest(der), ":")
}

fn hex(bytes: &[u8], separator: &str) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(separator)
}

/// Go's `time.RFC1123` for a UTC time, the format cmctl uses for validity.
fn rfc1123(time: &ASN1Time) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let time = time.to_datetime();
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} UTC",
        DAYS[time.weekday().number_days_from_sunday() as usize],
        time.day(),
        MONTHS[usize::from(u8::from(time.month())) - 1],
        time.year(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

// ------------------------------------------------------------------ parsing --

#[derive(Default, Debug, PartialEq)]
struct Parsed {
    /// Top-level `Key: Value` pairs, in order of appearance.
    rows: Vec<(String, String)>,
    /// Top-level `Key:` headers with their indented lines, re-indented so the
    /// first level sits flush left.
    sections: Vec<(String, Vec<String>)>,
    /// Top-level lines that are neither pairs nor headers, such as
    /// "No CertificateRequest found for this Certificate".
    notes: Vec<String>,
}

/// Indentation depth of a cmctl line. `cmctl status` indents with two spaces
/// per level, `cmctl inspect` with one tab, so both count as one.
fn split_indent(line: &str) -> (usize, &str) {
    let mut depth: usize = 0;
    let mut spaces: usize = 0;
    let mut start = 0;
    for (index, character) in line.char_indices() {
        match character {
            '\t' => depth += 1,
            ' ' => spaces += 1,
            _ => {
                start = index;
                break;
            }
        }
    }
    (depth + spaces.div_ceil(2), &line[start..])
}

/// Split `Key: Value` at the first colon that ends the key. A colon inside the
/// value (a timestamp, a URL) is left alone because the key never contains
/// whitespace after its colon.
fn split_pair(text: &str) -> Option<(&str, &str)> {
    let colon = text.find(':')?;
    let (key, rest) = text.split_at(colon);
    let rest = &rest[1..];
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let key = key.trim();
    if key.is_empty() || key.starts_with('-') {
        return None;
    }
    Some((key, rest.trim()))
}

/// Collapse the tab alignment cmctl uses between a key and its value.
fn normalize(text: &str) -> String {
    match split_pair(text) {
        Some((key, "")) => format!("{key}:"),
        Some((key, value)) => format!("{key}: {value}"),
        None => text.trim().to_string(),
    }
}

fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    let mut current: Option<usize> = None;
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let (indent, body) = split_indent(line);
        if indent == 0 && !body.starts_with("- ") {
            match split_pair(body) {
                Some((key, "")) => {
                    parsed.sections.push((key.to_string(), Vec::new()));
                    current = Some(parsed.sections.len() - 1);
                }
                Some((key, value)) => {
                    parsed.rows.push((key.to_string(), value.to_string()));
                    current = None;
                }
                None => {
                    parsed.notes.push(body.to_string());
                    current = None;
                }
            }
            continue;
        }
        let rendered = format!(
            "{}{}",
            "  ".repeat(indent.saturating_sub(1)),
            normalize(body)
        );
        match current {
            Some(index) => parsed.sections[index].1.push(rendered),
            None => parsed.notes.push(rendered),
        }
    }
    parsed
}

// ---------------------------------------------------------------- rendering --

fn context_row(request: &Request) -> Value {
    json!(["Context", request.context.as_deref().unwrap_or("inferred")])
}

/// A Summary table from `rows`, then one section per parsed block and the
/// notes, if any.
fn report(title: &str, rows: Vec<Value>, parsed: Parsed) -> Value {
    let mut rows = rows;
    rows.extend(parsed.rows.iter().map(|(key, value)| json!([key, value])));
    let mut sections = vec![json!({
        "title": "Summary",
        "columns": ["Field", "Value"],
        "rows": rows,
    })];
    for (title, lines) in parsed.sections {
        let lines = if lines.is_empty() {
            vec!["<none>".to_string()]
        } else {
            lines
        };
        sections.push(json!({ "title": title, "lines": lines }));
    }
    if !parsed.notes.is_empty() {
        sections.push(json!({ "title": "Notes", "lines": parsed.notes }));
    }
    json!({
        "schema_version": 1,
        "title": title,
        "sections": sections,
    })
}

fn render_status(request: &Request, target: &Target<'_>, text: &str) -> Value {
    let parsed = parse(text);
    let mut rows = vec![context_row(request)];
    if parsed.rows.is_empty() {
        // cmctl normally prints Name and Namespace itself; fall back to what
        // sofka selected when the output has no top-level pairs at all.
        rows.push(json!(["Namespace", target.namespace]));
        rows.push(json!(["Certificate", target.name]));
    }
    report("Certificate status", rows, parsed)
}

fn render_inspect(request: &Request, target: &Target<'_>, text: &str) -> Value {
    let rows = vec![
        context_row(request),
        json!(["Namespace", target.namespace]),
        json!(["Secret", target.name]),
    ];
    report("TLS secret", rows, parse(text))
}

fn render_renew(
    request: &Request,
    target: &Target<'_>,
    args: &[String],
    output: Option<&str>,
) -> Value {
    let verdict = match output {
        None => "dry run, nothing was renewed",
        Some(_) => "renewal requested",
    };
    let rows = vec![
        json!(["Verdict", verdict]),
        context_row(request),
        json!(["Namespace", target.namespace]),
        json!(["Certificate", target.name]),
    ];
    let mut sections = vec![
        json!({
            "title": "Summary",
            "columns": ["Field", "Value"],
            "rows": rows,
        }),
        json!({
            "title": "Command",
            "lines": [format!("{CMCTL} {}", args.join(" "))],
        }),
    ];
    match output {
        None => sections.push(json!({
            "title": "Notice",
            "lines": ["Re-run with dry_run=false to mark the Certificate for renewal."],
        })),
        Some(output) => {
            let lines: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
            let lines = if lines.is_empty() {
                vec!["<no output>"]
            } else {
                lines
            };
            sections.push(json!({ "title": "cmctl output", "lines": lines }));
            sections.push(json!({
                "title": "Next",
                "lines": [
                    "cert-manager now creates a CertificateRequest for this Certificate.",
                    "Use :cert-manager-status to follow the request, order and challenges.",
                ],
            }));
        }
    }
    json!({
        "schema_version": 1,
        "title": "Renew certificate",
        "sections": sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = include_str!("../fixtures/status.txt");
    const INSPECT: &str = include_str!("../fixtures/inspect.txt");

    fn status_request() -> Request {
        serde_json::from_str(include_str!("../fixtures/request.json")).unwrap()
    }

    fn inspect_request() -> Request {
        serde_json::from_str(include_str!("../fixtures/inspect-request.json")).unwrap()
    }

    fn renew_request() -> Request {
        serde_json::from_str(include_str!("../fixtures/renew-request.json")).unwrap()
    }

    fn fixture(name: &str) -> Value {
        let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    // ------------------------------------------------------------- fixtures --

    #[test]
    fn status_fixture_matches_expected_report() {
        let request = status_request();
        let target = certificate(&request).unwrap();
        assert_eq!(
            render_status(&request, &target, STATUS),
            fixture("report.json")
        );
    }

    #[test]
    fn the_status_request_fixture_replays_the_status_fixture() {
        assert_eq!(
            status_request().inputs.get("replay").map(String::as_str),
            Some("plugins/cert-manager/fixtures/status.txt")
        );
    }

    #[test]
    fn inspect_fixture_is_rendered_offline_from_the_secret_data() {
        let request = inspect_request();
        assert!(request.inputs.get("replay").is_none_or(String::is_empty));
        assert_eq!(
            run(Action::Inspect, &request).unwrap(),
            fixture("inspect-report.json")
        );
    }

    #[test]
    fn the_inspect_text_fixture_is_what_the_adapter_writes() {
        let request = inspect_request();
        let target = tls_secret(&request).unwrap();
        let pem = certificate_pem(&request, &target).unwrap();
        assert_eq!(describe_leaf(&pem).unwrap(), INSPECT);
    }

    #[test]
    fn renew_fixture_is_a_dry_run_that_matches_expected_report() {
        let request = renew_request();
        assert!(dry_run(&request));
        assert_eq!(
            run(Action::Renew, &request).unwrap(),
            fixture("renew-report.json")
        );
    }

    // -------------------------------------------------------------- actions --

    #[test]
    fn the_action_comes_from_the_first_argument_and_defaults_to_status() {
        let parse = |args: &[&str]| Action::parse(args.iter().map(|a| a.to_string()));
        assert_eq!(parse(&[]), Ok(Action::Status));
        assert_eq!(parse(&["status"]), Ok(Action::Status));
        assert_eq!(parse(&["inspect"]), Ok(Action::Inspect));
        assert_eq!(parse(&["renew"]), Ok(Action::Renew));
        assert!(parse(&["delete"]).unwrap_err().contains("unknown action"));
        assert!(parse(&["renew", "now"]).unwrap_err().contains("unexpected"));
    }

    #[test]
    fn rejects_unknown_request_schema() {
        let mut request = status_request();
        request.schema_version = 2;
        assert!(run(Action::Status, &request).is_err());
    }

    // ------------------------------------------------------------ selection --

    #[test]
    fn a_certificate_from_another_api_group_is_refused() {
        for api_version in [
            "networking.internal.knative.dev/v1alpha1",
            "applications.azuread.m.upbound.io/v1beta1",
            "v1",
        ] {
            let mut request = renew_request();
            request.object.as_mut().unwrap()["apiVersion"] = json!(api_version);
            let error = run(Action::Renew, &request).unwrap_err();
            assert!(
                error.contains("not a cert-manager.io Certificate"),
                "{error}"
            );
            let error = run(Action::Status, &request).unwrap_err();
            assert!(
                error.contains("not a cert-manager.io Certificate"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_cert_manager_object_of_another_kind_is_refused() {
        let mut request = renew_request();
        request.object.as_mut().unwrap()["kind"] = json!("CertificateRequest");
        let error = run(Action::Renew, &request).unwrap_err();
        assert!(
            error.contains("CertificateRequest from cert-manager.io/v1"),
            "{error}"
        );
    }

    #[test]
    fn a_request_without_an_object_cannot_be_verified() {
        let mut request = renew_request();
        request.object = None;
        assert!(
            run(Action::Renew, &request)
                .unwrap_err()
                .contains("no object")
        );
        request.object = Some(Value::Null);
        assert!(
            run(Action::Renew, &request)
                .unwrap_err()
                .contains("no object")
        );
    }

    #[test]
    fn name_and_namespace_must_be_present_and_match_the_object() {
        let mut request = renew_request();
        request.name.clear();
        assert!(
            run(Action::Renew, &request)
                .unwrap_err()
                .contains("no Certificate selected")
        );
        let mut request = renew_request();
        request.namespace = None;
        assert!(
            run(Action::Renew, &request)
                .unwrap_err()
                .contains("no namespace")
        );
        let mut request = renew_request();
        request.namespace = Some(String::new());
        assert!(
            run(Action::Renew, &request)
                .unwrap_err()
                .contains("no namespace")
        );
        let mut request = renew_request();
        request.object.as_mut().unwrap()["metadata"]["name"] = json!("other-tls");
        let error = run(Action::Renew, &request).unwrap_err();
        assert!(
            error.contains("\"other-tls\"") && error.contains("\"web-tls\""),
            "{error}"
        );
    }

    #[test]
    fn an_object_without_metadata_name_or_namespace_is_refused() {
        for field in ["name", "namespace"] {
            let mut request = renew_request();
            request.object.as_mut().unwrap()["metadata"][field].take();
            let error = run(Action::Renew, &request).unwrap_err();
            assert!(error.contains(&format!("no metadata.{field}")), "{error}");
            let mut request = renew_request();
            request.object.as_mut().unwrap()["metadata"][field] = json!(7);
            assert!(run(Action::Renew, &request).is_err());
        }
        let mut request = inspect_request();
        request.object.as_mut().unwrap()["metadata"] = json!({});
        assert!(
            run(Action::Inspect, &request)
                .unwrap_err()
                .contains("no metadata.name")
        );
    }

    #[test]
    fn inspect_requires_a_tls_secret() {
        let mut request = inspect_request();
        request.object.as_mut().unwrap()["type"] = json!("Opaque");
        let error = run(Action::Inspect, &request).unwrap_err();
        assert!(error.contains("type Opaque"), "{error}");
        let mut request = inspect_request();
        request.object.as_mut().unwrap()["kind"] = json!("ConfigMap");
        let error = run(Action::Inspect, &request).unwrap_err();
        assert!(error.contains("not a Secret"), "{error}");
        let mut request = inspect_request();
        request.object.as_mut().unwrap()["apiVersion"] = json!("cert-manager.io/v1");
        assert!(run(Action::Inspect, &request).is_err());
    }

    #[test]
    fn inspect_reports_a_secret_without_a_certificate() {
        let mut request = inspect_request();
        request.object.as_mut().unwrap()["data"] = json!({ "tls.key": "" });
        let error = run(Action::Inspect, &request).unwrap_err();
        assert!(error.contains("no tls.crt"), "{error}");
        let mut request = inspect_request();
        request.object.as_mut().unwrap()["data"]["tls.crt"] = json!("not base64!");
        assert!(
            run(Action::Inspect, &request)
                .unwrap_err()
                .contains("base64")
        );
        let mut request = inspect_request();
        request.object.as_mut().unwrap()["data"]["tls.crt"] = json!(
            base64::engine::general_purpose::STANDARD
                .encode("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")
        );
        let error = run(Action::Inspect, &request).unwrap_err();
        assert!(error.contains("no PEM certificate"), "{error}");
    }

    // -------------------------------------------------------------- inspect --

    #[test]
    fn the_inspect_text_has_cmctl_shape_and_content() {
        let parsed = parse(INSPECT);
        assert!(parsed.rows.is_empty());
        assert!(parsed.notes.is_empty());
        let titles: Vec<&str> = parsed.sections.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Valid for",
                "Validity period",
                "Issued By",
                "Issued For",
                "Certificate"
            ]
        );
        assert!(INSPECT.contains("\tDNS Names: \n\t\t- web.example.com\n\t\t- www.example.com\n"));
        assert!(INSPECT.contains("\tUsages: \n\t\t- digital signature\n\t\t- key encipherment\n\t\t- server auth\n\t\t- client auth\n"));
        assert!(INSPECT.contains("\tNot Before: Tue, 14 Jul 2026 07:00:00 UTC\n"));
        assert!(INSPECT.contains("\tNot After: Mon, 12 Oct 2026 06:59:59 UTC\n"));
        assert!(INSPECT.contains("\tSerial Number:\t430673462503741351513170006858831388180625\n"));
        assert!(INSPECT.contains("\tFingerprints: \t26:6A:9A:63:72:70:84:8B:EC:9A:42:43:C7:D3:D3:C6:C3:30:D8:A2:10:76:53:E0:4E:5E:46:2C:8E:C5:9D:9C\n"));
        assert!(INSPECT.contains("\tCRL:\thttp://crl.example.com/r1.crl\n"));
        assert!(INSPECT.ends_with("\tOCSP:\thttp://ocsp.example.com"));
        assert!(!INSPECT.contains("Debugging"));
    }

    #[test]
    fn cmctl_list_spellings_are_reproduced() {
        assert_eq!(list(&[]), "<none>");
        assert_eq!(list(&["a".to_string()]), "\n\t\t- a");
        assert_eq!(one(&[]), "<none>");
        assert_eq!(one(&["a".to_string()]), "a");
        assert_eq!(
            one(&["a".to_string(), "b".to_string()]),
            "\n\t\t- a\n\t\t- b"
        );
        assert_eq!(ip_address(&[10, 0, 0, 1]), "10.0.0.1");
        assert_eq!(
            ip_address(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001:db8::1"
        );
    }

    #[test]
    fn validity_uses_go_rfc1123_in_utc() {
        assert_eq!(
            rfc1123(&ASN1Time::from_timestamp(0).unwrap()),
            "Thu, 01 Jan 1970 00:00:00 UTC"
        );
        assert_eq!(
            rfc1123(&ASN1Time::from_timestamp(1_784_012_400).unwrap()),
            "Tue, 14 Jul 2026 07:00:00 UTC"
        );
    }

    #[test]
    fn a_saved_cmctl_inspect_output_still_replays() {
        let dir = std::env::temp_dir().join(format!("cert-manager-replay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inspect.txt");
        std::fs::write(
            &path,
            "Valid for:\n\tDNS Names: <none>\n\nDebugging:\n\tTrusted by this computer:\tyes\n",
        )
        .unwrap();
        let mut request = inspect_request();
        request
            .inputs
            .insert("replay".into(), path.to_string_lossy().into_owned());
        let report = run(Action::Inspect, &request).unwrap();
        let titles: Vec<&str> = report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["title"].as_str().unwrap())
            .collect();
        assert_eq!(titles, ["Summary", "Valid for", "Debugging"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // -------------------------------------------------------------- parsing --

    #[test]
    fn top_level_pairs_become_rows_and_headers_become_sections() {
        let parsed = parse(STATUS);
        let keys: Vec<&str> = parsed.rows.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "Name",
                "Namespace",
                "Created at",
                "Events",
                "Not Before",
                "Not After",
                "Renewal Time"
            ]
        );
        let titles: Vec<&str> = parsed.sections.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Conditions",
                "DNS Names",
                "Issuer",
                "Secret",
                "CertificateRequest",
                "Order",
                "Challenges"
            ]
        );
    }

    #[test]
    fn list_items_attach_to_the_open_section() {
        let parsed = parse("DNS Names:\n- a.example.com\n- b.example.com\nNot After: x\n");
        assert_eq!(
            parsed.sections,
            vec![(
                "DNS Names".to_string(),
                vec!["- a.example.com".to_string(), "- b.example.com".to_string()]
            )]
        );
        assert_eq!(
            parsed.rows,
            vec![("Not After".to_string(), "x".to_string())]
        );
    }

    #[test]
    fn nested_blocks_keep_one_level_of_indentation() {
        let parsed =
            parse("Issuer:\n  Name: ca\n  Conditions:\n    Ready: True, Reason: KeyPairVerified\n");
        assert_eq!(
            parsed.sections[0].1,
            vec![
                "Name: ca".to_string(),
                "Conditions:".to_string(),
                "  Ready: True, Reason: KeyPairVerified".to_string()
            ]
        );
    }

    #[test]
    fn tab_indented_list_items_keep_one_level_of_indentation() {
        let parsed = parse("Valid for:\n\tDNS Names: \n\t\t- web.example.com\n\tURIs: <none>\n");
        assert_eq!(
            parsed.sections[0].1,
            vec![
                "DNS Names:".to_string(),
                "  - web.example.com".to_string(),
                "URIs: <none>".to_string()
            ]
        );
    }

    #[test]
    fn tab_aligned_pairs_collapse_to_one_space() {
        assert_eq!(normalize("Common Name:\t\tR13"), "Common Name: R13");
        assert_eq!(normalize("Subject Key ID: "), "Subject Key ID:");
        assert_eq!(normalize("Organization:\t<none>"), "Organization: <none>");
        assert_eq!(
            normalize("Not Before: 2026-09-11T03:52:06+02:00"),
            "Not Before: 2026-09-11T03:52:06+02:00"
        );
    }

    #[test]
    fn a_colon_inside_a_value_does_not_split_the_key() {
        assert_eq!(
            split_pair("URL: https://acme.example/authz/1"),
            Some(("URL", "https://acme.example/authz/1"))
        );
        assert_eq!(
            split_pair("CRL:\t\thttp://crl.example.com/r1.crl"),
            Some(("CRL", "http://crl.example.com/r1.crl"))
        );
        assert_eq!(split_pair("- web.example.com"), None);
        assert_eq!(
            split_pair("No CertificateRequest found for this Certificate"),
            None
        );
    }

    #[test]
    fn free_text_lines_become_notes() {
        let parsed = parse("Name: x\nNo CertificateRequest found for this Certificate\n");
        assert_eq!(
            parsed.notes,
            vec!["No CertificateRequest found for this Certificate".to_string()]
        );
    }

    #[test]
    fn empty_sections_render_a_placeholder() {
        let request = status_request();
        let target = certificate(&request).unwrap();
        let report = render_status(&request, &target, "Conditions:\n");
        assert_eq!(report["sections"][1]["lines"], json!(["<none>"]));
        // No top-level pairs: the Summary names what sofka selected.
        assert_eq!(
            report["sections"][0]["rows"][1],
            json!(["Namespace", "apps"])
        );
        assert_eq!(
            report["sections"][0]["rows"][2],
            json!(["Certificate", "web-tls"])
        );
    }

    // ---------------------------------------------------------------- tools --

    #[test]
    fn arguments_follow_the_request() {
        let mut request = status_request();
        assert_eq!(
            arguments(&["status", "certificate"], &request),
            [
                "status",
                "certificate",
                "web-tls",
                "--namespace",
                "apps",
                "--context",
                "development"
            ]
        );
        assert_eq!(
            arguments(&["renew"], &request),
            [
                "renew",
                "web-tls",
                "--namespace",
                "apps",
                "--context",
                "development"
            ]
        );
        request.context = None;
        request.namespace = Some(String::new());
        assert_eq!(arguments(&["renew"], &request), ["renew", "web-tls"]);
    }

    #[test]
    fn a_real_renew_reports_what_cmctl_said() {
        let request = renew_request();
        let target = certificate(&request).unwrap();
        let args = arguments(&["renew"], &request);
        let report = render_renew(
            &request,
            &target,
            &args,
            Some("Manually triggered issuance of Certificate apps/web-tls\n"),
        );
        let sections = report["sections"].as_array().unwrap();
        assert_eq!(
            sections[0]["rows"][0],
            json!(["Verdict", "renewal requested"])
        );
        assert_eq!(sections[2]["title"], "cmctl output");
        assert_eq!(
            sections[2]["lines"],
            json!(["Manually triggered issuance of Certificate apps/web-tls"])
        );
        assert_eq!(sections[3]["title"], "Next");
    }

    #[test]
    fn only_the_exact_string_true_is_a_dry_run() {
        let mut request = renew_request();
        assert!(dry_run(&request));
        for value in ["True", "yes", "1", "false", ""] {
            request.inputs.insert("dry_run".into(), value.into());
            assert!(!dry_run(&request), "{value:?} must not be a dry run");
        }
        request.inputs.remove("dry_run");
        assert!(!dry_run(&request));
    }

    #[test]
    fn bounded_read_keeps_a_prefix_and_drains_the_rest() {
        let reader = std::io::repeat(b'x').take(2 * 1024 * 1024);
        let captured = bounded_read(reader, 1024).unwrap();
        assert_eq!(captured.bytes.len(), 1024);
        assert!(captured.truncated);
        let captured = bounded_read(&b"short"[..], 1024).unwrap();
        assert_eq!(captured.bytes, b"short");
        assert!(!captured.truncated);
    }

    #[test]
    fn bounded_read_propagates_read_failures() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        let error = bounded_read(Failing, 1024).unwrap_err();
        assert_eq!(error.to_string(), "boom");
    }

    #[test]
    fn the_replay_file_is_bounded() {
        let dir = std::env::temp_dir().join(format!("cert-manager-bound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("large.txt");
        std::fs::write(&path, vec![b'x'; REPLAY_MAX_BYTES + 1]).unwrap();
        let mut request = status_request();
        request
            .inputs
            .insert("replay".into(), path.to_string_lossy().into_owned());
        let error = run(Action::Status, &request).unwrap_err();
        assert!(error.contains("exceeds 1 MiB"), "{error}");
        request.inputs.insert(
            "replay".into(),
            dir.join("missing.txt").to_string_lossy().into_owned(),
        );
        assert!(
            run(Action::Status, &request)
                .unwrap_err()
                .contains("cannot read")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A fake tool on disk; the adapter never starts a shell itself.
    #[cfg(unix)]
    fn fake_tool(name: &str, script: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("cert-manager-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    }

    #[cfg(unix)]
    #[test]
    fn a_tool_that_floods_stderr_still_finishes() {
        let (dir, tool) = fake_tool(
            "noisy",
            "head -c 2097152 /dev/zero | tr '\\0' e >&2\nprintf 'Name: web-tls\\n'",
        );
        let output = execute_tool(tool.to_str().unwrap(), &[], "").unwrap();
        assert_eq!(output, "Name: web-tls\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_tool_that_writes_over_the_limit_is_an_error_not_a_partial_report() {
        let (dir, tool) = fake_tool("flood", "head -c 2097152 /dev/zero | tr '\\0' e");
        let error = execute_tool(tool.to_str().unwrap(), &[], "").unwrap_err();
        assert!(error.contains("more than 1 MiB"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_tool_reports_its_stderr() {
        let (dir, tool) = fake_tool(
            "failing",
            "echo 'partial' \necho 'error: certificates.cert-manager.io \"web-tls\" not found' >&2\nexit 1",
        );
        let args = vec!["renew".to_string(), "web-tls".to_string()];
        let error = execute_tool(tool.to_str().unwrap(), &args, "").unwrap_err();
        assert!(error.contains("renew web-tls failed"), "{error}");
        assert!(error.contains("not found"), "{error}");
        assert!(!error.contains("partial"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_missing_tool_points_at_its_installation() {
        let error = execute_tool(
            "cert-manager-no-such-tool",
            &[],
            "https://example.com/install",
        )
        .unwrap_err();
        assert!(error.contains("failed to start"), "{error}");
        assert!(error.contains("https://example.com/install"), "{error}");
    }
}
