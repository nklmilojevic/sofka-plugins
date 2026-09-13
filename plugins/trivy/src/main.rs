//! Trivy scan adapter. Runs `trivy kubernetes` for the context and namespace
//! sofka is showing and renders its JSON report as a sofka plugin report.
//!
//! The JSON is parsed straight from the child's pipe under a shared line budget:
//! a cluster-wide scan can name a finding for every image in every workload, and
//! none of that has to be held in memory at once.

mod progress;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

const EXECUTABLE: &str = "trivy";
const INSTALL: &str = "https://trivy.dev/latest/getting-started/installation/";
const REQUEST_MAX_BYTES: usize = 1024 * 1024;
const STDERR_MAX_BYTES: usize = 64 * 1024;
/// Sofka refuses a report over 1 MiB, so the rendered text stops well short of
/// it: JSON escaping and section framing still have to fit.
const REPORT_MAX_LINES: usize = 4_000;
const REPORT_MAX_BYTES: usize = 512 * 1024;
/// The limit sofka actually enforces, measured the way sofka measures it. The
/// line budget above counts unescaped bytes and never sees section titles or
/// summary values, so the finished report is weighed against this before it
/// goes out.
const REPORT_MAX_SERIALIZED_BYTES: usize = 1024 * 1024;
/// A value copied out of the scan is displayed, not trusted. No single field
/// may crowd out the report around it.
const FIELD_MAX_BYTES: usize = 256;

#[derive(Deserialize)]
struct Request {
    schema_version: u32,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), String> {
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
    let output = serde_json::to_vec(&run(&request)?).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|e| e.to_string())
}

fn run(request: &Request) -> Result<Value, String> {
    if request.schema_version != 1 {
        return Err("unsupported request schema_version".into());
    }
    let context = request.context.clone().unwrap_or_default();
    let namespace = request.namespace.clone().unwrap_or_default();
    let scan_mode = ScanMode::from_inputs(&request.inputs)?;
    let saved = request.inputs.get("report").map_or("", String::as_str);
    let envelope = if saved.is_empty() {
        scan(&context, &namespace, scan_mode)?
    } else {
        let file = std::fs::File::open(saved)
            .map_err(|e| format!("cannot read saved Trivy report {saved}: {e}"))?;
        parse(file)?
    };
    Ok(render(envelope, &context, &namespace))
}

// ---------------------------------------------------------------- discovery --

fn detect() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    detect_in_path(&path, std::env::current_exe().ok().as_deref())
}

/// PATH-parameterized so discovery stays testable without mutating the shared
/// environment. `own` is this adapter: a package directory that ends up on PATH
/// must not make it invoke itself.
fn detect_in_path(path: &OsStr, own: Option<&Path>) -> Option<PathBuf> {
    let own = own.and_then(|path| path.canonicalize().ok());
    std::env::split_paths(path)
        .map(|dir| dir.join(EXECUTABLE))
        .find(|candidate| is_executable(candidate) && candidate.canonicalize().ok() != own)
        .map(absolute)
}

fn absolute(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&path))
            .unwrap_or(path)
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

// ------------------------------------------------------------------ scanning --

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanMode {
    All,
    Misconfig,
}

impl ScanMode {
    fn from_inputs(inputs: &BTreeMap<String, String>) -> Result<Self, String> {
        match inputs.get("scan").map_or("all", String::as_str) {
            "all" => Ok(Self::All),
            "misconfig" => Ok(Self::Misconfig),
            value => Err(format!("scan must be all or misconfig, got {value:?}")),
        }
    }
}

fn configure(command: &mut Command, context: &str, namespace: &str, scan_mode: ScanMode) {
    // Keep pb/v3 output recognizable even if the shell selects a font-specific bar.
    command.env("UNICODE_PROGRESS_BAR", "false");
    command.args([
        "kubernetes",
        "--format",
        "json",
        "--report",
        "all",
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
        "--list-all-pkgs=false",
        "--disable-node-collector",
        "--exit-code",
        "0",
        "--timeout",
        "29m",
    ]);
    if scan_mode == ScanMode::Misconfig {
        command.args(["--scanners", "misconfig"]);
    }
    if !namespace.is_empty() {
        command.arg("--include-namespaces").arg(namespace);
    }
    if !context.is_empty() {
        // Trivy takes the kubeconfig context as the sole positional argument.
        command.arg("--").arg(context);
    }
}

fn scan(context: &str, namespace: &str, scan_mode: ScanMode) -> Result<Envelope, String> {
    let executable =
        detect().ok_or_else(|| format!("trivy is not on PATH; install it from {INSTALL}"))?;
    let mut command = Command::new(&executable);
    configure(&mut command, context, namespace, scan_mode);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to start {}: {e}", executable.display()))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture Trivy stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture Trivy stderr".to_string())?;
    // Drain stderr on its own thread: a chatty scan that fills the pipe would
    // otherwise block Trivy while this process waits on stdout.
    let errors = std::thread::spawn(move || {
        relay_diagnostics(stderr, std::io::stderr().lock(), STDERR_MAX_BYTES)
    });
    let parsed = parse(&mut stdout);
    if parsed.is_err() {
        // Stop reading mid-document and Trivy dies of SIGPIPE, which would then
        // be reported instead of whatever actually went wrong.
        bounded_read(&mut stdout, STDERR_MAX_BYTES);
    }
    drop(stdout);
    let status = child
        .wait()
        .map_err(|e| format!("failed while waiting for Trivy: {e}"))?;
    let stderr = errors
        .join()
        .map_err(|_| "Trivy diagnostic reader panicked".to_string())?
        .map_err(|e| format!("cannot read Trivy diagnostics: {e}"))?;
    match parsed {
        Ok(envelope) if status.success() => Ok(envelope),
        Ok(_) => Err(scan_error(None, &status.to_string(), &stderr)),
        Err(error) => Err(scan_error(Some(error), &status.to_string(), &stderr)),
    }
}

/// What a failed scan should say. When Trivy produced no usable report, its own
/// diagnosis beats ours — including when it died of SIGPIPE because this process
/// stopped reading a document it could not parse.
fn scan_error(parse_error: Option<String>, status: &str, stderr: &[u8]) -> String {
    match parse_error {
        Some(error) => match last_line(stderr) {
            Some(detail) => format!("Trivy failed: {detail}"),
            None => error,
        },
        None => format!(
            "Trivy exited with {status}: {}",
            last_line(stderr).unwrap_or("no error output")
        ),
    }
}

fn bounded_read(mut reader: impl Read, limit: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 8 * 1024];
    while let Ok(read) = reader.read(&mut chunk) {
        if read == 0 {
            break;
        }
        let keep = read.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk[..keep]);
    }
    bytes
}

/// Forward a bounded diagnostic prefix and retain a bounded tail for errors.
/// Keep draining after the relay limit or a write error so Trivy can finish.
fn relay_diagnostics(
    mut reader: impl Read,
    mut writer: impl std::io::Write,
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    let mut tail = Vec::new();
    let mut forwarded = 0;
    let mut truncated = false;
    let mut write_error = None;
    let mut normalizer = progress::ProgressText::default();
    let mut chunk = [0; 8 * 1024];
    if let Err(error) = writer
        .write_all(b"Starting Trivy scan...\n")
        .and_then(|()| writer.flush())
    {
        write_error = Some(error);
    }
    loop {
        let read = match reader.read(&mut chunk) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        let text = normalizer.feed(&chunk[..read], read == 0);
        let keep = text.len().min(limit);
        let remove = tail.len().saturating_add(keep).saturating_sub(limit);
        tail.drain(..remove);
        tail.extend_from_slice(&text[text.len() - keep..]);
        if write_error.is_none() {
            let send = text.len().min(limit.saturating_sub(forwarded));
            let result = (|| {
                writer.write_all(&text[..send])?;
                forwarded += send;
                if send < text.len() && !truncated {
                    writer.write_all(b"\n[Trivy activity truncated; scan continues]\n")?;
                    truncated = true;
                }
                writer.flush()
            })();
            if let Err(error) = result {
                write_error = Some(error);
            }
        }
        if read == 0 {
            break;
        }
    }
    // Preserve the report and error tail even when activity cannot be written.
    Ok(tail)
}

fn last_line(bytes: &[u8]) -> Option<&str> {
    // The retained tail can start inside a UTF-8 character. Its last line is
    // still useful, so decode only that line when choosing an error summary.
    bytes
        .rsplit(|byte| matches!(byte, b'\r' | b'\n'))
        .filter_map(|line| std::str::from_utf8(line).ok())
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("Trivy progress: "))
}

/// `serde_json::from_reader` pulls one byte per `Read::read`, so an unbuffered
/// source costs a syscall per byte of the report. Trivy emits megabytes.
fn parse(reader: impl Read) -> Result<Envelope, String> {
    let envelope: Envelope =
        serde_json::from_reader(std::io::BufReader::with_capacity(256 * 1024, reader))
            .map_err(|e| format!("invalid JSON from Trivy: {e}"))?;
    if let Some(schema_version) = envelope.schema_version
        && schema_version != 2
    {
        return Err(format!("unsupported Trivy SchemaVersion {schema_version}"));
    }
    Ok(envelope)
}

// ------------------------------------------------------------------ budgeting --

/// One line allowance shared by the whole report. A cluster-wide scan can raise
/// a finding for every image in every workload, so the renderer stops rather
/// than grows.
struct Budget {
    lines: usize,
    bytes: usize,
    truncated: bool,
}

impl Budget {
    fn new() -> Self {
        Self {
            lines: REPORT_MAX_LINES,
            bytes: REPORT_MAX_BYTES,
            truncated: false,
        }
    }

    fn accepting(&self) -> bool {
        !self.truncated && self.lines > 0
    }

    fn push(&mut self, lines: &mut Vec<String>, line: String) -> bool {
        if self.truncated || self.lines == 0 || line.len() > self.bytes {
            self.truncated = true;
            return false;
        }
        self.lines -= 1;
        self.bytes -= line.len();
        lines.push(line);
        true
    }

    /// Move an independently budgeted block in, stopping at the shared limit.
    fn absorb(&mut self, lines: &mut Vec<String>, block: Block) {
        for line in block.lines {
            if !self.push(lines, line) {
                return;
            }
        }
        self.truncated |= block.truncated;
    }
}

/// A block rendered under its own allowance, so one resource with thousands of
/// findings is bounded while it is parsed.
#[derive(Default)]
struct Block {
    lines: Vec<String>,
    truncated: bool,
}

// ------------------------------------------------------------------- severity --

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
enum Severity {
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "LOW")]
    Low,
    #[default]
    #[serde(other)]
    Unknown,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Counts {
    vulnerabilities: usize,
    misconfigurations: usize,
    secrets: usize,
    errors: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    unknown: usize,
}

impl Counts {
    fn record(&mut self, kind: Kind, severity: Severity) {
        match kind {
            Kind::Vulnerability => self.vulnerabilities += 1,
            Kind::Misconfiguration => self.misconfigurations += 1,
            Kind::Secret => self.secrets += 1,
        }
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Unknown => self.unknown += 1,
        }
    }

    fn merge(&mut self, other: Self) {
        self.vulnerabilities += other.vulnerabilities;
        self.misconfigurations += other.misconfigurations;
        self.secrets += other.secrets;
        self.errors += other.errors;
        self.critical += other.critical;
        self.high += other.high;
        self.medium += other.medium;
        self.low += other.low;
        self.unknown += other.unknown;
    }

    fn findings(self) -> usize {
        self.vulnerabilities + self.misconfigurations + self.secrets
    }

    fn tally(self) -> String {
        format!(
            "{} vulnerabilities · {} misconfigurations · {} secrets · C {} H {} M {} L {} U {}",
            self.vulnerabilities,
            self.misconfigurations,
            self.secrets,
            self.critical,
            self.high,
            self.medium,
            self.low,
            self.unknown
        )
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Vulnerability,
    Misconfiguration,
    Secret,
}

// ------------------------------------------------------------------- parsing --

struct Envelope {
    // Kubernetes reports currently omit their zero-valued schema field. If a
    // Trivy report supplies one, accept only the version used by JSON reports.
    schema_version: Option<u32>,
    cluster_name: String,
    /// `all` reports use Resources; consolidated `summary` reports use Findings.
    findings: Scanned,
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EnvelopeVisitor;

        impl<'de> Visitor<'de> for EnvelopeVisitor {
            type Value = Envelope;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy Kubernetes report")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Envelope, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut schema_version = None;
                let mut cluster_name = String::new();
                let mut findings = None;
                let mut unknown: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "SchemaVersion" => schema_version = map.next_value()?,
                        "ClusterName" => cluster_name = map.next_value()?,
                        "Resources" | "Findings" => findings = Some(map.next_value()?),
                        _ => {
                            // Remember the first unfamiliar key. Trivy grows new
                            // fields over time and they are ignored, but if no
                            // resource list turns up at all then one of them is
                            // the likeliest explanation.
                            if unknown.is_none() {
                                unknown = Some(key);
                            }
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                let findings = match (findings, unknown) {
                    (Some(findings), _) => findings,
                    // A scan that matched nothing omits the list entirely, so
                    // an otherwise familiar report without one is a clean
                    // empty result, not a failure.
                    (None, None) => Scanned::default(),
                    // No resource list and a field we do not recognise: the
                    // list has most likely been renamed, and reporting zero
                    // findings for that would be a lie.
                    (None, Some(key)) => {
                        return Err(serde::de::Error::custom(format!(
                            "Trivy report has no Resources or Findings; \
                             found unknown field {key} where the list should be"
                        )));
                    }
                };
                Ok(Envelope {
                    schema_version,
                    cluster_name,
                    findings,
                })
            }
        }

        deserializer.deserialize_map(EnvelopeVisitor)
    }
}

/// Every resource Trivy reported on, already rendered.
#[derive(Default)]
struct Scanned {
    resources: Vec<Rendered>,
    affected: usize,
    counts: Counts,
    truncated: bool,
}

struct Rendered {
    title: String,
    lines: Vec<String>,
}

impl<'de> Deserialize<'de> for Scanned {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScannedVisitor;

        impl<'de> Visitor<'de> for ScannedVisitor {
            type Value = Scanned;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy findings array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut budget = Budget::new();
                let mut scanned = Scanned::default();
                while let Some(finding) = seq.next_element::<Finding>()? {
                    render_finding(&mut budget, &mut scanned, finding);
                }
                scanned.truncated = budget.truncated;
                Ok(scanned)
            }
        }

        deserializer.deserialize_seq(ScannedVisitor)
    }
}

#[derive(Deserialize)]
struct Finding {
    #[serde(rename = "Namespace", default)]
    namespace: String,
    #[serde(rename = "Kind", default)]
    kind: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Results", default)]
    results: Results,
    #[serde(rename = "Error", default)]
    error: String,
}

/// One resource's results, rendered under their own allowance.
#[derive(Default)]
struct Results {
    block: Block,
    counts: Counts,
}

impl<'de> Deserialize<'de> for Results {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResultsVisitor;

        impl<'de> Visitor<'de> for ResultsVisitor {
            type Value = Results;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy results array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut budget = Budget::new();
                let mut results = Results::default();
                while let Some(result) = seq.next_element_seed(ResultSeed {
                    budget: &mut budget,
                    lines: &mut results.block.lines,
                })? {
                    results.counts.merge(result);
                }
                results.block.truncated = budget.truncated;
                Ok(results)
            }
        }

        deserializer.deserialize_seq(ResultsVisitor)
    }
}

/// One `Results` entry: a target plus its vulnerabilities, misconfigurations,
/// and secrets. Each list is rendered as it is read.
struct ResultSeed<'a> {
    budget: &'a mut Budget,
    lines: &'a mut Vec<String>,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum ResultField {
    #[serde(rename = "Vulnerabilities")]
    Vulnerabilities,
    #[serde(rename = "Misconfigurations")]
    Misconfigurations,
    #[serde(rename = "Secrets")]
    Secrets,
    #[serde(other)]
    Other,
}

impl<'de> DeserializeSeed<'de> for ResultSeed<'_> {
    type Value = Counts;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResultVisitor<'a> {
            budget: &'a mut Budget,
            lines: &'a mut Vec<String>,
        }

        impl<'de> Visitor<'de> for ResultVisitor<'_> {
            type Value = Counts;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy result object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut counts = Counts::default();
                while let Some(field) = map.next_key()? {
                    let kind = match field {
                        ResultField::Vulnerabilities => Kind::Vulnerability,
                        ResultField::Misconfigurations => Kind::Misconfiguration,
                        ResultField::Secrets => Kind::Secret,
                        ResultField::Other => {
                            map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    };
                    map.next_value_seed(ItemsSeed {
                        kind,
                        budget: self.budget,
                        lines: self.lines,
                        counts: &mut counts,
                    })?;
                }
                Ok(counts)
            }
        }

        deserializer.deserialize_map(ResultVisitor {
            budget: self.budget,
            lines: self.lines,
        })
    }
}

struct ItemsSeed<'a> {
    kind: Kind,
    budget: &'a mut Budget,
    lines: &'a mut Vec<String>,
    counts: &'a mut Counts,
}

impl<'de> DeserializeSeed<'de> for ItemsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ItemsVisitor<'a> {
            kind: Kind,
            budget: &'a mut Budget,
            lines: &'a mut Vec<String>,
            counts: &'a mut Counts,
        }

        impl<'de> Visitor<'de> for ItemsVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy finding array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                loop {
                    let should_render = self.budget.accepting();
                    let finding = match self.kind {
                        Kind::Vulnerability => seq
                            .next_element::<Vulnerability>()?
                            .map(|item| (item.severity, should_render.then(|| item.render()))),
                        Kind::Misconfiguration => seq
                            .next_element::<Misconfiguration>()?
                            .map(|item| (item.severity, should_render.then(|| item.render()))),
                        Kind::Secret => seq
                            .next_element::<Secret>()?
                            .map(|item| (item.severity, should_render.then(|| item.render()))),
                    };
                    let Some((severity, line)) = finding else {
                        return Ok(());
                    };
                    self.counts.record(self.kind, severity);
                    if let Some(line) = line {
                        self.budget.push(self.lines, line);
                    } else {
                        self.budget.truncated = true;
                    }
                }
            }
        }

        deserializer.deserialize_seq(ItemsVisitor {
            kind: self.kind,
            budget: self.budget,
            lines: self.lines,
            counts: self.counts,
        })
    }
}

#[derive(Deserialize)]
struct Vulnerability {
    #[serde(rename = "VulnerabilityID", default)]
    id: String,
    #[serde(rename = "PkgName", default)]
    package: String,
    #[serde(rename = "InstalledVersion", default)]
    installed: String,
    #[serde(rename = "FixedVersion", default)]
    fixed: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
}

impl Vulnerability {
    fn render(&self) -> String {
        let mut line = format!("  [vulnerability] {} {}", self.severity.label(), self.id);
        if !self.package.is_empty() {
            let _ = write!(line, " · {}@{}", self.package, self.installed);
        }
        if !self.fixed.is_empty() {
            let _ = write!(line, " → {}", self.fixed);
        }
        if !self.title.is_empty() {
            let _ = write!(line, " — {}", self.title);
        }
        line
    }
}

#[derive(Deserialize)]
struct Misconfiguration {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Message", default)]
    message: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
}

impl Misconfiguration {
    fn render(&self) -> String {
        let mut line = format!("  [misconfiguration] {} {}", self.severity.label(), self.id);
        let detail = if self.title.is_empty() {
            &self.message
        } else {
            &self.title
        };
        if !detail.is_empty() {
            let _ = write!(line, " — {detail}");
        }
        line
    }
}

#[derive(Deserialize)]
struct Secret {
    #[serde(rename = "RuleID", default)]
    id: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Category", default)]
    category: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
}

impl Secret {
    fn render(&self) -> String {
        let mut line = format!("  [secret] {} {}", self.severity.label(), self.id);
        let detail = if self.title.is_empty() {
            &self.category
        } else {
            &self.title
        };
        if !detail.is_empty() {
            let _ = write!(line, " — {detail}");
        }
        line
    }
}

// ----------------------------------------------------------------- rendering --

/// Shorten a value taken from the scan, cutting on a character boundary.
fn field(value: &str) -> String {
    if value.len() <= FIELD_MAX_BYTES {
        return value.to_string();
    }
    let mut end = FIELD_MAX_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

fn serialized_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// Put the report together within sofka's limit, dropping resource sections
/// from the end until the serialized bytes fit. The summary is never dropped:
/// its counts describe the whole scan even when the detail below them does
/// not, which is what the partial marker says.
fn assemble(mut rows: Vec<Value>, details: Vec<Value>, truncated: bool, notice: &str) -> Value {
    let partial = json!(["Detail", "partial — rendered sections truncated"]);
    let summarize = |rows: &[Value]| {
        json!({
            "title": "Summary",
            "columns": ["Field", "Value"],
            "rows": rows,
        })
    };
    let notice_section = json!({"title": "Notice", "lines": [notice]});
    // Reserve the widest shape the framing can take — the summary carrying its
    // partial marker, plus the notice — so trimming can never overshoot.
    let mut widest = rows.clone();
    widest.push(partial.clone());
    let mut used = serialized_len(&json!({
        "schema_version": 1,
        "title": "Trivy scan",
        "sections": [],
    })) + serialized_len(&summarize(&widest))
        + serialized_len(&notice_section)
        + 2;
    let mut truncated = truncated;
    let mut kept = Vec::new();
    for section in details {
        let cost = serialized_len(&section) + 1;
        if used + cost > REPORT_MAX_SERIALIZED_BYTES {
            truncated = true;
            break;
        }
        used += cost;
        kept.push(section);
    }
    if truncated {
        rows.push(partial);
    }
    let mut sections = vec![summarize(&rows)];
    sections.append(&mut kept);
    if truncated {
        sections.push(notice_section);
    }
    json!({
        "schema_version": 1,
        "title": "Trivy scan",
        "sections": sections,
    })
}

/// A resource with nothing to report is left out entirely: a cluster-wide scan
/// touches every workload, and listing the clean ones would bury the findings.
fn render_finding(budget: &mut Budget, scanned: &mut Scanned, finding: Finding) {
    let mut counts = finding.results.counts;
    if !finding.error.is_empty() {
        counts.errors += 1;
    }
    if counts.findings() == 0 && counts.errors == 0 {
        return;
    }
    scanned.affected += 1;
    scanned.counts.merge(counts);

    if !budget.accepting() {
        budget.truncated = true;
        return;
    }

    let mut title = String::new();
    if !finding.namespace.is_empty() {
        let _ = write!(title, "{} · ", field(&finding.namespace));
    }
    let _ = write!(title, "{}/{}", field(&finding.kind), field(&finding.name));

    let mut lines = Vec::new();
    budget.push(&mut lines, counts.tally());
    budget.absorb(&mut lines, finding.results.block);
    if !finding.error.is_empty() {
        budget.push(&mut lines, format!("  ERROR {}", finding.error));
    }
    scanned.resources.push(Rendered { title, lines });
}

fn render(envelope: Envelope, requested_context: &str, requested_namespace: &str) -> Value {
    let Envelope {
        cluster_name,
        findings,
        ..
    } = envelope;
    let counts = findings.counts;
    let mut rows = vec![
        json!(["Findings", counts.findings().to_string()]),
        json!(["Critical", counts.critical.to_string()]),
        json!(["High", counts.high.to_string()]),
        json!(["Medium", counts.medium.to_string()]),
        json!(["Low", counts.low.to_string()]),
        json!(["Vulnerabilities", counts.vulnerabilities.to_string()]),
        json!(["Misconfigurations", counts.misconfigurations.to_string()]),
        json!(["Secrets", counts.secrets.to_string()]),
    ];
    if !requested_context.is_empty() {
        rows.push(json!(["Context", field(requested_context)]));
    }
    if !cluster_name.is_empty() {
        rows.push(json!(["Cluster", field(&cluster_name)]));
    }
    rows.push(json!([
        "Namespace",
        if requested_namespace.is_empty() {
            "all".to_string()
        } else {
            field(requested_namespace)
        }
    ]));
    rows.push(json!(["Resources", findings.affected.to_string()]));
    if counts.errors > 0 {
        rows.push(json!(["Scan errors", counts.errors.to_string()]));
    }

    let details: Vec<Value> = findings
        .resources
        .into_iter()
        .map(|resource| json!({"title": resource.title, "lines": resource.lines}))
        .collect();
    let notice = if requested_namespace.is_empty() {
        "… report truncated; scan one namespace at a time to see the rest"
    } else {
        "… report truncated; inspect the full Trivy JSON output to see the rest"
    };
    assemble(rows, details, findings.truncated, notice)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCAN: &str = include_str!("../fixtures/scan.json");

    fn parsed(json: &str) -> Envelope {
        parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn fixture_matches_expected_report() {
        let request: Request =
            serde_json::from_str(include_str!("../fixtures/request.json")).unwrap();
        let expected: Value =
            serde_json::from_str(include_str!("../fixtures/report.json")).unwrap();
        assert_eq!(
            render(
                parsed(SCAN),
                request.context.as_deref().unwrap_or_default(),
                request.namespace.as_deref().unwrap_or_default(),
            ),
            expected
        );
        // CI runs the adapter from the repository root.
        assert_eq!(
            request.inputs.get("report").map(String::as_str),
            Some("plugins/trivy/fixtures/scan.json")
        );
    }

    #[test]
    fn every_finding_kind_is_counted_and_rendered() {
        let report = render(parsed(SCAN), "docker-desktop", "");
        let sections = report["sections"].as_array().unwrap();
        let rows: Vec<(String, String)> = sections[0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r[0].as_str().unwrap().into(), r[1].as_str().unwrap().into()))
            .collect();
        let value = |name: &str| rows.iter().find(|(k, _)| k == name).unwrap().1.clone();
        assert_eq!(value("Findings"), "9");
        assert_eq!(value("Critical"), "1");
        assert_eq!(value("High"), "3");
        assert_eq!(value("Medium"), "1");
        assert_eq!(value("Low"), "3");
        assert_eq!(value("Vulnerabilities"), "6");
        assert_eq!(value("Misconfigurations"), "3");
        assert_eq!(value("Scan errors"), "1");

        // Trivy emits the config scan and the image scan of one workload as
        // two entries, so the workload gets a section for each.
        assert_eq!(sections[1]["title"], "traefik · Deployment/traefik");
        assert_eq!(sections[2]["title"], "traefik · Deployment/traefik");
        let lines: Vec<&str> = sections[2]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        assert!(lines[1].starts_with("  [vulnerability] HIGH CVE-2026-14456"));
        assert!(lines[1].contains("libcrypto3@3.5.7-r0 → 3.5.8-r0"));
        let misconfigs: Vec<&str> = sections[1]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        assert!(misconfigs[1].starts_with("  [misconfiguration] MEDIUM KSV-0001"));
        // A Go advisory carries no severity of its own.
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("  [vulnerability] UNKNOWN GO-2026-5932"))
        );
    }

    #[test]
    fn a_clean_resource_is_omitted_and_a_failed_one_is_kept() {
        let report = render(parsed(SCAN), "docker-desktop", "");
        let titles: Vec<&str> = report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["title"].as_str().unwrap())
            .collect();
        // The fixture's ServiceAccount was scanned and found clean.
        assert!(!titles.iter().any(|t| t.contains("ServiceAccount")));
        // The image scan of this Deployment failed and produced no results at
        // all. `--report all` still carries the entry, which is why the
        // adapter asks for it: the consolidated `summary` report drops it and
        // the workload would read as clean.
        let errored = report["sections"][3].clone();
        assert_eq!(errored["title"], "kube-system · Deployment/coredns");
        assert!(
            errored["lines"][1]
                .as_str()
                .unwrap()
                .starts_with("  ERROR scan error: scan failed:")
        );
    }

    #[test]
    fn the_summary_findings_spelling_is_accepted() {
        let renamed = SCAN.replacen("\"Resources\"", "\"Findings\"", 1);
        let report = render(parsed(&renamed), "docker-desktop", "");
        assert_eq!(report["sections"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn unknown_severities_and_absent_fields_are_tolerated() {
        let json = r#"{"Findings":[{"Kind":"Pod","Name":"p","Results":[{
            "Vulnerabilities":[{"VulnerabilityID":"X","Severity":"NOPE"}],
            "Unknown":[{"whatever":1}]}]}]}"#;
        let report = render(parsed(json), "", "");
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Findings", "1"])));
        assert!(rows.contains(&json!(["Namespace", "all"])));
        assert!(!rows.iter().any(|r| r[0] == "Context"));
        assert!(
            report["sections"][1]["lines"][1]
                .as_str()
                .unwrap()
                .contains("[vulnerability] UNKNOWN X")
        );
    }

    /// Synthetic on purpose: the captured cluster holds no secret for Trivy to
    /// find, so this is the one finding kind the fixture cannot prove.
    #[test]
    fn a_secret_is_rendered_like_the_other_finding_kinds() {
        let json = r#"{"Resources":[{"Namespace":"apps","Kind":"Pod","Name":"p","Results":[{
            "Secrets":[{"RuleID":"generic-api-key","Title":"API key","Severity":"MEDIUM"}]}]}]}"#;
        let report = render(parsed(json), "", "apps");
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Secrets", "1"])));
        assert!(
            report["sections"][1]["lines"][1]
                .as_str()
                .unwrap()
                .starts_with("  [secret] MEDIUM generic-api-key")
        );
    }

    #[test]
    fn an_unbounded_scan_is_truncated_with_a_notice() {
        let items: Vec<String> = (0..REPORT_MAX_LINES + 100)
            .map(|i| format!(r#"{{"VulnerabilityID":"CVE-{i}","Severity":"LOW"}}"#))
            .collect();
        let json = format!(
            r#"{{"Findings":[
                {{"Kind":"Pod","Name":"noisy","Results":[{{"Vulnerabilities":[{}]}}]}},
                {{"Kind":"Pod","Name":"later","Results":[{{"Secrets":[{{"RuleID":"k"}}]}}]}}
            ]}}"#,
            items.join(",")
        );
        let report = render(parsed(&json), "dev", "default");
        let sections = report["sections"].as_array().unwrap();
        assert_eq!(sections.last().unwrap()["title"], "Notice");
        assert_eq!(
            sections.last().unwrap()["lines"][0],
            "… report truncated; inspect the full Trivy JSON output to see the rest"
        );
        let rows = sections[0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Findings", (REPORT_MAX_LINES + 101).to_string()])));
        assert!(rows.contains(&json!(["Low", (REPORT_MAX_LINES + 100).to_string()])));
        assert!(rows.contains(&json!(["Resources", "2"])));
        assert!(rows.contains(&json!(["Detail", "partial — rendered sections truncated"])));
        let rendered = serde_json::to_vec(&report).unwrap();
        assert!(rendered.len() < 1024 * 1024, "{} bytes", rendered.len());
    }

    /// Every byte the line budget counts can become six once serialized, and
    /// section titles never pass through that budget at all. What sofka
    /// measures is the serialized report, so that is what has to fit.
    /// A scan that matched nothing omits the list entirely. This is the exact
    /// body `trivy kubernetes --format json --report all` wrote for a
    /// namespace that does not exist.
    #[test]
    fn a_scan_that_found_nothing_is_a_clean_report_not_a_failure() {
        let report = render(
            parsed(
                r#"{
  "ClusterName": "docker-desktop"
}
"#,
            ),
            "docker-desktop",
            "empty-scan-test",
        );
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Findings", "0"])));
        assert!(rows.contains(&json!(["Resources", "0"])));
        assert!(rows.contains(&json!(["Cluster", "docker-desktop"])));
        // Nothing to show, so nothing but the summary.
        assert_eq!(report["sections"].as_array().unwrap().len(), 1);
        // An explicitly empty list reads the same way.
        assert_eq!(
            render(parsed(r#"{"ClusterName":"c","Resources":[]}"#), "", ""),
            render(parsed(r#"{"ClusterName":"c"}"#), "", "")
        );
    }

    /// The other reason the list can be missing is that it was renamed, and
    /// reporting zero findings for that would be a lie.
    #[test]
    fn a_renamed_resource_list_fails_instead_of_reporting_nothing() {
        let error = match parse(
            br#"{"ClusterName":"c","Discoveries":[{"Kind":"Pod","Name":"p"}]}"#.as_slice(),
        ) {
            Ok(_) => panic!("a renamed resource list parsed as an empty report"),
            Err(error) => error,
        };
        assert!(error.contains("unknown field Discoveries"), "{error}");
        // A new field Trivy adds alongside a list that is present stays
        // ignored: only a missing list makes an unfamiliar key suspicious.
        assert!(
            parse(br#"{"ClusterName":"c","SomethingNew":{"a":1},"Resources":[]}"#.as_slice())
                .is_ok()
        );
    }

    #[test]
    fn an_escape_heavy_report_still_fits_sofkas_limit() {
        // A control character serializes as \u0000: one byte in, six out.
        let noisy = r"\u0001".repeat(400);
        let items: Vec<String> = (0..REPORT_MAX_LINES)
            .map(|i| {
                format!(r#"{{"VulnerabilityID":"CVE-{i}","Severity":"LOW","Title":"{noisy}"}}"#)
            })
            .collect();
        // Titles are attacker-controlled too, and a long one costs nothing
        // against the line budget.
        let json = format!(
            r#"{{"Resources":[{{"Kind":"Pod","Namespace":"{ns}","Name":"{name}","Results":[{{"Vulnerabilities":[{items}]}}]}}]}}"#,
            ns = "n".repeat(100_000),
            name = "p".repeat(100_000),
            items = items.join(","),
        );
        let report = render(parsed(&json), "ctx", "ns");
        let rendered = serde_json::to_vec(&report).unwrap();
        assert!(rendered.len() <= 1024 * 1024, "{} bytes", rendered.len());
        // The counts still describe the whole scan, and the report says so.
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Findings", REPORT_MAX_LINES.to_string()])));
        assert!(rows.contains(&json!(["Detail", "partial — rendered sections truncated"])));
        assert_eq!(
            report["sections"].as_array().unwrap().last().unwrap()["title"],
            "Notice"
        );
    }

    #[test]
    fn one_oversized_field_cannot_crowd_out_the_report() {
        let json = format!(
            r#"{{"ClusterName":"{}","Resources":[{{"Kind":"Pod","Name":"p","Results":[{{"Secrets":[{{"RuleID":"k"}}]}}]}}]}}"#,
            "c".repeat(50_000)
        );
        let report = render(parsed(&json), "", "");
        let cluster = report["sections"][0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row[0] == "Cluster")
            .unwrap()[1]
            .as_str()
            .unwrap()
            .to_string();
        assert!(cluster.len() <= FIELD_MAX_BYTES + 4, "{}", cluster.len());
        assert!(cluster.ends_with('…'));
    }

    #[test]
    fn rejects_unknown_request_schema_and_a_missing_saved_report() {
        let request: Request = serde_json::from_value(json!({"schema_version": 2})).unwrap();
        assert!(
            run(&request)
                .unwrap_err()
                .contains("unsupported request schema_version")
        );
        assert!(parse(br#"{"SchemaVersion":1,"Resources":[]}"#.as_slice()).is_err());
        assert!(parse(br#"{"SchemaVersion":2,"Resources":[]}"#.as_slice()).is_ok());
        // A report carrying nothing but a cluster name is what an empty scan
        // really looks like, so it parses; see the two tests above for what
        // separates that from a renamed list.
        assert!(parse(br#"{"ClusterName":"empty scan"}"#.as_slice()).is_ok());
        let request: Request = serde_json::from_value(json!({
            "schema_version": 1,
            "inputs": {"report": "does/not/exist.json"},
        }))
        .unwrap();
        assert!(
            run(&request)
                .unwrap_err()
                .contains("cannot read saved Trivy report")
        );
    }

    #[test]
    fn trivy_is_invoked_with_the_context_as_its_positional_argument() {
        let arguments = |context: &str, namespace: &str, scan_mode: ScanMode| {
            let mut command = Command::new("trivy");
            configure(&mut command, context, namespace, scan_mode);
            command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let scoped = arguments("prod", "apps", ScanMode::All);
        assert_eq!(&scoped[..4], ["kubernetes", "--format", "json", "--report"]);
        assert!(scoped.contains(&"--disable-telemetry".to_string()));
        assert!(scoped.contains(&"--no-progress".to_string()));
        assert!(!scoped.contains(&"--quiet".to_string()));
        assert!(scoped.contains(&"--disable-node-collector".to_string()));
        // --include-namespaces takes the namespace; the context is positional.
        let namespace = scoped
            .iter()
            .position(|a| a == "--include-namespaces")
            .unwrap();
        assert_eq!(scoped[namespace + 1], "apps");
        assert_eq!(&scoped[scoped.len() - 2..], ["--", "prod"]);
        assert!(scoped.windows(2).any(|args| args == ["--exit-code", "0"]));
        assert!(!scoped.contains(&"--parallel".to_string()));

        let quick = arguments("prod", "apps", ScanMode::Misconfig);
        assert!(
            quick
                .windows(2)
                .any(|args| args == ["--scanners", "misconfig"])
        );
        // No namespace means every namespace, and no context means the current one.
        let unscoped = arguments("", "", ScanMode::All);
        assert!(!unscoped.contains(&"--include-namespaces".to_string()));
        assert_eq!(unscoped.last().unwrap(), "29m");
    }

    #[test]
    fn a_failed_scan_reports_what_trivy_said_rather_than_how_it_died() {
        assert_eq!(
            scan_error(
                Some("invalid JSON from Trivy: EOF".into()),
                "signal: 13 (SIGPIPE)",
                b"FATAL kubernetes scan error: unable to reach the cluster\n",
            ),
            "Trivy failed: FATAL kubernetes scan error: unable to reach the cluster"
        );
        assert_eq!(
            scan_error(
                Some("invalid JSON from Trivy: EOF".into()),
                "exit status: 1",
                b""
            ),
            "invalid JSON from Trivy: EOF"
        );
        assert_eq!(
            scan_error(None, "exit status: 2", b""),
            "Trivy exited with exit status: 2: no error output"
        );
    }

    #[test]
    fn diagnostics_are_forwarded_before_eof_and_flushed() {
        use std::cell::RefCell;
        use std::rc::Rc;

        struct Writer(Rc<RefCell<Vec<u8>>>);
        impl std::io::Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        struct Reader {
            output: Rc<RefCell<Vec<u8>>>,
            read: bool,
        }
        impl Read for Reader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.read {
                    assert!(self.output.borrow().ends_with(b"Scanning image...\n"));
                    return Ok(0);
                }
                assert!(
                    self.output
                        .borrow()
                        .starts_with(b"Starting Trivy scan...\n")
                );
                self.read = true;
                let message = b"Scanning image...\n";
                buf[..message.len()].copy_from_slice(message);
                Ok(message.len())
            }
        }
        let output = Rc::new(RefCell::new(Vec::new()));
        let tail = relay_diagnostics(
            Reader {
                output: output.clone(),
                read: false,
            },
            std::io::BufWriter::new(Writer(output)),
            STDERR_MAX_BYTES,
        )
        .unwrap();
        assert_eq!(tail, b"Scanning image...\n");
    }

    #[test]
    fn diagnostics_are_bounded_but_drained_and_keep_the_final_error() {
        let mut input = std::io::Cursor::new(vec![b'x'; STDERR_MAX_BYTES * 3]);
        input
            .get_mut()
            .extend_from_slice(b"\nFATAL unable to scan\n");
        let mut output = Vec::new();
        let tail = relay_diagnostics(&mut input, &mut output, STDERR_MAX_BYTES).unwrap();
        assert_eq!(input.position() as usize, input.get_ref().len());
        assert_eq!(tail.len(), STDERR_MAX_BYTES);
        assert!(output.len() < STDERR_MAX_BYTES + 128);
        assert_eq!(
            String::from_utf8(output)
                .unwrap()
                .matches("activity truncated")
                .count(),
            1
        );
        assert_eq!(
            scan_error(None, "exit status: 1", &tail),
            "Trivy exited with exit status: 1: FATAL unable to scan"
        );
        assert_eq!(
            last_line(b"\x80\nINFO starting\nFATAL failed\n"),
            Some("FATAL failed")
        );
    }

    #[test]
    fn repeated_pipe_bars_do_not_exhaust_the_live_diagnostic_budget() {
        let bar = format!("2 / 81 [-->{}] 2.47% ? p/s", "_".repeat(6000));
        let input = format!(
            "{}8 / 81 [--->____] 9.88% 1 p/s\nFATAL example\n",
            bar.repeat(100)
        );
        let mut output = Vec::new();
        let tail = relay_diagnostics(input.as_bytes(), &mut output, STDERR_MAX_BYTES).unwrap();
        assert!(output.len() < 256);
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.matches("2 / 81").count(), 1);
        assert!(text.contains("8 / 81 (9.88%)"));
        assert!(!text.contains("truncated"));
        assert_eq!(last_line(&tail), Some("FATAL example"));
    }

    #[test]
    fn diagnostic_read_errors_propagate_but_write_errors_preserve_capture() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("read failed"))
            }
        }
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("write failed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            relay_diagnostics(Broken, Vec::new(), 10)
                .unwrap_err()
                .to_string(),
            "read failed"
        );
        let mut input = std::io::Cursor::new(vec![b'x'; 30_000]);
        assert_eq!(
            relay_diagnostics(&mut input, Broken, 10).unwrap(),
            vec![b'x'; 10]
        );
        assert_eq!(input.position(), 30_000);
    }

    #[test]
    fn normalized_progress_does_not_mask_parse_errors_or_real_diagnostics() {
        let progress = b"\rTrivy progress: 8 / 81 (9.88%) 1 p/s";
        assert_eq!(
            scan_error(Some("invalid JSON".into()), "exit status: 0", progress),
            "invalid JSON"
        );
        let mut stderr = b"FATAL database unavailable\n".to_vec();
        stderr.extend_from_slice(progress);
        assert_eq!(
            scan_error(Some("invalid JSON".into()), "exit status: 1", &stderr),
            "Trivy failed: FATAL database unavailable"
        );
        assert_eq!(last_line(progress), None);
    }

    #[test]
    fn discovery_never_selects_this_adapter() {
        let dir = std::env::temp_dir().join(format!("sofka-trivy-{}", std::process::id()));
        let package = dir.join("package");
        let system = dir.join("system");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir_all(&system).unwrap();
        let write = |path: &Path| {
            std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        };
        let own = package.join("trivy");
        write(&own);
        let path = std::env::join_paths([&package, &system]).unwrap();
        assert_eq!(detect_in_path(&path, Some(&own)), None);
        assert_eq!(detect_in_path(&path, None), Some(own.clone()));
        let system_trivy = system.join("trivy");
        write(&system_trivy);
        assert_eq!(detect_in_path(&path, Some(&own)), Some(system_trivy));
        let _ = std::fs::remove_dir_all(dir);
    }
}
