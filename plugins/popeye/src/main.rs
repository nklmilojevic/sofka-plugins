//! Popeye scan adapter. Runs the Popeye CLI for the context and namespace sofka
//! is showing and renders its JSON report as a sofka plugin report.
//!
//! The JSON is parsed straight from the child's pipe under a shared line budget,
//! so a scan of a large cluster never has to be held in memory in full.

mod activity;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

/// Popeye ships standalone and as a Krew plugin; both spellings are accepted.
const EXECUTABLES: &[&str] = &["popeye", "kubectl-popeye"];
const INSTALL: &str = "https://github.com/derailed/popeye#installation";
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
    let saved = request.inputs.get("report").map_or("", String::as_str);
    let envelope = if saved.is_empty() {
        scan(&context, &namespace)?
    } else {
        let file = std::fs::File::open(saved)
            .map_err(|e| format!("cannot read saved Popeye report {saved}: {e}"))?;
        parse(file)?
    };
    Ok(render(envelope, &context, &namespace))
}

// ---------------------------------------------------------------- discovery --

/// Find a standalone or Krew-installed Popeye on the process PATH.
fn detect() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    detect_in_path(&path, std::env::current_exe().ok().as_deref())
}

/// PATH-parameterized so discovery stays testable without mutating the
/// environment Rust's parallel test runner shares. `own` is this adapter, which
/// is itself named `popeye` inside the package: a package directory that ends up
/// on PATH must not make the adapter invoke itself.
fn detect_in_path(path: &OsStr, own: Option<&Path>) -> Option<PathBuf> {
    let own = own.and_then(|path| path.canonicalize().ok());
    for dir in std::env::split_paths(path) {
        for name in EXECUTABLES {
            let candidate = dir.join(name);
            if !is_executable(&candidate) {
                continue;
            }
            if candidate.canonicalize().ok() == own {
                continue;
            }
            return Some(absolute(candidate));
        }
    }
    None
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

fn configure(command: &mut Command, context: &str, namespace: &str) {
    command.args([
        "--out",
        "json",
        "--force-exit-zero",
        "--log-level",
        "0",
        "--logs",
        "none",
    ]);
    if !context.is_empty() {
        command.arg("--context").arg(context);
    }
    if namespace.is_empty() {
        command.arg("--all-namespaces");
    } else {
        command.arg("--namespace").arg(namespace);
    }
}

fn scan(context: &str, namespace: &str) -> Result<Envelope, String> {
    let executable =
        detect().ok_or_else(|| format!("popeye is not on PATH; install it from {INSTALL}"))?;
    let mut command = Command::new(&executable);
    configure(&mut command, context, namespace);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to start {}: {e}", executable.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture Popeye stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture Popeye stderr".to_string())?;
    let _ = writeln!(
        std::io::stderr(),
        "Popeye Kubernetes scan started; waiting for scanner results"
    );
    // Drain stderr independently while stdout remains the final JSON report.
    let errors =
        std::thread::spawn(move || activity::relay(stderr, std::io::stderr(), STDERR_MAX_BYTES));
    let mut stdout = CapturingReader::new(stdout, STDERR_MAX_BYTES);
    let parsed = parse(&mut stdout);
    if parsed.is_err() {
        // Stop reading mid-document and Popeye dies of SIGPIPE, which would
        // then be reported instead of whatever actually went wrong. Take the
        // rest of what it had to say first. CapturingReader retains the bounded
        // prefix already consumed by serde together with this remainder.
        let _ = bounded_read(&mut stdout, 0);
    }
    let stdout = stdout.captured;
    let status = child
        .wait()
        .map_err(|e| format!("failed while waiting for Popeye: {e}"))?;
    let stderr = errors
        .join()
        .map_err(|_| "Popeye diagnostic reader panicked".to_string())?
        .map_err(|e| format!("cannot read Popeye diagnostics: {e}"))?;
    match parsed {
        Ok(envelope) if status.success() => {
            let _ = writeln!(std::io::stderr(), "Popeye scan finished; preparing report");
            Ok(envelope)
        }
        Ok(_) => Err(scan_error(None, &status.to_string(), &stdout, &stderr)),
        Err(error) => Err(scan_error(
            Some(error),
            &status.to_string(),
            &stdout,
            &stderr,
        )),
    }
}

/// What a failed scan should say. When Popeye produced no usable report, its own
/// diagnosis beats ours — including when it died of SIGPIPE because this process
/// stopped reading a document it could not parse.
fn scan_error(parse_error: Option<String>, status: &str, stdout: &[u8], stderr: &[u8]) -> String {
    match parse_error {
        Some(error) => match diagnosis(stdout) {
            // Popeye's own account of why it gave up.
            Some(detail) => format!("Popeye failed: {detail}"),
            // It printed a document this process could not read. The parser
            // knows where that broke; stderr here is usually a client-go
            // warning that had nothing to do with it.
            None if first_line(stdout).is_some() => error,
            // It printed nothing at all, so stderr is the only evidence left.
            None => first_line(stderr).map_or(error, |detail| format!("Popeye failed: {detail}")),
        },
        None => format!(
            "Popeye exited with {status}: {}",
            first_line(stderr).unwrap_or("no error output")
        ),
    }
}

struct CapturingReader<R> {
    inner: R,
    captured: Vec<u8>,
    limit: usize,
}

impl<R> CapturingReader<R> {
    fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            captured: Vec::new(),
            limit,
        }
    }
}

impl<R: Read> Read for CapturingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        let keep = read.min(self.limit.saturating_sub(self.captured.len()));
        self.captured.extend_from_slice(&buffer[..keep]);
        Ok(read)
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

/// The first line Popeye wrote to stdout, unless that line is the report
/// itself. A document that failed to parse starts with `{`, and "Popeye
/// failed: {" hides the parser error that actually explains the failure.
fn diagnosis(stdout: &[u8]) -> Option<&str> {
    first_line(stdout).filter(|line| !line.starts_with(['{', '[']))
}

fn first_line(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
}

/// `serde_json::from_reader` pulls one byte per `Read::read`, so an unbuffered
/// source costs a syscall per byte of the report. Popeye emits megabytes.
fn parse(reader: impl Read) -> Result<Envelope, String> {
    serde_json::from_reader(std::io::BufReader::with_capacity(256 * 1024, reader))
        .map_err(|e| format!("invalid JSON from Popeye: {e}"))
}

// ------------------------------------------------------------------ budgeting --

/// One line allowance shared by the whole report. Popeye can raise an issue for
/// every resource in a cluster, so the renderer stops rather than grows.
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

/// A block rendered under its own allowance, so a single linter with a finding
/// for every resource in the cluster is bounded while it is parsed, before the
/// shared budget decides how much of it survives.
#[derive(Default)]
struct Block {
    lines: Vec<String>,
    truncated: bool,
}

// ------------------------------------------------------------------- parsing --

#[derive(Deserialize)]
struct Envelope {
    popeye: Report,
    #[serde(rename = "ClusterName", default)]
    cluster_name: String,
    #[serde(rename = "ContextName", default)]
    context_name: String,
}

struct Report {
    report_time: String,
    score: i64,
    grade: String,
    linters: usize,
    sections: Vec<Rendered>,
    errors: Vec<String>,
    truncated: bool,
}

/// One linter's findings, already rendered.
struct Rendered {
    title: String,
    lines: Vec<String>,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum ReportField {
    #[serde(rename = "report_time")]
    ReportTime,
    #[serde(rename = "score")]
    Score,
    #[serde(rename = "grade")]
    Grade,
    #[serde(rename = "sections")]
    Sections,
    #[serde(rename = "errors")]
    Errors,
    #[serde(other)]
    Other,
}

impl<'de> Deserialize<'de> for Report {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReportVisitor;

        impl<'de> Visitor<'de> for ReportVisitor {
            type Value = Report;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye report object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut report_time = None;
                let mut score = None;
                let mut grade = None;
                let mut budget = Budget::new();
                let mut linters = 0;
                let mut sections = Vec::new();
                let mut errors = Vec::new();

                while let Some(field) = map.next_key()? {
                    match field {
                        ReportField::ReportTime => report_time = Some(map.next_value()?),
                        ReportField::Score => score = Some(map.next_value()?),
                        ReportField::Grade => grade = Some(map.next_value()?),
                        ReportField::Sections => map.next_value_seed(SectionsSeed {
                            budget: &mut budget,
                            linters: &mut linters,
                            sections: &mut sections,
                        })?,
                        ReportField::Errors => map.next_value_seed(ErrorsSeed {
                            budget: &mut budget,
                            errors: &mut errors,
                        })?,
                        ReportField::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }

                Ok(Report {
                    report_time: report_time.unwrap_or_default(),
                    score: score.ok_or_else(|| M::Error::missing_field("score"))?,
                    grade: grade.unwrap_or_default(),
                    linters,
                    sections,
                    errors,
                    truncated: budget.truncated,
                })
            }
        }

        deserializer.deserialize_map(ReportVisitor)
    }
}

#[derive(Default, Deserialize)]
struct Tally {
    #[serde(default)]
    ok: usize,
    #[serde(default)]
    info: usize,
    #[serde(default, rename = "warning")]
    warnings: usize,
    #[serde(default)]
    error: usize,
    #[serde(default)]
    score: i64,
}

#[derive(Deserialize)]
struct Issue {
    #[serde(default)]
    level: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Section {
    linter: String,
    #[serde(default)]
    gvr: String,
    #[serde(default)]
    tally: Tally,
    #[serde(default)]
    issues: Issues,
}

struct SectionsSeed<'a> {
    budget: &'a mut Budget,
    linters: &'a mut usize,
    sections: &'a mut Vec<Rendered>,
}

impl<'de> DeserializeSeed<'de> for SectionsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SectionsVisitor<'a> {
            budget: &'a mut Budget,
            linters: &'a mut usize,
            sections: &'a mut Vec<Rendered>,
        }

        impl<'de> Visitor<'de> for SectionsVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye sections array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while self.budget.accepting() {
                    let Some(section) = seq.next_element::<Section>()? else {
                        return Ok(());
                    };
                    *self.linters += 1;
                    self.sections.push(render_section(self.budget, section));
                }
                // Drain the rest so the stream stays well formed, and record
                // that the report the user sees is not the whole report.
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    *self.linters += 1;
                    self.budget.truncated = true;
                    while seq.next_element::<IgnoredAny>()?.is_some() {
                        *self.linters += 1;
                    }
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(SectionsVisitor {
            budget: self.budget,
            linters: self.linters,
            sections: self.sections,
        })
    }
}

/// A linter's resource-to-issues map, rendered under its own allowance.
#[derive(Default)]
struct Issues(Block);

impl<'de> Deserialize<'de> for Issues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssuesVisitor;

        impl<'de> Visitor<'de> for IssuesVisitor {
            type Value = Issues;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye resource-to-issues object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut budget = Budget::new();
                let mut block = Block::default();
                while budget.accepting() {
                    let Some(resource) = map.next_key::<String>()? else {
                        break;
                    };
                    budget.push(&mut block.lines, format!("  {resource}"));
                    map.next_value_seed(IssueListSeed {
                        budget: &mut budget,
                        lines: &mut block.lines,
                    })?;
                }
                if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    budget.truncated = true;
                    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                }
                block.truncated = budget.truncated;
                Ok(Issues(block))
            }
        }

        deserializer.deserialize_map(IssuesVisitor)
    }
}

struct IssueListSeed<'a> {
    budget: &'a mut Budget,
    lines: &'a mut Vec<String>,
}

impl<'de> DeserializeSeed<'de> for IssueListSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssueListVisitor<'a> {
            budget: &'a mut Budget,
            lines: &'a mut Vec<String>,
        }

        impl<'de> Visitor<'de> for IssueListVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye issue array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while self.budget.accepting() {
                    let Some(issue) = seq.next_element::<Issue>()? else {
                        return Ok(());
                    };
                    let level = match issue.level {
                        3 => "ERROR",
                        2 => "WARNING",
                        1 => "INFO",
                        _ => "OK",
                    };
                    self.budget
                        .push(self.lines, format!("    {level} {}", issue.message));
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    self.budget.truncated = true;
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(IssueListVisitor {
            budget: self.budget,
            lines: self.lines,
        })
    }
}

struct ErrorsSeed<'a> {
    budget: &'a mut Budget,
    errors: &'a mut Vec<String>,
}

impl<'de> DeserializeSeed<'de> for ErrorsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ErrorsVisitor<'a> {
            budget: &'a mut Budget,
            errors: &'a mut Vec<String>,
        }

        impl<'de> Visitor<'de> for ErrorsVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye errors object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                while self.budget.accepting() {
                    let Some((_key, error)) = map.next_entry::<IgnoredAny, String>()? else {
                        return Ok(());
                    };
                    self.budget.push(self.errors, error);
                }
                if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    self.budget.truncated = true;
                    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_map(ErrorsVisitor {
            budget: self.budget,
            errors: self.errors,
        })
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

/// Put the report together within sofka's limit, dropping linter sections from
/// the end until the serialized bytes fit. The summary is never dropped: its
/// score and counts describe the whole scan even when the detail below them
/// does not. Popeye's own errors are kept ahead of that detail, because they
/// are what explains a partial scan.
fn assemble(
    rows: Vec<Value>,
    sections: Vec<Value>,
    errors: Option<Value>,
    truncated: bool,
    notice: &str,
) -> Value {
    let summary = json!({
        "title": "Summary",
        "columns": ["Field", "Value"],
        "rows": rows,
    });
    let notice_section = json!({"title": "Notice", "lines": [notice]});
    // Reserve the widest shape the framing can take, so trimming the detail
    // can never overshoot.
    let mut reserved = serialized_len(&json!({
        "schema_version": 1,
        "title": "Popeye scan",
        "sections": [],
    })) + serialized_len(&summary)
        + serialized_len(&notice_section)
        + 2;
    let mut truncated = truncated;
    let errors = errors.and_then(|section| {
        let cost = serialized_len(&section) + 1;
        if reserved + cost > REPORT_MAX_SERIALIZED_BYTES {
            truncated = true;
            return None;
        }
        reserved += cost;
        Some(section)
    });
    let mut kept = Vec::new();
    for section in sections {
        let cost = serialized_len(&section) + 1;
        if reserved + cost > REPORT_MAX_SERIALIZED_BYTES {
            truncated = true;
            break;
        }
        reserved += cost;
        kept.push(section);
    }
    let mut out = vec![summary];
    out.append(&mut kept);
    out.extend(errors);
    if truncated {
        out.push(notice_section);
    }
    json!({
        "schema_version": 1,
        "title": "Popeye scan",
        "sections": out,
    })
}

fn render_section(budget: &mut Budget, section: Section) -> Rendered {
    let mut title = field(&section.linter);
    let _ = write!(title, " — {}%", section.tally.score);
    if !section.gvr.is_empty() {
        let _ = write!(title, " ({})", field(&section.gvr));
    }
    let mut lines = Vec::new();
    budget.push(
        &mut lines,
        format!(
            "ok {} · info {} · warning {} · error {}",
            section.tally.ok, section.tally.info, section.tally.warnings, section.tally.error
        ),
    );
    budget.absorb(&mut lines, section.issues.0);
    Rendered { title, lines }
}

fn render(envelope: Envelope, requested_context: &str, requested_namespace: &str) -> Value {
    let Envelope {
        popeye,
        cluster_name,
        context_name,
    } = envelope;
    let Report {
        report_time,
        score,
        grade,
        linters,
        sections,
        errors,
        truncated,
    } = popeye;
    // Popeye reports the context it actually scanned; prefer it over the one
    // sofka asked for, which may have been inferred.
    let context = if context_name.is_empty() {
        requested_context
    } else {
        &context_name
    };
    let mut rows = vec![json!(["Score", format!("{score}% ({grade})")])];
    if !context.is_empty() {
        rows.push(json!(["Context", field(context)]));
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
    if !report_time.is_empty() {
        rows.push(json!(["Scanned", field(&report_time)]));
    }
    rows.push(json!(["Linters", linters.to_string()]));

    let sections: Vec<Value> = sections
        .into_iter()
        .map(|section| json!({"title": section.title, "lines": section.lines}))
        .collect();
    let errors = (!errors.is_empty()).then(|| json!({"title": "Report errors", "lines": errors}));
    let notice = if requested_namespace.is_empty() {
        "… report truncated; scan one namespace at a time to see the rest"
    } else {
        "… report truncated; inspect the full Popeye JSON output to see the rest"
    };
    assemble(rows, sections, errors, truncated, notice)
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
        // The scope in the request fixture is what produces the report fixture;
        // CI additionally runs the binary over both from the repository root.
        assert_eq!(
            render(
                parsed(SCAN),
                request.context.as_deref().unwrap_or_default(),
                request.namespace.as_deref().unwrap_or_default(),
            ),
            expected
        );
    }

    #[test]
    fn the_request_fixture_points_at_the_scan_fixture() {
        let request: Request =
            serde_json::from_str(include_str!("../fixtures/request.json")).unwrap();
        assert_eq!(request.schema_version, 1);
        // CI runs the adapter from the repository root.
        assert_eq!(
            request.inputs.get("report").map(String::as_str),
            Some("plugins/popeye/fixtures/scan.json")
        );
    }

    #[test]
    fn rejects_unknown_request_schema() {
        let request: Request = serde_json::from_value(json!({"schema_version": 2})).unwrap();
        assert!(
            run(&request)
                .unwrap_err()
                .contains("unsupported request schema_version")
        );
    }

    #[test]
    fn a_missing_saved_report_is_an_error_and_never_starts_a_scan() {
        let request: Request = serde_json::from_value(json!({
            "schema_version": 1,
            "inputs": {"report": "does/not/exist.json"},
        }))
        .unwrap();
        assert!(
            run(&request)
                .unwrap_err()
                .contains("cannot read saved Popeye report")
        );
    }

    #[test]
    fn levels_and_tallies_render_as_the_document_view_shows_them() {
        let report = render(parsed(SCAN), "ignored", "default");
        let sections = report["sections"].as_array().unwrap();
        assert_eq!(report["title"], "Popeye scan");
        // Popeye's own context wins over the one sofka asked for.
        assert_eq!(sections[0]["rows"][1], json!(["Context", "docker-desktop"]));
        // Every linter Popeye ran gets a section, clean ones included: the
        // tally line is the whole report for those.
        assert_eq!(sections[1]["title"], "configmaps — 100% (v1/configmaps)");
        let services = sections
            .iter()
            .find(|s| s["title"] == "services — 20% (v1/services)")
            .expect("no services section");
        let lines: Vec<&str> = services["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line.as_str().unwrap())
            .collect();
        assert_eq!(
            &lines[..5],
            [
                "ok 1 · info 0 · warning 0 · error 4",
                "  default/lb-proxy-hyper",
                "    ERROR [POP-1100] No pods match service selector",
                "    WARNING [POP-1110] Match EP has no subsets",
                "    INFO [POP-1104] Do you mean it? Type NodePort detected",
            ]
        );
        let errors = sections.last().unwrap();
        assert_eq!(errors["title"], "Report errors");
        assert_eq!(
            errors["lines"][0],
            "the server could not find the requested resource"
        );
    }

    #[test]
    fn an_unnamespaced_scan_reports_every_namespace() {
        let report = render(parsed(SCAN), "prod", "");
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Namespace", "all"])));
    }

    #[test]
    fn unknown_fields_and_absent_optional_fields_are_tolerated() {
        let minimal = r#"{"popeye": {"score": 100, "unknown": [1, 2]}}"#;
        let report = render(parsed(minimal), "dev", "default");
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert_eq!(rows[0], json!(["Score", "100% ()"]));
        assert!(rows.contains(&json!(["Context", "dev"])));
        assert!(rows.contains(&json!(["Linters", "0"])));
        // No Scanned row, because Popeye reported no time.
        assert!(!rows.iter().any(|row| row[0] == "Scanned"));
        assert_eq!(report["sections"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_report_without_a_score_is_not_a_report() {
        assert!(parse(r#"{"popeye": {"grade": "A"}}"#.as_bytes()).is_err());
        assert!(parse(b"not json".as_slice()).is_err());
    }

    #[test]
    fn an_unbounded_scan_is_truncated_with_a_notice() {
        let issues: Vec<String> = (0..REPORT_MAX_LINES + 100)
            .map(|i| format!(r#"{{"level": 2, "message": "issue {i}"}}"#))
            .collect();
        let json = format!(
            r#"{{"popeye": {{"score": 1, "sections": [
                {{"linter": "pods", "tally": {{}}, "issues": {{"ns/a": [{}]}}}},
                {{"linter": "services", "tally": {{}}, "issues": {{}}}}
            ]}}}}"#,
            issues.join(",")
        );
        let report = render(parsed(&json), "dev", "default");
        let sections = report["sections"].as_array().unwrap();
        assert_eq!(sections.last().unwrap()["title"], "Notice");
        let rendered = serde_json::to_vec(&report).unwrap();
        assert!(rendered.len() < 1024 * 1024, "{} bytes", rendered.len());
        assert!(sections[1]["lines"].as_array().unwrap().len() <= REPORT_MAX_LINES);
        // The budget is shared, so a linter that exhausts it costs the linters
        // after it. The notice is the only promise made about what is missing.
        assert!(
            !sections
                .iter()
                .any(|section| section["title"] == "services — 0%")
        );
        assert!(
            sections[0]["rows"]
                .as_array()
                .unwrap()
                .contains(&json!(["Linters", "2"]))
        );
        assert_eq!(
            sections.last().unwrap()["lines"][0],
            "… report truncated; inspect the full Popeye JSON output to see the rest"
        );
    }

    #[test]
    fn popeye_is_invoked_with_a_bounded_machine_readable_scan() {
        let arguments = |context: &str, namespace: &str| {
            let mut command = Command::new("popeye");
            configure(&mut command, context, namespace);
            command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            arguments("prod", "apps"),
            [
                "--out",
                "json",
                "--force-exit-zero",
                "--log-level",
                "0",
                "--logs",
                "none",
                "--context",
                "prod",
                "--namespace",
                "apps",
            ]
        );
        assert_eq!(arguments("", "").last().unwrap(), "--all-namespaces");
    }

    #[test]
    fn discovery_accepts_both_spellings_and_never_selects_this_adapter() {
        let dir = std::env::temp_dir().join(format!("sofka-popeye-{}", std::process::id()));
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
        let own = package.join("popeye");
        write(&own);
        let path = std::env::join_paths([&package, &system]).unwrap();

        // With only this adapter on PATH, there is no Popeye to run.
        assert_eq!(detect_in_path(&path, Some(&own)), None);
        // Without the guard it would find itself.
        assert_eq!(detect_in_path(&path, None), Some(own.clone()));

        let krew = system.join("kubectl-popeye");
        write(&krew);
        assert_eq!(detect_in_path(&path, Some(&own)), Some(krew.clone()));

        // A standalone Popeye earlier on PATH wins over the Krew spelling.
        let standalone = system.join("popeye");
        write(&standalone);
        assert_eq!(detect_in_path(&path, Some(&own)), Some(standalone));

        let empty = std::ffi::OsString::from("");
        assert_eq!(detect_in_path(&empty, None), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Every byte the line budget counts can become six once serialized, and
    /// section titles never pass through that budget at all. What sofka
    /// measures is the serialized report, so that is what has to fit.
    #[test]
    fn an_escape_heavy_report_still_fits_sofkas_limit() {
        // A control character serializes as \u0000: one byte in, six out.
        let noisy = r"\u0001".repeat(400);
        let issues: Vec<String> = (0..REPORT_MAX_LINES)
            .map(|i| format!(r#"{{"level":2,"message":"[POP-{i}] {noisy}"}}"#))
            .collect();
        // A linter name is attacker-controlled too, and the title it becomes
        // costs nothing against the line budget.
        let json = format!(
            r#"{{"popeye":{{"score":1,"grade":"F","sections":[
                {{"linter":"{linter}","gvr":"{gvr}","tally":{{}},"issues":{{"ns/a":[{issues}]}}}}
            ]}}}}"#,
            linter = "l".repeat(100_000),
            gvr = "g".repeat(100_000),
            issues = issues.join(","),
        );
        let report = render(parsed(&json), "ctx", "ns");
        let rendered = serde_json::to_vec(&report).unwrap();
        assert!(rendered.len() <= 1024 * 1024, "{} bytes", rendered.len());
        // The summary survives whatever happens to the detail below it.
        assert_eq!(report["sections"][0]["title"], "Summary");
        assert_eq!(
            report["sections"].as_array().unwrap().last().unwrap()["title"],
            "Notice"
        );
    }

    #[test]
    fn one_oversized_field_cannot_crowd_out_the_report() {
        let json = format!(
            r#"{{"popeye":{{"score":10,"grade":"D","sections":[]}},"ClusterName":"{}"}}"#,
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
    fn a_failed_scan_reports_what_popeye_said_rather_than_how_it_died() {
        // Popeye writes fatal errors to stdout. That diagnosis wins over an
        // unrelated client-go warning on stderr and our JSON parse error.
        assert_eq!(
            scan_error(
                Some("invalid JSON from Popeye: EOF".into()),
                "signal: 13 (SIGPIPE)",
                b"Boom! Kubernetes cluster unreachable\n",
                b"E0911 couldn't get current server API group list\n",
            ),
            "Popeye failed: Boom! Kubernetes cluster unreachable"
        );
        // Nothing on stderr either: our own parse error is all there is.
        assert_eq!(
            scan_error(
                Some("invalid JSON from Popeye: EOF".into()),
                "exit status: 1",
                b"",
                b""
            ),
            "invalid JSON from Popeye: EOF"
        );
        // A report that broke part way through is not a diagnosis. Its first
        // line is "{", which says nothing the parser error does not say
        // better, and the warning on stderr is unrelated.
        assert_eq!(
            scan_error(
                Some("invalid JSON from Popeye: expected `,` at line 9".into()),
                "exit status: 0",
                b"{\n  \"popeye\": {\n    \"score\": 85\n",
                b"E0911 couldn't get current server API group list\n",
            ),
            "invalid JSON from Popeye: expected `,` at line 9"
        );
        // Popeye said nothing at all: stderr is all there is to go on.
        assert_eq!(
            scan_error(
                Some("invalid JSON from Popeye: EOF".into()),
                "exit status: 1",
                b"",
                b"stat kubeconfig: no such file or directory\n",
            ),
            "Popeye failed: stat kubeconfig: no such file or directory"
        );
        // A complete report from a run that still failed keeps the status.
        assert_eq!(
            scan_error(None, "exit status: 2", b"", b"partial scan\n"),
            "Popeye exited with exit status: 2: partial scan"
        );
        assert_eq!(
            scan_error(None, "exit status: 2", b"", b""),
            "Popeye exited with exit status: 2: no error output"
        );
    }

    #[test]
    fn a_bounded_reader_keeps_only_its_limit_and_finds_the_first_message() {
        let bytes = bounded_read(&b"abcdefgh"[..], 3);
        assert_eq!(bytes, b"abc");

        let mut stdout = CapturingReader::new(&b"Boom! cluster unreachable\n"[..], 64);
        assert!(parse(&mut stdout).is_err());
        let _ = bounded_read(&mut stdout, 0);
        assert_eq!(
            first_line(&stdout.captured),
            Some("Boom! cluster unreachable")
        );

        assert_eq!(first_line(b"\n\n  boom  \nnext"), Some("boom"));
        assert_eq!(first_line(b"   \n"), None);
        assert_eq!(first_line(&[0xff, 0xfe]), None);
    }
}
