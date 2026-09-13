//! HTTP benchmark adapter. Sends load at the selected pod or service with oha
//! and renders its JSON report.
//!
//! Unlike the cluster scanners, this one needs a reachable URL. It does not
//! build one: sofka opens (or reuses) a port-forward and names the local port
//! in the request, so the adapter never shells out to kubectl and never has to
//! guess whether an address is routable from here.

mod activity;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;
use serde_json::{Value, json};

const EXECUTABLE: &str = "oha";
const INSTALL: &str = "https://github.com/hatoo/oha#installation";
const REQUEST_MAX_BYTES: usize = 1024 * 1024;
const STDERR_MAX_BYTES: usize = 64 * 1024;
/// Distribution maps are remote input; cap what is rendered from them.
const MAX_DISTRIBUTION_ROWS: usize = 64;

#[derive(Deserialize)]
struct Request {
    schema_version: u32,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
    #[serde(default)]
    forward: Option<Forward>,
}

/// Sofka fills this in once the forward is ready.
#[derive(Clone, Deserialize)]
struct Forward {
    host: String,
    local_port: u16,
    remote_port: u16,
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
    let forward = request.forward.clone().ok_or_else(|| {
        "sofka did not open a port-forward; run this on a pod or service".to_string()
    })?;
    let options = Options::from(&request.inputs)?;
    let url = url(&forward, &options.path);
    let saved = request.inputs.get("report").map_or("", String::as_str);
    let report = if saved.is_empty() {
        benchmark(&url, &options)?
    } else {
        let file = std::fs::File::open(saved)
            .map_err(|e| format!("cannot read saved oha report {saved}: {e}"))?;
        parse(file)?
    };
    Ok(render(report, request, &forward, &options, &url))
}

fn url(forward: &Forward, path: &str) -> String {
    let host = if forward.host.is_empty() {
        "127.0.0.1"
    } else {
        &forward.host
    };
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("http://{host}:{}{path}", forward.local_port)
}

struct Options {
    duration: u64,
    connections: u32,
    rate: u32,
    path: String,
}

impl Options {
    /// Sofka validates every declared input against the manifest before the
    /// adapter runs, so these parse cleanly; the fallbacks keep a hand-built
    /// request from panicking.
    fn from(inputs: &BTreeMap<String, String>) -> Result<Self, String> {
        let seconds = |value: &str| -> Option<u64> {
            let value = value.trim();
            let (digits, unit) = match value.find(|c: char| !c.is_ascii_digit()) {
                Some(i) => value.split_at(i),
                None => (value, "s"),
            };
            let n: u64 = digits.parse().ok()?;
            let per = match unit {
                "s" => 1,
                "m" => 60,
                "h" => 3600,
                _ => return None,
            };
            n.checked_mul(per).filter(|n| *n > 0)
        };
        let duration = inputs
            .get("duration")
            .map_or(Some(10), |v| seconds(v))
            .ok_or_else(|| "duration must be a positive time like \"10s\"".to_string())?;
        let connections = inputs
            .get("connections")
            .map_or(Ok(20), |v| v.parse::<u32>())
            .map_err(|_| "connections must be a positive whole number".to_string())?;
        if connections == 0 {
            return Err("connections must be at least 1".into());
        }
        if connections > 1_000 {
            return Err("connections must be at most 1000".into());
        }
        let rate = inputs
            .get("rate")
            .map_or(Ok(100), |v| v.parse::<u32>())
            .map_err(|_| "rate must be a positive whole number".to_string())?;
        if !(1..=10_000).contains(&rate) {
            return Err("rate must be between 1 and 10000 requests per second".into());
        }
        Ok(Self {
            duration,
            connections,
            rate,
            path: inputs.get("path").cloned().unwrap_or_else(|| "/".into()),
        })
    }
}

// ---------------------------------------------------------------- discovery --

fn detect() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    detect_in_path(&path, std::env::current_exe().ok().as_deref())
}

fn detect_in_path(path: &OsStr, own: Option<&Path>) -> Option<PathBuf> {
    let own = own.and_then(|path| path.canonicalize().ok());
    std::env::split_paths(path)
        .map(|dir| dir.join(EXECUTABLE))
        .find(|candidate| is_executable(candidate) && candidate.canonicalize().ok() != own)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                std::env::current_dir()
                    .map(|c| c.join(&path))
                    .unwrap_or(path)
            }
        })
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

// ----------------------------------------------------------------- execution --

fn configure(command: &mut Command, url: &str, options: &Options) {
    command
        .arg("--no-tui")
        // oha 1.9.0+ selects JSON through the named output format.
        .arg("--output-format")
        .arg("json")
        .arg("-z")
        .arg(format!("{}s", options.duration))
        .arg("-c")
        .arg(options.connections.to_string())
        .arg("-q")
        .arg(options.rate.to_string())
        .arg(url);
}

fn benchmark(url: &str, options: &Options) -> Result<Report, String> {
    let executable =
        detect().ok_or_else(|| format!("oha is not on PATH; install it from {INSTALL}"))?;
    let mut command = Command::new(&executable);
    configure(&mut command, url, options);
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
        .ok_or_else(|| "failed to capture oha stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture oha stderr".to_string())?;
    let progress = activity::Progress::start(options.duration, options.connections, options.rate);
    let errors = std::thread::spawn(move || {
        activity::relay_stderr(stderr, std::io::stderr(), STDERR_MAX_BYTES)
    });
    let parsed = parse(&mut stdout);
    if parsed.is_err() {
        bounded_read(&mut stdout, STDERR_MAX_BYTES);
    }
    drop(stdout);
    let status = child
        .wait()
        .map_err(|e| format!("failed while waiting for oha: {e}"))?;
    // Optional activity must not discard an otherwise complete report.
    let _ = progress.finish();
    let stderr = errors
        .join()
        .map_err(|_| "oha diagnostic reader panicked".to_string())?
        .map_err(|e| format!("cannot read oha diagnostics: {e}"))?;
    match parsed {
        Ok(report) if status.success() => {
            let _ = std::io::stderr().write_all(b"oha finished; preparing report\n");
            Ok(report)
        }
        Ok(_) => Err(run_error(None, &status.to_string(), &stderr)),
        Err(error) => Err(run_error(Some(error), &status.to_string(), &stderr)),
    }
}

/// What a failed run should say. When oha produced no usable report, its own
/// diagnosis beats ours — including when it died of SIGPIPE because this
/// process stopped reading a document it could not parse.
fn run_error(parse_error: Option<String>, status: &str, stderr: &[u8]) -> String {
    match parse_error {
        Some(error) => match first_line(stderr) {
            Some(detail) => format!("oha failed: {detail}"),
            None => error,
        },
        None => format!(
            "oha exited with {status}: {}",
            first_line(stderr).unwrap_or("no error output")
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

fn first_line(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
}

/// `serde_json::from_reader` pulls one byte per `Read::read`, so an unbuffered
/// source costs a syscall per byte.
fn parse(reader: impl Read) -> Result<Report, String> {
    serde_json::from_reader(std::io::BufReader::with_capacity(64 * 1024, reader))
        .map_err(|e| format!("invalid JSON from oha: {e}"))
}

// ------------------------------------------------------------------- parsing --

/// oha's report. A run that completed nothing leaves every statistic null, and
/// that run is exactly the one whose error counts explain what went wrong — so
/// every number here is optional.
#[derive(Deserialize)]
struct Report {
    #[serde(default)]
    summary: Summary,
    #[serde(rename = "latencyPercentiles", default)]
    percentiles: BTreeMap<String, Option<f64>>,
    #[serde(rename = "statusCodeDistribution", default)]
    statuses: BTreeMap<String, u64>,
    #[serde(rename = "errorDistribution", default)]
    errors: BTreeMap<String, u64>,
}

#[derive(Default, Deserialize)]
struct Summary {
    #[serde(rename = "successRate", default)]
    success_rate: Option<f64>,
    #[serde(default)]
    total: Option<f64>,
    #[serde(default)]
    slowest: Option<f64>,
    #[serde(default)]
    fastest: Option<f64>,
    #[serde(default)]
    average: Option<f64>,
    #[serde(rename = "requestsPerSec", default)]
    requests_per_sec: Option<f64>,
    #[serde(rename = "totalData", default)]
    total_data: Option<u64>,
    #[serde(rename = "sizePerRequest", default)]
    size_per_request: Option<u64>,
}

// ----------------------------------------------------------------- rendering --

fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Seconds into the largest unit that keeps three significant figures, which is
/// how a latency reads at a glance: 218µs, 31.0ms, 1.44s.
fn latency(seconds: Option<f64>) -> String {
    let Some(s) = seconds.filter(|s| s.is_finite() && *s >= 0.0) else {
        return "—".into();
    };
    if s < 0.001 {
        format!("{:.0}µs", s * 1_000_000.0)
    } else if s < 1.0 {
        format!("{:.1}ms", s * 1_000.0)
    } else {
        format!("{s:.2}s")
    }
}

fn bytes(value: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// Rows from a remote map, largest first and capped.
fn distribution(map: &BTreeMap<String, u64>) -> (Vec<Value>, usize) {
    let mut rows: Vec<(&String, &u64)> = map.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let dropped = rows.len().saturating_sub(MAX_DISTRIBUTION_ROWS);
    rows.truncate(MAX_DISTRIBUTION_ROWS);
    (
        rows.into_iter()
            .map(|(k, v)| json!([k, thousands(*v)]))
            .collect(),
        dropped,
    )
}

fn render(
    report: Report,
    request: &Request,
    forward: &Forward,
    options: &Options,
    url: &str,
) -> Value {
    let served: u64 = report.statuses.values().sum();
    let failed: u64 = report.errors.values().sum();
    let requests = served + failed;
    let summary = &report.summary;

    let target = format!(
        "{}/{}",
        request.resource.as_deref().unwrap_or("?"),
        request.name.as_deref().unwrap_or("?")
    );
    let mut rows = vec![
        json!(["Target", target]),
        json!(["Namespace", request.namespace.as_deref().unwrap_or("")]),
        json!(["URL", url]),
        json!([
            "Forwarded",
            format!("{} -> {}", forward.local_port, forward.remote_port)
        ]),
        json!([
            "Requested",
            format!(
                "{}s, {} connections, {} requests/s",
                options.duration, options.connections, options.rate
            )
        ]),
        json!(["Requests", thousands(requests)]),
        json!([
            "Success",
            summary
                .success_rate
                .map_or("—".into(), |r| format!("{:.2}%", r * 100.0))
        ]),
        json!([
            "Requests/sec",
            summary
                .requests_per_sec
                .map_or("—".into(), |r| format!("{r:.1}"))
        ]),
        json!([
            "Elapsed",
            summary.total.map_or("—".into(), |t| format!("{t:.2}s"))
        ]),
        json!(["Fastest", latency(summary.fastest)]),
        json!(["Average", latency(summary.average)]),
        json!(["Slowest", latency(summary.slowest)]),
    ];
    for key in ["p50", "p90", "p95", "p99"] {
        rows.push(json!([
            key,
            latency(report.percentiles.get(key).copied().flatten())
        ]));
    }
    if let Some(total) = summary.total_data {
        let per = summary
            .size_per_request
            .map_or(String::new(), |s| format!(" ({} per request)", bytes(s)));
        rows.push(json!(["Data", format!("{}{per}", bytes(total))]));
    }

    let mut sections = vec![json!({
        "title": "Summary",
        "columns": ["Field", "Value"],
        "rows": rows,
    })];
    let (status_rows, status_dropped) = distribution(&report.statuses);
    if !status_rows.is_empty() {
        sections.push(json!({
            "title": if status_dropped > 0 {
                format!("Status codes ({status_dropped} more not shown)")
            } else {
                "Status codes".into()
            },
            "columns": ["Code", "Responses"],
            "rows": status_rows,
        }));
    }
    let (error_rows, error_dropped) = distribution(&report.errors);
    if !error_rows.is_empty() {
        sections.push(json!({
            "title": if error_dropped > 0 {
                format!("Errors ({error_dropped} more not shown)")
            } else {
                "Errors".into()
            },
            "columns": ["Error", "Count"],
            "rows": error_rows,
        }));
    }
    json!({
        "schema_version": 1,
        "title": "HTTP benchmark",
        "sections": sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCAN: &str = include_str!("../fixtures/scan.json");

    fn request() -> Request {
        serde_json::from_str(include_str!("../fixtures/request.json")).unwrap()
    }

    #[test]
    fn fixture_matches_expected_report() {
        let request = request();
        let expected: Value =
            serde_json::from_str(include_str!("../fixtures/report.json")).unwrap();
        let forward = request.forward.clone().unwrap();
        let options = Options::from(&request.inputs).unwrap();
        let url = url(&forward, &options.path);
        assert_eq!(
            render(
                parse(SCAN.as_bytes()).unwrap(),
                &request,
                &forward,
                &options,
                &url
            ),
            expected
        );
        assert_eq!(
            request.inputs.get("report").map(String::as_str),
            Some("plugins/oha/fixtures/scan.json")
        );
    }

    #[test]
    fn a_real_oha_report_renders_the_numbers_it_reported() {
        let request = request();
        let forward = request.forward.clone().unwrap();
        let options = Options::from(&request.inputs).unwrap();
        let report = render(
            parse(SCAN.as_bytes()).unwrap(),
            &request,
            &forward,
            &options,
            &url(&forward, &options.path),
        );
        let rows: Vec<(String, String)> = report["sections"][0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r[0].as_str().unwrap().into(), r[1].as_str().unwrap().into()))
            .collect();
        let value = |name: &str| rows.iter().find(|(k, _)| k == name).unwrap().1.clone();
        // 21,636 served plus the 9 aborted at the deadline.
        assert_eq!(value("Requests"), "21,645");
        assert_eq!(value("Success"), "100.00%");
        assert_eq!(value("Requests/sec"), "7205.7");
        assert_eq!(value("Elapsed"), "3.00s");
        assert_eq!(value("Fastest"), "218µs");
        assert_eq!(value("p50"), "635µs");
        assert_eq!(value("p99"), "31.0ms");
        assert_eq!(value("Data"), "21.1 MiB (1.0 KiB per request)");
        assert_eq!(report["sections"][1]["rows"][0], json!(["200", "21,636"]));
        assert_eq!(
            report["sections"][2]["rows"][0],
            json!(["aborted due to deadline", "9"])
        );
    }

    #[test]
    fn a_run_that_completed_nothing_still_reports_its_errors() {
        // Every statistic is null here. That run is exactly the one whose error
        // counts explain what went wrong, so it must not fail the parse.
        let json = r#"{"summary":{"successRate":null,"total":null,"slowest":null,
            "fastest":null,"average":null,"requestsPerSec":null,"totalData":null,
            "sizePerRequest":null},"latencyPercentiles":{"p50":null},
            "statusCodeDistribution":{},"errorDistribution":{"connection refused":5}}"#;
        let request = request();
        let forward = request.forward.clone().unwrap();
        let options = Options::from(&request.inputs).unwrap();
        let report = render(
            parse(json.as_bytes()).unwrap(),
            &request,
            &forward,
            &options,
            "http://127.0.0.1:32123/",
        );
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Requests", "5"])));
        assert!(rows.contains(&json!(["Success", "—"])));
        assert!(rows.contains(&json!(["p50", "—"])));
        // No status codes at all, so that section is left out entirely.
        assert_eq!(report["sections"].as_array().unwrap().len(), 2);
        assert_eq!(report["sections"][1]["title"], "Errors");
    }

    #[test]
    fn without_a_forward_there_is_nothing_to_benchmark() {
        let mut request = request();
        request.forward = None;
        assert!(
            run(&request)
                .unwrap_err()
                .contains("did not open a port-forward")
        );
    }

    #[test]
    fn the_url_comes_from_the_forward_sofka_opened() {
        let forward = Forward {
            host: "127.0.0.1".into(),
            local_port: 32123,
            remote_port: 80,
        };
        assert_eq!(url(&forward, "/"), "http://127.0.0.1:32123/");
        assert_eq!(url(&forward, "/healthz"), "http://127.0.0.1:32123/healthz");
        // A path without its leading slash is still a path.
        assert_eq!(url(&forward, "healthz"), "http://127.0.0.1:32123/healthz");
        let empty = Forward {
            host: String::new(),
            ..forward
        };
        assert_eq!(url(&empty, "/"), "http://127.0.0.1:32123/");
    }

    #[test]
    fn inputs_are_read_with_defaults_and_rejected_when_nonsense() {
        let options = Options::from(&BTreeMap::new()).unwrap();
        assert_eq!(
            (options.duration, options.connections, options.rate),
            (10, 20, 100)
        );
        assert_eq!(options.path, "/");

        let parsed = |pairs: &[(&str, &str)]| {
            Options::from(
                &pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            )
        };
        assert_eq!(parsed(&[("duration", "2m")]).unwrap().duration, 120);
        assert_eq!(parsed(&[("duration", "45")]).unwrap().duration, 45);
        assert!(parsed(&[("duration", "10w")]).is_err());
        assert!(parsed(&[("duration", "0s")]).is_err());
        assert!(parsed(&[("connections", "0")]).is_err());
        assert!(parsed(&[("connections", "1001")]).is_err());
        assert!(parsed(&[("connections", "many")]).is_err());
        assert_eq!(parsed(&[("rate", "250")]).unwrap().rate, 250);
        assert!(parsed(&[("rate", "0")]).is_err());
        assert!(parsed(&[("rate", "10001")]).is_err());
    }

    #[test]
    fn oha_is_invoked_for_the_requested_duration_and_concurrency() {
        let mut command = Command::new("oha");
        configure(
            &mut command,
            "http://127.0.0.1:32123/healthz",
            &Options {
                duration: 30,
                connections: 50,
                rate: 100,
                path: "/healthz".into(),
            },
        );
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--no-tui",
                "--output-format",
                "json",
                "-z",
                "30s",
                "-c",
                "50",
                "-q",
                "100",
                "http://127.0.0.1:32123/healthz",
            ]
        );
    }

    #[test]
    fn a_failed_run_reports_what_oha_said_rather_than_how_it_died() {
        assert_eq!(
            run_error(
                Some("invalid JSON from oha: EOF".into()),
                "signal: 13 (SIGPIPE)",
                b"error: connection refused\n",
            ),
            "oha failed: error: connection refused"
        );
        assert_eq!(
            run_error(
                Some("invalid JSON from oha: EOF".into()),
                "exit status: 1",
                b""
            ),
            "invalid JSON from oha: EOF"
        );
        assert_eq!(
            run_error(None, "exit status: 2", b""),
            "oha exited with exit status: 2: no error output"
        );
    }

    #[test]
    fn remote_distributions_are_ordered_and_capped() {
        let many: BTreeMap<String, u64> = (0..MAX_DISTRIBUTION_ROWS + 10)
            .map(|i| (format!("code-{i:03}"), i as u64))
            .collect();
        let (rows, dropped) = distribution(&many);
        assert_eq!(rows.len(), MAX_DISTRIBUTION_ROWS);
        assert_eq!(dropped, 10);
        // Largest first.
        assert_eq!(rows[0][1], thousands(MAX_DISTRIBUTION_ROWS as u64 + 9));
    }

    #[test]
    fn numbers_read_the_way_a_person_scans_them() {
        assert_eq!(thousands(21_645), "21,645");
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(latency(Some(0.000218)), "218µs");
        assert_eq!(latency(Some(0.031)), "31.0ms");
        assert_eq!(latency(Some(1.444)), "1.44s");
        assert_eq!(latency(None), "—");
        assert_eq!(latency(Some(f64::NAN)), "—");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(22_155_264), "21.1 MiB");
    }

    #[test]
    fn discovery_never_selects_this_adapter() {
        let dir = std::env::temp_dir().join(format!("sofka-oha-{}", std::process::id()));
        let package = dir.join("package");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&package).unwrap();
        let own = package.join("oha");
        std::fs::write(&own, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = std::env::join_paths([&package]).unwrap();
        assert_eq!(detect_in_path(&path, Some(&own)), None);
        assert_eq!(detect_in_path(&path, None), Some(own));
        let _ = std::fs::remove_dir_all(dir);
    }
}
