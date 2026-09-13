//! Resiliency test. Deletes pods belonging to the selected workload and waits
//! for the workload to become ready again, reporting how long that took.
//!
//! Deleting a pod is something sofka can already do. What this adds is the
//! measurement afterwards: a workload that never comes back, or takes minutes
//! to, is the finding. Everything destructive is gated behind `dry_run`, which
//! defaults to on.

use std::collections::BTreeMap;
use std::io::{Read, Write as _};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

const REQUEST_MAX_BYTES: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const PODS_JSONPATH: &str = r#"jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.uid}{"\t"}{.metadata.creationTimestamp}{"\t"}{.metadata.deletionTimestamp}{"\t"}{.status.phase}{"\t"}{range .metadata.ownerReferences[?(@.controller==true)]}{.kind}{":"}{.uid}{end}{"\t"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}"#;
const WORKLOAD_JSONPATH: &str = r#"jsonpath={.metadata.uid}{"\t"}{.spec.replicas}{"\t"}{.status.replicas}{"\t"}{.status.readyReplicas}{"\t"}{.status.desiredNumberScheduled}{"\t"}{.status.numberReady}"#;
const REPLICA_SETS_JSONPATH: &str = r#"jsonpath={range .items[*]}{.metadata.uid}{"\t"}{range .metadata.ownerReferences[?(@.controller==true)]}{.kind}{":"}{.uid}{end}{"\n"}{end}"#;

#[derive(Deserialize)]
struct Request {
    schema_version: u32,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
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
    // A captured pod list stands in for the cluster, so what this would pick
    // can be reviewed — and the packaged fixture test runs — without one.
    let saved = request.inputs.get("pods").map_or("", String::as_str);
    let report = if saved.is_empty() {
        run(&request, &Kubectl)?
    } else {
        run(&request, &Saved::open(saved, &request)?)?
    };
    let output = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|e| e.to_string())
}

/// Everything that touches the cluster, behind one trait so the decision logic
/// can be tested without one.
trait Cluster {
    fn pods(&self, scope: &Scope, selector: &str) -> Result<Vec<Pod>, String>;
    fn replica_sets(
        &self,
        scope: &Scope,
        selector: &str,
        deployment_uid: &str,
    ) -> Result<Vec<Owner>, String>;
    fn delete(&self, scope: &Scope, pods: &[String]) -> Result<(), String>;
    fn workload(&self, scope: &Scope) -> Result<Workload, String>;
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

struct Kubectl;

impl Kubectl {
    fn run(scope: &Scope, args: &[&str]) -> Result<String, String> {
        let mut command = Command::new("kubectl");
        if !scope.context.is_empty() {
            command.arg("--context").arg(&scope.context);
        }
        if !scope.namespace.is_empty() {
            command.arg("--namespace").arg(&scope.namespace);
        }
        let output = command
            .args(args)
            .output()
            .map_err(|e| format!("failed to run kubectl: {e}"))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let detail = detail.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            return Err(format!("kubectl {}: {detail}", args.join(" ")));
        }
        String::from_utf8(output.stdout)
            .map_err(|e| format!("kubectl returned non-UTF-8 output: {e}"))
    }
}

impl Cluster for Kubectl {
    fn pods(&self, scope: &Scope, selector: &str) -> Result<Vec<Pod>, String> {
        let out = Self::run(scope, &["get", "pods", "-l", selector, "-o", PODS_JSONPATH])?;
        parse_pod_lines(&out)
    }

    fn replica_sets(
        &self,
        scope: &Scope,
        selector: &str,
        deployment_uid: &str,
    ) -> Result<Vec<Owner>, String> {
        let out = Self::run(
            scope,
            &[
                "get",
                "replicasets",
                "-l",
                selector,
                "-o",
                REPLICA_SETS_JSONPATH,
            ],
        )?;
        parse_replica_set_lines(&out, deployment_uid)
    }

    fn delete(&self, scope: &Scope, pods: &[String]) -> Result<(), String> {
        let mut args = vec!["delete", "pod", "--wait=false"];
        args.extend(pods.iter().map(String::as_str));
        Self::run(scope, &args).map(|_| ())
    }

    fn workload(&self, scope: &Scope) -> Result<Workload, String> {
        let out = Self::run(
            scope,
            &["get", &scope.resource, &scope.name, "-o", WORKLOAD_JSONPATH],
        )?;
        parse_workload_line(&out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Owner {
    kind: String,
    uid: String,
}

#[derive(Clone, Debug)]
struct Pod {
    name: String,
    uid: Option<String>,
    created: String,
    terminating: bool,
    phase: String,
    owner: Option<Owner>,
    ready: bool,
}

#[derive(Clone, Debug)]
struct Workload {
    uid: String,
    desired: i64,
    ready: i64,
}

fn owner(value: &str) -> Option<Owner> {
    let (kind, uid) = value.split_once(':')?;
    (!kind.is_empty() && !uid.is_empty()).then(|| Owner {
        kind: kind.to_string(),
        uid: uid.to_string(),
    })
}

fn fields<'a>(line: &'a str, expected: usize, label: &str) -> Result<Vec<&'a str>, String> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != expected {
        return Err(format!("invalid kubectl {label} output"));
    }
    Ok(fields)
}

fn parse_pod_lines(output: &str) -> Result<Vec<Pod>, String> {
    output
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let value = fields(line, 7, "pod list")?;
            if value[0].is_empty() {
                return Err("kubectl returned a pod without a name".into());
            }
            Ok(Pod {
                name: value[0].to_string(),
                uid: (!value[1].is_empty()).then(|| value[1].to_string()),
                created: value[2].to_string(),
                terminating: !value[3].is_empty(),
                phase: value[4].to_string(),
                owner: owner(value[5]),
                ready: value[6] == "True",
            })
        })
        .collect()
}

fn parse_replica_set_lines(output: &str, deployment_uid: &str) -> Result<Vec<Owner>, String> {
    let mut owners = Vec::new();
    for line in output.lines().filter(|line| !line.is_empty()) {
        let value = fields(line, 2, "ReplicaSet list")?;
        if owner(value[1])
            .is_some_and(|owner| owner.kind == "Deployment" && owner.uid == deployment_uid)
            && !value[0].is_empty()
        {
            owners.push(Owner {
                kind: "ReplicaSet".into(),
                uid: value[0].to_string(),
            });
        }
    }
    Ok(owners)
}

fn number(value: &str) -> i64 {
    value.parse().unwrap_or(0)
}

fn parse_workload_line(output: &str) -> Result<Workload, String> {
    let value = fields(output.trim_end_matches('\n'), 6, "workload")?;
    if value[0].is_empty() {
        return Err("selected workload has no UID".into());
    }
    let desired_scheduled = number(value[4]);
    let desired = if desired_scheduled > 0 {
        desired_scheduled
    } else {
        let spec = number(value[1]);
        if spec > 0 { spec } else { number(value[2]) }
    };
    let number_ready = number(value[5]);
    Ok(Workload {
        uid: value[0].to_string(),
        desired,
        ready: if number_ready > 0 {
            number_ready
        } else {
            number(value[3])
        },
    })
}

fn pods_from_value(value: &Value) -> Vec<Pod> {
    value
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|pod| {
            let name = pod.pointer("/metadata/name")?.as_str()?.to_string();
            let owner = pod
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
                .and_then(|owners| {
                    owners.iter().find(|owner| {
                        owner.get("controller").and_then(Value::as_bool) == Some(true)
                    })
                })
                .and_then(|owner| {
                    Some(Owner {
                        kind: owner.get("kind")?.as_str()?.to_string(),
                        uid: owner.get("uid")?.as_str()?.to_string(),
                    })
                });
            Some(Pod {
                name,
                uid: pod
                    .pointer("/metadata/uid")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                created: pod
                    .pointer("/metadata/creationTimestamp")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                terminating: pod.pointer("/metadata/deletionTimestamp").is_some(),
                phase: pod
                    .pointer("/status/phase")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                owner,
                ready: pod
                    .pointer("/status/conditions")
                    .and_then(Value::as_array)
                    .is_some_and(|conditions| {
                        conditions.iter().any(|condition| {
                            condition.get("type").and_then(Value::as_str) == Some("Ready")
                                && condition.get("status").and_then(Value::as_str) == Some("True")
                        })
                    }),
            })
        })
        .collect()
}

fn workload_from_value(value: &Value) -> Result<Workload, String> {
    let uid = value
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .ok_or_else(|| "selected workload has no UID".to_string())?
        .to_string();
    let status = value.get("status");
    let number = |value: Option<&Value>| value.and_then(Value::as_i64).unwrap_or(0);
    let desired = status
        .and_then(|status| status.get("desiredNumberScheduled"))
        .map(|value| number(Some(value)))
        .unwrap_or_else(|| {
            number(
                value
                    .pointer("/spec/replicas")
                    .or_else(|| status.and_then(|status| status.get("replicas"))),
            )
        });
    let ready = status
        .and_then(|status| {
            status
                .get("numberReady")
                .or_else(|| status.get("readyReplicas"))
        })
        .map(|value| number(Some(value)))
        .unwrap_or(0);
    Ok(Workload {
        uid,
        desired,
        ready,
    })
}

/// Reads a captured pod list instead of a cluster. It can never delete, so a
/// saved run is a dry run whatever the inputs say.
struct Saved {
    pods: Value,
    workload: Value,
}

impl Saved {
    fn open(path: &str, request: &Request) -> Result<Self, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read saved pod list {path}: {e}"))?;
        Ok(Self {
            pods: serde_json::from_slice(&bytes)
                .map_err(|e| format!("invalid saved pod list {path}: {e}"))?,
            workload: request.object.clone().unwrap_or(Value::Null),
        })
    }
}

impl Cluster for Saved {
    fn pods(&self, _: &Scope, _: &str) -> Result<Vec<Pod>, String> {
        Ok(pods_from_value(&self.pods))
    }

    fn replica_sets(&self, _: &Scope, _: &str, _: &str) -> Result<Vec<Owner>, String> {
        let mut owners = Vec::new();
        for pod in pods_from_value(&self.pods) {
            if let Some(owner) = pod.owner
                && owner.kind == "ReplicaSet"
                && !owners.contains(&owner)
            {
                owners.push(owner);
            }
        }
        Ok(owners)
    }

    fn delete(&self, _: &Scope, _: &[String]) -> Result<(), String> {
        Err("a saved pod-list replay cannot delete from a cluster".into())
    }

    fn workload(&self, _: &Scope) -> Result<Workload, String> {
        workload_from_value(&self.workload)
    }
}

struct Scope {
    context: String,
    namespace: String,
    resource: String,
    name: String,
}

struct Options {
    dry_run: bool,
    count: usize,
    wait: Duration,
}

impl Options {
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
                _ => return None,
            };
            n.checked_mul(per).filter(|n| *n > 0)
        };
        Ok(Self {
            // Anything but an explicit "false" leaves the run harmless.
            dry_run: inputs.get("dry_run").is_none_or(|v| v != "false")
                || inputs.get("pods").is_some_and(|p| !p.is_empty()),
            count: inputs
                .get("count")
                .map_or(Ok(1), |v| v.parse::<usize>())
                .map_err(|_| "count must be a whole number".to_string())?
                .max(1),
            wait: Duration::from_secs(
                inputs
                    .get("wait")
                    .map_or(Some(120), |v| seconds(v))
                    .ok_or_else(|| "wait must be a positive time like \"120s\"".to_string())?,
            ),
        })
    }
}

/// A workload's pod selector, as `k=v,k=v`. Only `matchLabels` is supported:
/// `matchExpressions` cannot be expressed as a `-l` argument, and guessing
/// would delete the wrong pods.
fn selector(object: &Value) -> Result<String, String> {
    let selector = object
        .get("spec")
        .and_then(|s| s.get("selector"))
        .ok_or_else(|| "workload has no spec.selector".to_string())?;
    // A selector carrying both forms narrows on the expressions too. Reading
    // only matchLabels would widen it, and the widened set is what gets
    // deleted, so refuse rather than approximate.
    if selector
        .get("matchExpressions")
        .and_then(Value::as_array)
        .is_some_and(|e| !e.is_empty())
    {
        return Err(
            "workload selector uses matchExpressions, which cannot be narrowed here; \
             refusing rather than deleting a wider set of pods"
                .into(),
        );
    }
    let labels = selector
        .get("matchLabels")
        .and_then(Value::as_object)
        .ok_or_else(|| "workload has no spec.selector.matchLabels".to_string())?;
    if labels.is_empty() {
        return Err("workload selector is empty; refusing to match every pod".into());
    }
    Ok(labels
        .iter()
        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(","))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Victim {
    name: String,
    uid: Option<String>,
}

/// Pods eligible to be killed, oldest first. A matching label is not enough:
/// every pod must be controlled by the selected workload (through one of its
/// ReplicaSets for a Deployment). Debug pods that merely share labels are left
/// alone.
fn victims(pods: &[Pod], owners: &[Owner], count: usize) -> Vec<Victim> {
    let mut running: Vec<&Pod> = pods
        .iter()
        .filter(|pod| {
            pod.phase == "Running"
                && !pod.terminating
                && pod
                    .owner
                    .as_ref()
                    .is_some_and(|owner| owners.contains(owner))
        })
        .collect();
    // RFC 3339 timestamps sort lexicographically; name breaks ties so the
    // order is total and a dry run matches the run that follows it.
    running.sort_by(|a, b| a.created.cmp(&b.created).then(a.name.cmp(&b.name)));
    running
        .into_iter()
        .take(count)
        .map(|pod| Victim {
            name: pod.name.clone(),
            uid: pod.uid.clone(),
        })
        .collect()
}

/// The controller status can remain fully ready briefly after an asynchronous
/// delete. Recovery therefore also requires the selected pod UIDs to be gone
/// or terminating and the desired number of replacement pods to be Ready.
fn replacements_ready(pods: &[Pod], owners: &[Owner], killed: &[Victim], desired: i64) -> bool {
    let killed_uids: Vec<&str> = killed.iter().filter_map(|pod| pod.uid.as_deref()).collect();
    let old_pod_still_active = pods.iter().any(|pod| {
        pod.uid
            .as_deref()
            .is_some_and(|uid| killed_uids.contains(&uid))
            && !pod.terminating
    });
    let ready = pods
        .iter()
        .filter(|pod| {
            pod.phase == "Running"
                && !pod.terminating
                && pod.ready
                && pod
                    .owner
                    .as_ref()
                    .is_some_and(|owner| owners.contains(owner))
        })
        .count();
    !old_pod_still_active && usize::try_from(desired).is_ok_and(|desired| ready >= desired)
}

/// `kubectl delete` names a pod; it cannot say "only if this is still the same
/// pod". A StatefulSet brings its pods back under their original names, so
/// between choosing a victim and deleting it a name can belong to a different
/// pod. Read the list again and refuse the whole run if any chosen identity
/// moved: nothing has been deleted yet, so refusing costs nothing.
fn confirm_identities(
    cluster: &dyn Cluster,
    scope: &Scope,
    selector: &str,
    victims: &[Victim],
) -> Result<(), String> {
    let current = cluster.pods(scope, selector)?;
    for victim in victims {
        let found = current
            .iter()
            .find(|pod| pod.name == victim.name)
            .and_then(|pod| pod.uid.as_deref());
        match found {
            Some(uid) if Some(uid) == victim.uid.as_deref() => {}
            Some(_) => {
                return Err(format!(
                    "pod {} is no longer the pod that was selected; \
                     refusing to delete its replacement",
                    victim.name
                ));
            }
            None => {
                return Err(format!(
                    "pod {} is already gone; refusing to delete whatever took its name",
                    victim.name
                ));
            }
        }
    }
    Ok(())
}

fn workload_owners(
    kind: &str,
    workload: &Workload,
    cluster: &dyn Cluster,
    scope: &Scope,
    selector: &str,
) -> Result<Vec<Owner>, String> {
    match kind {
        "Deployment" => cluster.replica_sets(scope, selector, &workload.uid),
        "StatefulSet" | "DaemonSet" => Ok(vec![Owner {
            kind: kind.to_string(),
            uid: workload.uid.clone(),
        }]),
        _ => Err(format!(
            "{kind} is not supported; select a Deployment, StatefulSet, or DaemonSet"
        )),
    }
}

struct Outcome {
    killed: Vec<String>,
    delete_succeeded: bool,
    measurement_error: Option<String>,
    recovered: Option<Duration>,
    desired: i64,
    ready: i64,
    polls: usize,
}

fn run(request: &Request, cluster: &dyn Cluster) -> Result<Value, String> {
    let mut remaining = 64 * 1024;
    run_with_activity(request, cluster, &mut |message| {
        if remaining == 0 {
            return;
        }
        let line = format!("{message}\n");
        if line.len() > remaining {
            let _ = std::io::stderr()
                .write_all(b"[chaos-kill activity truncated; recovery measurement continues]\n");
            remaining = 0;
        } else {
            remaining -= line.len();
            // A diagnostic write failure must not abandon recovery measurement
            // after a pod deletion has already been requested.
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
    })
}

fn run_with_activity(
    request: &Request,
    cluster: &dyn Cluster,
    activity: &mut dyn FnMut(&str),
) -> Result<Value, String> {
    if request.schema_version != 1 {
        return Err("unsupported request schema_version".into());
    }
    let object = request
        .object
        .as_ref()
        .ok_or_else(|| "select a workload to test".to_string())?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let name = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or_else(|| "selected object has no name".to_string())?
        .to_string();
    let scope = Scope {
        context: request.context.clone().unwrap_or_default(),
        namespace: object
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| request.namespace.clone())
            .unwrap_or_default(),
        resource: kind.to_ascii_lowercase(),
        name: name.clone(),
    };
    if scope.namespace.is_empty() {
        return Err("a namespace is required; this never runs cluster-wide".into());
    }
    let options = Options::from(&request.inputs)?;
    let selector = selector(object)?;
    activity("Reading workload status and checking pod ownership");
    let workload = cluster.workload(&scope)?;
    if workload.desired <= 0 {
        return Err(format!(
            "{kind}/{name} has no desired replicas; nothing can recover"
        ));
    }
    if i64::try_from(options.count).is_err()
        || i64::try_from(options.count).unwrap_or(i64::MAX) >= workload.desired
    {
        return Err(format!(
            "count must be less than the workload's {} desired replicas",
            workload.desired
        ));
    }
    let owners = workload_owners(&kind, &workload, cluster, &scope, &selector)?;

    let pods = cluster.pods(&scope, &selector)?;
    let victims = victims(&pods, &owners, options.count);
    if victims.is_empty() {
        return Err(format!(
            "{kind}/{name} has no running pods owned by this workload to kill; nothing to test"
        ));
    }
    let killed: Vec<String> = victims.iter().map(|pod| pod.name.clone()).collect();

    if options.dry_run {
        activity(&format!(
            "Dry run: selected {} pod(s); nothing will be deleted",
            killed.len()
        ));
        return Ok(report(
            &kind,
            &scope,
            &selector,
            &options,
            &Outcome {
                killed,
                delete_succeeded: false,
                measurement_error: None,
                recovered: None,
                desired: workload.desired,
                ready: workload.ready,
                polls: 0,
            },
        ));
    }

    if let Some(pod) = victims.iter().find(|pod| pod.uid.is_none()) {
        return Err(format!(
            "pod {} has no UID; refusing to delete a pod whose replacement cannot be verified",
            pod.name
        ));
    }
    activity("Verifying selected pod identities before deletion");
    confirm_identities(cluster, &scope, &selector, &victims)?;
    let mut outcome = Outcome {
        killed,
        delete_succeeded: false,
        measurement_error: None,
        recovered: None,
        desired: workload.desired,
        ready: workload.ready,
        polls: 0,
    };
    activity(&format!(
        "Requesting deletion of {} pod(s)",
        outcome.killed.len()
    ));
    if let Err(error) = cluster.delete(&scope, &outcome.killed) {
        activity("Deletion failed; recovery measurement was not started");
        outcome.measurement_error = Some(error);
        return Ok(report(&kind, &scope, &selector, &options, &outcome));
    }
    outcome.delete_succeeded = true;
    activity(&format!(
        "Deletion request accepted; waiting up to {}s for replacement readiness",
        options.wait.as_secs()
    ));
    let started = Instant::now();
    while started.elapsed() < options.wait {
        cluster.sleep(POLL_INTERVAL);
        outcome.polls += 1;
        let state = match cluster.workload(&scope) {
            Ok(state) => state,
            Err(error) => {
                outcome.measurement_error = Some(error);
                break;
            }
        };
        (outcome.desired, outcome.ready) = (state.desired, state.ready);
        activity(&format!(
            "Recovery: {} / {} controller replicas ready; {:.1}s elapsed / {}s deadline",
            outcome.ready,
            outcome.desired,
            started.elapsed().as_secs_f64(),
            options.wait.as_secs()
        ));
        if outcome.desired > 0 && outcome.ready >= outcome.desired {
            let pods = match cluster.pods(&scope, &selector) {
                Ok(pods) => pods,
                Err(error) => {
                    outcome.measurement_error = Some(error);
                    break;
                }
            };
            if replacements_ready(&pods, &owners, &victims, outcome.desired) {
                outcome.recovered = Some(started.elapsed());
                activity("Replacement pods verified ready; workload recovered");
                break;
            }
            activity("Controller reports ready; still waiting for verified replacement pods");
        }
    }
    if outcome.measurement_error.is_some() {
        activity("Recovery measurement failed; see report for details");
    } else if outcome.recovered.is_none() {
        activity("Recovery deadline reached without verified recovery");
    }
    Ok(report(&kind, &scope, &selector, &options, &outcome))
}

fn report(
    kind: &str,
    scope: &Scope,
    selector: &str,
    options: &Options,
    outcome: &Outcome,
) -> Value {
    let verdict = if options.dry_run {
        "dry run — nothing was deleted".to_string()
    } else if let Some(error) = &outcome.measurement_error {
        format!("measurement failed: {error}")
    } else if let Some(elapsed) = outcome.recovered {
        format!("recovered in {:.1}s", elapsed.as_secs_f64())
    } else {
        format!(
            "DID NOT RECOVER within {}s — {} of {} replicas ready",
            options.wait.as_secs(),
            outcome.ready,
            outcome.desired
        )
    };
    let mut rows = vec![
        json!(["Verdict", verdict]),
        json!(["Workload", format!("{kind}/{}", scope.name)]),
        json!(["Namespace", scope.namespace.clone()]),
        json!(["Selector", selector]),
        json!([
            if options.dry_run {
                "Would kill"
            } else if outcome.delete_succeeded {
                "Killed"
            } else {
                "Targeted"
            },
            outcome.killed.len().to_string()
        ]),
        json!(["Desired replicas", outcome.desired.to_string()]),
        json!(["Ready replicas", outcome.ready.to_string()]),
    ];
    if !options.dry_run {
        rows.push(json!([
            "Waited up to",
            format!("{}s", options.wait.as_secs())
        ]));
        rows.push(json!(["Checks", outcome.polls.to_string()]));
    }

    let mut sections = vec![json!({
        "title": "Summary",
        "columns": ["Field", "Value"],
        "rows": rows,
    })];
    let pod_section = if options.dry_run {
        "Pods that would be deleted"
    } else if outcome.delete_succeeded {
        "Pods deleted"
    } else {
        "Pods targeted for deletion"
    };
    sections.push(json!({
        "title": pod_section,
        "lines": outcome.killed.iter().map(|p| format!("  {p}")).collect::<Vec<_>>(),
    }));
    if let Some(error) = &outcome.measurement_error {
        sections.push(json!({
            "title": "Measurement error",
            "lines": [error],
        }));
    }
    if options.dry_run {
        sections.push(json!({
            "title": "Notice",
            "lines": ["Re-run with dry_run=false to delete these pods and measure recovery."],
        }));
    }
    json!({
        "schema_version": 1,
        "title": "Chaos kill",
        "sections": sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const PODS: &str = include_str!("../fixtures/pods.json");
    const WORKLOAD_UID: &str = "deployment-web";
    const REPLICA_SET_UID: &str = "rs-web";

    fn request() -> Request {
        serde_json::from_str(include_str!("../fixtures/request.json")).unwrap()
    }

    /// Records what the adapter asked the cluster to do, and replays a fixed
    /// sequence of readiness states. The first state answers the reading taken
    /// before the delete; the rest answer the recovery polls.
    struct Fake {
        pods: Value,
        after_delete: Value,
        states: RefCell<Vec<(i64, i64)>>,
        deleted: RefCell<Vec<String>>,
        delete_error: Option<String>,
        workload_errors_after_delete: bool,
        /// Served by the second read taken before any delete: the pod list as
        /// the identity re-check finds it.
        recheck: Option<Value>,
        pod_reads: RefCell<usize>,
    }

    impl Fake {
        fn new(states: Vec<(i64, i64)>) -> Self {
            let pods: Value = serde_json::from_str(PODS).unwrap();
            let mut after_delete = pods.clone();
            for pod in after_delete["items"].as_array_mut().unwrap() {
                if pod.pointer("/status/phase").and_then(Value::as_str) == Some("Running")
                    && pod.pointer("/metadata/deletionTimestamp").is_none()
                {
                    let uid = pod["metadata"]["uid"].as_str().unwrap().to_string();
                    pod["metadata"]["uid"] = json!(format!("replacement-{uid}"));
                }
            }
            Self {
                pods,
                after_delete,
                states: RefCell::new(states),
                deleted: RefCell::new(Vec::new()),
                delete_error: None,
                workload_errors_after_delete: false,
                recheck: None,
                pod_reads: RefCell::new(0),
            }
        }

        fn with_after_delete(states: Vec<(i64, i64)>, after_delete: Value) -> Self {
            Self {
                after_delete,
                ..Self::new(states)
            }
        }
    }

    impl Cluster for Fake {
        fn pods(&self, _: &Scope, _: &str) -> Result<Vec<Pod>, String> {
            if !self.deleted.borrow().is_empty() {
                return Ok(pods_from_value(&self.after_delete));
            }
            let reads = {
                let mut reads = self.pod_reads.borrow_mut();
                *reads += 1;
                *reads
            };
            match &self.recheck {
                // The first read chooses victims; the second re-checks them.
                Some(recheck) if reads > 1 => Ok(pods_from_value(recheck)),
                _ => Ok(pods_from_value(&self.pods)),
            }
        }

        fn replica_sets(
            &self,
            _: &Scope,
            _: &str,
            deployment_uid: &str,
        ) -> Result<Vec<Owner>, String> {
            // Only the selected Deployment's own ReplicaSet owns killable pods.
            Ok(if deployment_uid == WORKLOAD_UID {
                vec![Owner {
                    kind: "ReplicaSet".into(),
                    uid: REPLICA_SET_UID.into(),
                }]
            } else {
                Vec::new()
            })
        }

        fn delete(&self, _: &Scope, pods: &[String]) -> Result<(), String> {
            if let Some(error) = &self.delete_error {
                return Err(error.clone());
            }
            self.deleted.borrow_mut().extend_from_slice(pods);
            Ok(())
        }

        fn workload(&self, _: &Scope) -> Result<Workload, String> {
            if self.workload_errors_after_delete && !self.deleted.borrow().is_empty() {
                return Err("kubectl get deployments: connection refused".into());
            }
            let mut states = self.states.borrow_mut();
            let (desired, ready) = if states.len() > 1 {
                states.remove(0)
            } else {
                *states.first().unwrap_or(&(3, 3))
            };
            Ok(Workload {
                uid: WORKLOAD_UID.to_string(),
                desired,
                ready,
            })
        }
    }

    fn rows(report: &Value) -> Vec<(String, String)> {
        report["sections"][0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r[0].as_str().unwrap().into(), r[1].as_str().unwrap().into()))
            .collect()
    }

    fn value(report: &Value, field: &str) -> String {
        rows(report)
            .into_iter()
            .find(|(k, _)| k == field)
            .unwrap_or_else(|| panic!("no {field} row"))
            .1
    }

    #[test]
    fn a_dry_run_deletes_nothing() {
        let fake = Fake::new(vec![(3, 3)]);
        let mut messages = Vec::new();
        let report = run_with_activity(&request(), &fake, &mut |line| {
            messages.push(line.to_string())
        })
        .unwrap();
        assert!(
            messages
                .iter()
                .any(|line| line.contains("Dry run: selected 2 pod(s)"))
        );
        assert!(
            !messages
                .iter()
                .any(|line| line.contains("Requesting deletion"))
        );
        assert!(fake.deleted.borrow().is_empty(), "a dry run deleted pods");
        assert_eq!(value(&report, "Verdict"), "dry run — nothing was deleted");
        assert_eq!(value(&report, "Would kill"), "2");
        assert_eq!(report["sections"][2]["title"], "Notice");
    }

    #[test]
    fn anything_but_an_explicit_false_stays_a_dry_run() {
        for setting in ["true", "", "no", "FALSE", "0"] {
            let mut request = request();
            request.inputs.insert("dry_run".into(), setting.to_string());
            let fake = Fake::new(vec![(3, 3)]);
            run(&request, &fake).unwrap();
            assert!(
                fake.deleted.borrow().is_empty(),
                "dry_run={setting:?} deleted pods"
            );
        }
    }

    #[test]
    fn victims_are_the_oldest_running_pods_the_workload_owns() {
        let pods = pods_from_value(&serde_json::from_str::<Value>(PODS).unwrap());
        let owners = [Owner {
            kind: "ReplicaSet".into(),
            uid: REPLICA_SET_UID.into(),
        }];
        // Terminating and Pending pods are never chosen: deleting a pod that is
        // already going away proves nothing. `debug-shell` is older than every
        // other pod and carries the same labels, but nothing owns it, so
        // nothing would bring it back.
        assert_eq!(
            victims(&pods, &owners, 3)
                .into_iter()
                .map(|pod| pod.name)
                .collect::<Vec<_>>(),
            ["web-oldest", "web-middle", "web-newest"]
        );
        assert_eq!(victims(&pods, &owners, 1)[0].name, "web-oldest");
        assert_eq!(victims(&pods, &owners, 99).len(), 3);
        // No owner matches: a labelled pod on its own is never eligible.
        assert!(victims(&pods, &[], 1).is_empty());
        assert!(victims(&[], &owners, 1).is_empty());
    }

    #[test]
    fn a_real_run_deletes_then_measures_recovery() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.remove("pods");
        // Whole before the delete, then degraded, still degraded, whole again.
        let fake = Fake::new(vec![(3, 3), (3, 1), (3, 2), (3, 3)]);
        let mut messages = Vec::new();
        let report =
            run_with_activity(&request, &fake, &mut |line| messages.push(line.to_string()))
                .unwrap();
        for ready in [1, 2, 3] {
            assert!(messages.iter().any(|line| {
                line.contains(&format!("Recovery: {ready} / 3 controller replicas ready"))
            }));
        }
        assert_eq!(
            messages.last().unwrap(),
            "Replacement pods verified ready; workload recovered"
        );
        assert_eq!(*fake.deleted.borrow(), ["web-oldest", "web-middle"]);
        assert!(value(&report, "Verdict").starts_with("recovered in"));
        assert_eq!(value(&report, "Ready replicas"), "3");
        assert_eq!(value(&report, "Checks"), "3");
        assert_eq!(report["sections"][1]["title"], "Pods deleted");
    }

    #[test]
    fn a_workload_that_never_comes_back_is_the_finding() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.remove("pods");
        // The deadline is wall-clock, so this really waits — briefly.
        request.inputs.insert("wait".into(), "2s".into());
        let fake = Fake::new(vec![(3, 1)]);
        let started = Instant::now();
        let report = run(&request, &fake).unwrap();
        let verdict = value(&report, "Verdict");
        assert!(verdict.contains("DID NOT RECOVER"), "{verdict}");
        assert!(verdict.contains("1 of 3"), "{verdict}");
        // It gave up at the deadline instead of polling forever.
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(value(&report, "Checks").parse::<usize>().unwrap() <= 3);
    }

    #[test]
    fn stale_controller_readiness_does_not_claim_recovery() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.remove("pods");
        request.inputs.insert("wait".into(), "1s".into());
        // The async delete returned, but the pod list and controller readiness
        // are both still the old observation.
        let fake = Fake::with_after_delete(vec![(3, 3)], serde_json::from_str(PODS).unwrap());
        let mut messages = Vec::new();
        let report =
            run_with_activity(&request, &fake, &mut |line| messages.push(line.to_string()))
                .unwrap();
        assert!(
            messages
                .iter()
                .any(|line| line.contains("still waiting for verified replacement pods"))
        );
        assert!(
            !messages
                .iter()
                .any(|line| line.contains("workload recovered"))
        );
        assert_eq!(
            messages.last().unwrap(),
            "Recovery deadline reached without verified recovery"
        );

        let verdict = value(&report, "Verdict");
        assert!(verdict.contains("DID NOT RECOVER"), "{verdict}");
        assert_eq!(value(&report, "Checks"), "1");
    }

    #[test]
    fn a_selector_it_cannot_express_is_refused_rather_than_guessed() {
        let mut expressions = request();
        expressions.object.as_mut().unwrap()["spec"]["selector"] =
            json!({"matchExpressions": [{"key": "app"}]});
        assert!(
            run(&expressions, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("matchExpressions")
        );

        // Both forms together: reading only matchLabels would widen the
        // selector, and the wider set is what would be deleted.
        let mut both = request();
        both.object.as_mut().unwrap()["spec"]["selector"] = json!({
            "matchLabels": {"app": "web"},
            "matchExpressions": [{"key": "track", "operator": "In", "values": ["canary"]}],
        });
        let error = run(&both, &Fake::new(vec![(3, 3)])).unwrap_err();
        assert!(error.contains("matchExpressions"), "{error}");

        // An empty expressions list narrows nothing, so it is not a refusal.
        let mut empty_expressions = request();
        empty_expressions.object.as_mut().unwrap()["spec"]["selector"] =
            json!({"matchLabels": {"app": "web"}, "matchExpressions": []});
        assert!(run(&empty_expressions, &Fake::new(vec![(3, 3)])).is_ok());

        let mut empty = request();
        empty.object.as_mut().unwrap()["spec"]["selector"]["matchLabels"] = json!({});
        assert!(
            run(&empty, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("refusing to match every pod")
        );
    }

    #[test]
    fn it_never_runs_without_a_namespace_or_a_selection() {
        let mut unselected = request();
        unselected.object = None;
        assert!(
            run(&unselected, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("select a workload")
        );

        let mut unscoped = request();
        unscoped.namespace = None;
        unscoped.object.as_mut().unwrap()["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("namespace");
        assert!(
            run(&unscoped, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("never runs cluster-wide")
        );
    }

    #[test]
    fn a_workload_with_nothing_running_is_not_a_test() {
        let fake = Fake {
            pods: json!({"items": []}),
            ..Fake::new(vec![(3, 3)])
        };
        assert!(
            run(&request(), &fake)
                .unwrap_err()
                .contains("no running pods owned by this workload to kill")
        );
    }

    #[test]
    fn daemonsets_count_their_replicas_their_own_way() {
        let daemonset = workload_from_value(&json!({
            "metadata": {"uid": "ds-agent"},
            "status": {"desiredNumberScheduled": 4, "numberReady": 2},
        }))
        .unwrap();
        assert_eq!((daemonset.desired, daemonset.ready), (4, 2));
        let deployment = workload_from_value(&json!({
            "metadata": {"uid": "deployment-web"},
            "spec": {"replicas": 3},
            "status": {"readyReplicas": 3},
        }))
        .unwrap();
        assert_eq!((deployment.desired, deployment.ready), (3, 3));
        // A workload that reports nothing is not "ready": desired 0 never wins.
        let silent = workload_from_value(&json!({"metadata": {"uid": "quiet"}})).unwrap();
        assert_eq!((silent.desired, silent.ready), (0, 0));
        // Without a UID no pod can be tied to the workload, so it is refused.
        assert!(workload_from_value(&json!({})).is_err());
    }

    #[test]
    fn count_may_not_take_every_desired_replica() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.insert("count".into(), "3".into());
        // Deleting all three replicas of a three-replica Deployment is an
        // outage, not a resiliency test.
        let error = run(&request, &Fake::new(vec![(3, 3)])).unwrap_err();
        assert!(error.contains("must be less than"), "{error}");
        // One below the desired count is still a test.
        request.inputs.insert("count".into(), "2".into());
        assert!(run(&request, &Fake::new(vec![(3, 3)])).is_ok());
    }

    /// `kubectl delete` takes a name, and a StatefulSet gives a replacement the
    /// name its predecessor had. Deleting that replacement would disrupt a pod
    /// that was never selected or checked.
    #[test]
    fn a_pod_that_changed_identity_is_not_deleted() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.remove("pods");
        // Same name, same labels, same owner — a different pod.
        let mut recheck: Value = serde_json::from_str(PODS).unwrap();
        for pod in recheck["items"].as_array_mut().unwrap() {
            if pod["metadata"]["name"] == "web-oldest" {
                pod["metadata"]["uid"] = json!("uid-oldest-replacement");
            }
        }
        let fake = Fake {
            recheck: Some(recheck),
            ..Fake::new(vec![(3, 3)])
        };
        let error = run(&request, &fake).unwrap_err();
        assert!(
            error.contains("no longer the pod that was selected"),
            "{error}"
        );
        assert!(
            fake.deleted.borrow().is_empty(),
            "a pod was deleted after its identity moved"
        );

        // A name that vanished entirely is refused for the same reason.
        let mut vanished: Value = serde_json::from_str(PODS).unwrap();
        vanished["items"]
            .as_array_mut()
            .unwrap()
            .retain(|pod| pod["metadata"]["name"] != "web-oldest");
        let fake = Fake {
            recheck: Some(vanished),
            ..Fake::new(vec![(3, 3)])
        };
        let error = run(&request, &fake).unwrap_err();
        assert!(error.contains("already gone"), "{error}");
        assert!(fake.deleted.borrow().is_empty());

        // Unchanged identities go ahead as before.
        let fake = Fake {
            recheck: Some(serde_json::from_str(PODS).unwrap()),
            ..Fake::new(vec![(3, 3), (3, 1), (3, 2), (3, 3)])
        };
        assert!(run(&request, &fake).is_ok());
        assert_eq!(*fake.deleted.borrow(), ["web-oldest", "web-middle"]);
    }

    #[test]
    fn a_delete_that_fails_still_reports_what_it_targeted() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.remove("pods");
        let fake = Fake {
            delete_error: Some("kubectl delete pods: forbidden".into()),
            ..Fake::new(vec![(3, 3)])
        };
        let report = run(&request, &fake).unwrap();
        assert_eq!(
            value(&report, "Verdict"),
            "measurement failed: kubectl delete pods: forbidden"
        );
        assert_eq!(value(&report, "Targeted"), "2");
        assert_eq!(report["sections"][1]["title"], "Pods targeted for deletion");
        assert_eq!(report["sections"][2]["title"], "Measurement error");
    }

    #[test]
    fn a_measurement_that_fails_after_the_delete_keeps_the_killed_list() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.remove("pods");
        // The pods are gone; whatever happens next, the user has to be told
        // which ones they were.
        let fake = Fake {
            workload_errors_after_delete: true,
            ..Fake::new(vec![(3, 3)])
        };
        let report = run(&request, &fake).unwrap();
        assert_eq!(*fake.deleted.borrow(), ["web-oldest", "web-middle"]);
        assert!(
            value(&report, "Verdict").starts_with("measurement failed:"),
            "{}",
            value(&report, "Verdict")
        );
        assert_eq!(value(&report, "Killed"), "2");
        assert_eq!(report["sections"][1]["title"], "Pods deleted");
        assert_eq!(
            report["sections"][1]["lines"],
            json!(["  web-oldest", "  web-middle"])
        );
    }

    #[test]
    fn the_pod_columns_parse_back_into_pods() {
        let pods = parse_pod_lines(concat!(
            "web-oldest\tuid-oldest\t2026-09-11T09:00:00Z\t\tRunning\tReplicaSet:rs-web\tTrue\n",
            "web-going\tuid-going\t2026-09-11T08:00:00Z\t2026-09-11T12:30:00Z\tRunning\tReplicaSet:rs-web\t\n",
            "debug-shell\tuid-debug\t2026-09-11T06:00:00Z\t\tRunning\t\tTrue\n",
        ))
        .unwrap();
        assert_eq!(pods.len(), 3);
        assert_eq!(pods[0].uid.as_deref(), Some("uid-oldest"));
        assert!(!pods[0].terminating && pods[0].ready);
        assert!(pods[1].terminating && !pods[1].ready);
        // An uncontrolled pod has no owner to match against.
        assert!(pods[2].owner.is_none());
        // A row the jsonpath template could not have produced is an error, not
        // a pod with empty fields.
        assert!(parse_pod_lines("web-oldest\tuid-oldest\n").is_err());
        assert!(parse_pod_lines("\tuid\t\t\tRunning\t\tTrue\n").is_err());
    }

    #[test]
    fn only_the_selected_deployments_replica_sets_are_owners() {
        let owners = parse_replica_set_lines(
            concat!(
                "rs-web\tDeployment:deployment-web\n",
                "rs-other\tDeployment:deployment-other\n",
                "rs-orphan\t\n",
            ),
            "deployment-web",
        )
        .unwrap();
        assert_eq!(
            owners,
            [Owner {
                kind: "ReplicaSet".into(),
                uid: "rs-web".into(),
            }]
        );
    }

    #[test]
    fn the_workload_columns_parse_back() {
        let deployment = parse_workload_line("deployment-web\t3\t3\t2\t\t\n").unwrap();
        assert_eq!(deployment.uid, "deployment-web");
        assert_eq!((deployment.desired, deployment.ready), (3, 2));
        // A DaemonSet has no spec.replicas; its own counters answer instead.
        let daemonset = parse_workload_line("ds-agent\t\t\t\t4\t1\n").unwrap();
        assert_eq!((daemonset.desired, daemonset.ready), (4, 1));
        assert!(parse_workload_line("\t3\t3\t3\t\t\n").is_err());
        assert!(parse_workload_line("ds-agent\t4\t1\n").is_err());
    }

    #[test]
    fn the_selector_is_built_from_every_match_label() {
        let object = json!({"spec": {"selector": {"matchLabels": {"app": "web", "tier": "fe"}}}});
        assert_eq!(selector(&object).unwrap(), "app=web,tier=fe");
    }

    #[test]
    fn inputs_default_to_the_harmless_setting() {
        let options = Options::from(&BTreeMap::new()).unwrap();
        assert!(options.dry_run);
        assert_eq!(options.count, 1);
        assert_eq!(options.wait, Duration::from_secs(120));
        let bad: BTreeMap<String, String> = [("wait".to_string(), "10w".to_string())]
            .into_iter()
            .collect();
        assert!(Options::from(&bad).is_err());
    }

    #[test]
    fn a_saved_pod_list_can_never_delete() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.insert(
            "pods".into(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/pods.json").into(),
        );
        // Even with dry_run=false, a saved run stays a dry run.
        let saved = Saved::open(request.inputs.get("pods").unwrap(), &request).unwrap();
        let report = run(&request, &saved).unwrap();
        assert_eq!(value(&report, "Verdict"), "dry run — nothing was deleted");
        assert_eq!(value(&report, "Would kill"), "2");
        // And the delete path itself refuses outright.
        assert!(
            saved
                .delete(
                    &Scope {
                        context: String::new(),
                        namespace: "apps".into(),
                        resource: "deployments".into(),
                        name: "web".into(),
                    },
                    &["web-oldest".to_string()]
                )
                .is_err()
        );
    }

    #[test]
    fn fixture_matches_expected_report() {
        let request = request();
        let expected: Value =
            serde_json::from_str(include_str!("../fixtures/report.json")).unwrap();
        let saved = Saved {
            pods: serde_json::from_str(PODS).unwrap(),
            workload: request.object.clone().unwrap(),
        };
        assert_eq!(run(&request, &saved).unwrap(), expected);
        // CI runs the adapter from the repository root.
        assert_eq!(
            request.inputs.get("pods").map(String::as_str),
            Some("plugins/chaos-kill/fixtures/pods.json")
        );
    }

    #[test]
    fn rejects_unknown_request_schema() {
        let mut request = request();
        request.schema_version = 2;
        assert!(
            run(&request, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("unsupported request schema_version")
        );
    }
}
