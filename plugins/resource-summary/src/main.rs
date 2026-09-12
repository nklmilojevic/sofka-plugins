use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Request {
    schema_version: u32,
    context: Option<String>,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
    object: Option<Value>,
}

fn report(request: &Request) -> Result<Value, String> {
    if request.schema_version != 1 {
        return Err("unsupported request schema_version".into());
    }
    let object = request.object.as_ref().and_then(Value::as_object);
    let metadata = object
        .and_then(|object| object.get("metadata"))
        .and_then(Value::as_object);
    let value = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let rows = vec![
        json!(["Context", request.context.as_deref().unwrap_or("inferred")]),
        json!(["Kind", value(object.and_then(|object| object.get("kind")))]),
        json!([
            "Namespace",
            value(metadata.and_then(|m| m.get("namespace")))
        ]),
        json!(["Name", value(metadata.and_then(|m| m.get("name")))]),
    ];
    let mut sections = vec![json!({
        "title": "Selection",
        "columns": ["Field", "Value"],
        "rows": rows,
    })];
    if request
        .inputs
        .get("detail")
        .is_some_and(|detail| detail == "true")
    {
        let labels = metadata
            .and_then(|metadata| metadata.get("labels"))
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(key, value)| json!([key, value.as_str().unwrap_or_default()]))
            .collect::<Vec<_>>();
        sections.push(json!({
            "title": "Labels",
            "columns": ["Label", "Value"],
            "rows": labels,
        }));
    }
    Ok(json!({
        "schema_version": 1,
        "title": "Resource summary",
        "sections": sections,
    }))
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
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("request exceeds 1 MiB".into());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid request: {e}"))?;
    let output = serde_json::to_vec(&report(&request)?).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_matches_expected_report() {
        let request: Request =
            serde_json::from_str(include_str!("../fixtures/request.json")).unwrap();
        let expected: Value =
            serde_json::from_str(include_str!("../fixtures/report.json")).unwrap();
        assert_eq!(report(&request).unwrap(), expected);
    }

    #[test]
    fn rejects_unknown_request_schema() {
        let request: Request = serde_json::from_value(json!({
            "schema_version": 2,
            "context": null,
            "object": null
        }))
        .unwrap();
        assert!(report(&request).is_err());
    }
}
