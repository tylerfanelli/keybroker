// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::*;
use serde_json::{from_str, Value};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    #[structopt(long, about = "HTTP address of the keybroker server to register with")]
    http: String,
    #[structopt(long = "opa", about = "Path to OPA appraisal policy")]
    opa: PathBuf,
    #[structopt(long = "reference", about = "Path to reference values")]
    reference: PathBuf,
    #[structopt(long = "queries", about = "Path to the JSON OPA policy queries")]
    queries: PathBuf,
    #[structopt(long = "resources", about = "Path to JSON resource definitions")]
    resources: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::from_args();

    let opa = opa(args.opa.as_path())?;
    let reference = reference(args.reference.as_path())?;
    let queries = queries(args.queries.as_path())?;
    let resources = resources(args.resources.as_path())?;

    let r_id = post(args.http, (opa, queries, reference, resources))?;

    println!(
        "\nReference UUID to be included in attestation report: {}\n",
        &r_id[1..r_id.len() - 1]
    );

    Ok(())
}

fn post(http: String, vals: (String, Vec<String>, String, String)) -> Result<String> {
    let cli = ClientBuilder::new()
        .build()
        .context("unable to build HTTP client")?;

    let url = format!("{}/rvp/registration", http);

    let body = cli
        .post(url.clone())
        .json(&vals)
        .send()
        .context(format!("unable to send POST request to URL: {}", url))?;

    let bytes = body
        .bytes()
        .context("unable to decode bytes of registration UUID")?;

    String::from_utf8(bytes.to_ascii_lowercase()).context("reference ID not in UTF8")
}

fn contents(path: &Path, msg: String) -> Result<String> {
    if !path.exists() {
        return Err(anyhow!(format!(
            "{} {} does not exist",
            msg,
            path.display()
        )));
    }

    read_to_string(path).context(format!("unable to read from {}", msg))
}

fn json(path: &Path, msg: String) -> Result<(String, Value)> {
    let c = contents(path, msg.clone())?;

    let json: Value = from_str(&c).context(format!(
        "unable to decode JSON {} from {}",
        msg,
        path.display()
    ))?;

    Ok((c, json))
}

fn json_obj(path: &Path, msg: String) -> Result<String> {
    let (c, val) = json(path, msg.clone())?;

    match val {
        Value::Object(_) => Ok(c),
        _ => Err(anyhow!(format!(
            "{} found in {} are not in the form of a JSON object",
            msg,
            path.display()
        ))),
    }
}

fn json_strvec(path: &Path, msg: String) -> Result<Vec<String>> {
    let c = contents(path, msg.clone())?;

    let arr: Vec<String> = from_str(&c).context(format!(
        "unable to decode {} found in {} to a string array",
        msg,
        path.display()
    ))?;

    Ok(arr)
}

fn opa(path: &Path) -> Result<String> {
    contents(path, "OPA policy".to_string())
}

fn reference(path: &Path) -> Result<String> {
    json_obj(path, "reference values".to_string())
}

fn queries(path: &Path) -> Result<Vec<String>> {
    json_strvec(path, "OPA queries".to_string())
}

fn resources(path: &Path) -> Result<String> {
    json_obj(path, "resource tokens".to_string())
}
