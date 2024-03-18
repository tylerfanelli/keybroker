// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::*;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, Map, Value};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    #[structopt(long, about = "HTTP address of the keybroker server to register with")]
    http: String,

    #[structopt(long = "reference", about = "Path to reference values")]
    reference: PathBuf,

    #[structopt(long = "queries", about = "Path to the JSON OPA policy queries")]
    query: PathBuf,

    #[structopt(long = "resources", about = "Path to JSON resource definitions")]
    resources: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RvpRefValues {
    pub query: Vec<String>,
    pub reference_values: Map<String, Value>,
    pub resources: Map<String, Value>,
}

fn main() -> Result<()> {
    let args = Args::from_args();

    let query = queries(args.query.as_path())?;
    let reference = reference(args.reference.as_path())?;
    let resources = resources(args.resources.as_path())?;

    let rvp = RvpRefValues {
        query,
        reference_values: reference,
        resources,
    };

    let r_id = post(args.http, rvp)?;

    println!("\nbase64-encoded HOST_DATA: {}", &r_id[1..r_id.len() - 1]);

    Ok(())
}

fn post(http: String, vals: RvpRefValues) -> Result<String> {
    let cli = ClientBuilder::new()
        .build()
        .context("unable to build HTTP client")?;

    let url = format!("{}/rvp/register", http);

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

fn json_map(path: &Path, msg: String) -> Result<Map<String, Value>> {
    let json = contents(path, msg.clone())?;

    let map: Map<String, Value> = from_str(&json).context(format!(
        "unable to decode {} found in {} to a JSON map",
        msg,
        path.display()
    ))?;

    Ok(map)
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

fn reference(path: &Path) -> Result<Map<String, Value>> {
    json_map(path, "reference values".to_string())
}

fn queries(path: &Path) -> Result<Vec<String>> {
    json_strvec(path, "OPA queries".to_string())
}

fn resources(path: &Path) -> Result<Map<String, Value>> {
    json_map(path, "resource tokens".to_string())
}
