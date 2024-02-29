// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Mutex};

use actix_web::{post, web::Json, HttpResponse};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

/// A client's reference values to compare with its TEE evidence in the appraisal process.
#[derive(Deserialize, Serialize)]
pub(super) struct RvpRefValues {
    /// Queries on the TEE evidence with respect to the attestation policy.
    query: Vec<String>,

    /// Reference TEE evidence information to compare with.
    reference_values: Map<String, Value>,

    /// Resources able to be fetched on a successful attestation.
    resources: Map<String, Value>,
}

// A map of guest UUIDs to reference values.
lazy_static! {
    pub(super) static ref RVP_MAP: Mutex<HashMap<Uuid, RvpRefValues>> = Mutex::new(HashMap::new());
}

// Lock the mutex and access the underlying RVP map.
#[macro_export]
macro_rules! rvp_map {
    () => {
        RVP_MAP.lock().unwrap()
    };
}

/// Register a client's reference values with the RATS reference value provider (RVP).
#[post("/register")]
pub async fn register(json: Json<RvpRefValues>) -> actix_web::Result<HttpResponse> {
    let input: RvpRefValues = json.into_inner();

    // Associate the guest's reference values with a UUID.
    let id = Uuid::new_v4();

    rvp_map!().insert(id, input);

    Ok(HttpResponse::Ok().json(id.to_string()))
}
