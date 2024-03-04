// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Mutex};

use actix_web::{post, web::Json, HttpResponse};
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use openssl::sha::Sha256;
use serde::{Deserialize, Serialize};
use serde_json::{to_string as json, Map, Value};
use uuid::Uuid;

/// A client's reference values to compare with its TEE evidence in the appraisal process.
#[derive(Deserialize, Serialize)]
pub struct RvpRefValues {
    /// Queries on the TEE evidence with respect to the attestation policy.
    pub query: Vec<String>,

    /// Reference TEE evidence information to compare with.
    pub reference_values: Map<String, Value>,

    /// Resources able to be fetched on a successful attestation.
    pub resources: Map<String, Value>,
}

#[derive(Default)]
pub struct Rvp {
    vals: HashMap<Uuid, (RvpRefValues, u8)>,
    hashes: HashMap<[u8; 32], Uuid>,
}

lazy_static! {
    // A map of guest UUIDs to reference values.
    pub static ref RVP_MAP: Mutex<Rvp> = Mutex::new(Rvp::default());
}

// Lock the mutex and access the underlying RVP map.
#[macro_export]
macro_rules! rvp_map {
    () => {
        RVP_MAP.lock().unwrap()
    };
}

pub(crate) use rvp_map;

impl Rvp {
    /// Insert a set of reference values and return their associated UUID. Note that if the
    /// reference values are already found, their reference count will be updated and the existing
    /// UUID will be returned.
    pub fn insert(&mut self, vals: RvpRefValues) -> Uuid {
        let sha = self.hash_calc(&vals);

        // Check if there is already an entry for this set of reference values.
        if let Some(id) = self.hashes.get(&sha) {
            let entry = self.vals.get_mut(id).unwrap();
            (entry.1) += 1;

            return *id;
        }

        // Create a new entry in both the value store and hashes store.
        let id = Uuid::new_v4();
        self.hashes.insert(sha, id);
        self.vals.insert(id, (vals, 1));

        id
    }

    /// Calculate a set of reference values' SHA256 hash.
    pub fn hash_calc(&self, vals: &RvpRefValues) -> [u8; 32] {
        let mut sha = Sha256::new();

        for q in &vals.query {
            sha.update(q.as_bytes());
        }

        for key in vals.reference_values.keys() {
            sha.update(key.as_bytes());
        }

        for val in vals.reference_values.values() {
            sha.update(json(val).unwrap().as_bytes());
        }

        for key in vals.resources.keys() {
            sha.update(key.as_bytes());
        }

        for val in vals.resources.values() {
            sha.update(json(val).unwrap().as_bytes());
        }

        sha.finish()
    }

    /// Fetch the reference values from the UUID found in a client's evidence.
    pub fn get(&self, id: &Uuid) -> Result<&RvpRefValues> {
        Ok(&self
            .vals
            .get(id)
            .ok_or(anyhow!(format!(
                "no reference values found for UUID {}",
                id
            )))?
            .0)
    }
}

/// Register a client's reference values with the RATS reference value provider (RVP).
#[post("/register")]
pub async fn register(json: Json<RvpRefValues>) -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(rvp_map!().insert(json.into_inner()).to_string()))
}
