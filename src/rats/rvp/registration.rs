// SPDX-License-Identifier: Apache-2.0

use super::{resource::*, rv::*, Error};

use actix_web::{post, web, HttpResponse};
use serde_json::{from_str, Map as JsonMap, Value};
use uuid::Uuid;

#[post("/registration")]
pub async fn register(
    info: web::Json<(String, Vec<String>, String, String)>,
) -> actix_web::Result<HttpResponse> {
    let id = Uuid::new_v4();

    let (policy, queries, reference, resources) = info.into_inner();

    let rv = ReferenceValues {
        policy,
        queries,
        reference,
    };

    let r_map: JsonMap<String, Value> = from_str(&resources).map_err(Error::ResourceMapDecode)?;

    rv_new(id, rv);
    resources_new(id, r_map);

    Ok(HttpResponse::Ok().json(id))
}
