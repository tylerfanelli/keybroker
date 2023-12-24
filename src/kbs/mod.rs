// SPDX-License-Identifier: Apache-2.0

pub(crate) mod session;

use super::*;

use rats::*;
use session::*;

use std::str::FromStr;

use actix_web::{cookie::Cookie, get, post, web, HttpRequest, HttpResponse, Result};
use kbs_types as KBS;
use openssl::{pkey::Public, rsa::Rsa};
use uuid::Uuid;

#[macro_export]
macro_rules! smap {
    () => {
        SESSION_MAP.0.write().unwrap()
    };
}

#[post("/auth")]
pub async fn auth(req: web::Json<KBS::Request>) -> Result<HttpResponse> {
    let session = Session::new(req.tee);
    let id = session.id;

    smap!().insert(id, session);

    let cookie = Cookie::build("kbs-session-id", id.to_string()).finish();

    let c = KBS::Challenge {
        nonce: id.to_string(),
        extra_params: "".to_string(),
    };

    Ok(HttpResponse::Ok().cookie(cookie).json(c))
}

#[post("/attest")]
pub async fn attest(
    req: HttpRequest,
    attestation: web::Json<KBS::Attestation>,
) -> Result<HttpResponse> {
    let id = Uuid::from_str(req.cookie("kbs-session-id").unwrap().value()).unwrap();

    let mut map = smap!();
    let session = map.get_mut(&id).unwrap();

    let mut attester = RatsAttester::new(session, attestation.into_inner());
    attester.attest().unwrap();

    let cookie = Cookie::build("kbs-session-id", id.to_string()).finish();

    Ok(HttpResponse::Ok().cookie(cookie).finish())
}

#[get("/resource/{name}")]
pub async fn resource(req: HttpRequest, path: web::Path<String>) -> Result<HttpResponse> {
    let id = Uuid::from_str(req.cookie("kbs-session-id").unwrap().value()).unwrap();
    let name = path.into_inner();

    let mut map = smap!();
    let session = map.get_mut(&id).unwrap();

    let resp = session.encrypted_resource(name);

    Ok(HttpResponse::Ok().json(resp))
}
