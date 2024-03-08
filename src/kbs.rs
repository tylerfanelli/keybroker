// SPDX-License-Identifier: Apache-2.0

use super::rats;

use std::{collections::HashMap, fmt, str::FromStr, sync::RwLock};

use actix_web::{
    body::BoxBody,
    cookie::Cookie,
    error::ResponseError,
    get,
    http::{header::ContentType, StatusCode},
    post, web, HttpRequest, HttpResponse, Result,
};
use anyhow::Context;
use kbs_types::{Challenge, Request};
use lazy_static::lazy_static;
use openssl::{
    pkey::Public,
    rsa::{Padding, Rsa},
};
use serde_json::{Map, Value};
use uuid::Uuid;

/// To keep track of different KBS attestation sessions, maintain a mapping of ID's (stored via
/// HTTP cookies) and session data.
pub struct SessionMap(RwLock<HashMap<Uuid, Session>>);

// Static, heap-allocated map of sessions.
lazy_static! {
    pub static ref SESSION_MAP: SessionMap = SessionMap(RwLock::new(HashMap::new()));
}

// Lock the session map mutex for writing and return the underlying data in a mutable reference for
// modification.
#[macro_export]
macro_rules! smap {
    () => {
        SESSION_MAP.0.write().unwrap()
    };
}

/// Initiate the attestation protocol and authenticate itself against the KBS. The KBS replies with
/// a HTTP response of a Challenge and Set-Cookie header set to kbs-session-id={SESSION_UUID}.
#[post("/auth")]
pub async fn auth(req: web::Json<Request>) -> Result<HttpResponse> {
    let session = Session::from(req.into_inner());

    let id = session.id();

    smap!().insert(id, session);

    let cookie = Cookie::build("kbs-session-id", id.to_string()).finish();

    let c = Challenge {
        nonce: id.to_string(),
        extra_params: String::new(),
    };

    Ok(HttpResponse::Ok().cookie(cookie).json(c))
}

/// Reply to attestation challenge with a client's attestation evidence. Server will attest the
/// evidence according to RATS and indicate whether the attestation was successful or not. On
/// successful attestation, client's pre-registered attestation information will be made available
/// for fetching from /key endpoint.
#[post("/attest")]
pub async fn attest(
    req: HttpRequest,
    attest: web::Json<kbs_types::Attestation>,
) -> Result<HttpResponse> {
    let id = kbs_session_id(req).map_err(KeybrokerError)?;

    let mut map = smap!();
    let session = map
        .get_mut(&id)
        .context(format!("session with ID {} not found", id))
        .map_err(KeybrokerError)?;

    let resources = rats::attest(attest.into_inner(), session).map_err(KeybrokerError)?;

    session.resources_set(resources);

    let cookie = Cookie::build("kbs-session-id", id.to_string()).finish();

    Ok(HttpResponse::Ok().cookie(cookie).finish())
}

#[get("/resource/{name}")]
pub async fn resource(req: HttpRequest, path: web::Path<String>) -> Result<HttpResponse> {
    let id = kbs_session_id(req).map_err(KeybrokerError)?;

    let resource_name = path.into_inner();

    let mut map = smap!();
    let session = map
        .get_mut(&id)
        .context(format!("session with ID {} not found", id))
        .map_err(KeybrokerError)?;

    let ciphertext = session
        .encrypted_resource(resource_name)
        .map_err(KeybrokerError)?;

    let resp = kbs_types::Response {
        protected: "".to_string(),
        encrypted_key: "".to_string(),
        iv: "".to_string(),
        ciphertext,
        tag: "".to_string(),
    };

    Ok(HttpResponse::Ok().json(resp))
}

/// Describes the state managed between each step in the KBS protocol for a specific client.
/// Sessions are unique to each attesting client.
#[allow(dead_code)]
pub struct Session {
    id: Uuid,
    resources: Option<(Rsa<Public>, Map<String, Value>)>,
    tee: kbs_types::Tee,
}

impl From<Request> for Session {
    fn from(req: Request) -> Self {
        let id = Uuid::new_v4();

        Self {
            id,
            resources: None,
            tee: req.tee,
        }
    }
}

impl Session {
    /// Fetch the ID of this session (i.e. the ID in which the session is indexed in the session
    /// map).
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Fetch the TEE that the session is attesting for.
    pub fn tee(&self) -> kbs_types::Tee {
        self.tee
    }

    /// On successful attestation, give the session access to both the resources and the RSA public
    /// key used to encrypt the resources.
    pub fn resources_set(&mut self, data: (Rsa<Public>, Map<String, Value>)) {
        self.resources = Some(data);
    }

    /// Attempt to fetch a resource from a client's resource map. The resource must be encrypted
    /// with the client's public key.
    pub fn encrypted_resource(&self, name: String) -> anyhow::Result<String> {
        let (key, map) = self.resources.as_ref().context("session is unattested")?;

        let val = map
            .get(&name)
            .context(format!("resource with name {} not found", name))?;

        let val = match val {
            Value::String(s) => s,
            _ => panic!("not a string"),
        };

        let mut encrypted = vec![0; key.size() as usize];
        key.public_encrypt(val.as_bytes(), &mut encrypted, Padding::PKCS1)
            .context(format!("unable to encrypt {} resource", name))?;

        Ok(hex::encode(encrypted))
    }
}

/// A wrapper around anyhow Errors to allow for implementing actix_web::ResponseError. This allows
/// anyhow Errors to be cleanly consumed, with their error messages being returned to the attesting
/// client.
#[derive(Debug)]
pub struct KeybrokerError(anyhow::Error);

impl fmt::Display for KeybrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl ResponseError for KeybrokerError {
    /// Something was wrong with the request. This could mean the attestation evidence was faulty,
    /// a resource that doesn't exist was requested, the public keys were unable to correctly
    /// parsed, etc.
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    /// Wrap the anyhow Error's message into an HttpResponse so the client can discover what went
    /// wrong in their attestation.
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(format!("keybroker error: {}", self.0))
    }
}

/// Given an HTTP request from an attesting/attested client, parse the kbs-session-id cookie that
/// was set in the authentication phase (/auth).
fn kbs_session_id(req: HttpRequest) -> anyhow::Result<Uuid> {
    let cookie = req
        .cookie("kbs-session-id")
        .context("kbs-session-id cookie not found")?;

    Uuid::from_str(cookie.value()).context("value of kbs-session-id cookie not a valid UUID")
}
