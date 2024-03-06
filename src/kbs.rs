// SPDX-License-Identifier: Apache-2.0

use super::rats;

use std::{collections::HashMap, str::FromStr, sync::RwLock};

use actix_web::{cookie::Cookie, get, post, web, HttpRequest, HttpResponse, Result};
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
    let id = Uuid::from_str(req.cookie("kbs-session-id").unwrap().value()).unwrap();

    let mut map = smap!();
    let session = map.get_mut(&id).unwrap();

    let resources = rats::attest(attest.into_inner(), session).unwrap();

    session.resources_set(resources);

    let cookie = Cookie::build("kbs-session-id", id.to_string()).finish();

    Ok(HttpResponse::Ok().cookie(cookie).finish())
}

#[get("/resource/{name}")]
pub async fn resource(req: HttpRequest, path: web::Path<String>) -> Result<HttpResponse> {
    let id = Uuid::from_str(req.cookie("kbs-session-id").unwrap().value()).unwrap();
    let resource_name = path.into_inner();

    let mut map = smap!();
    let session = map.get_mut(&id).unwrap();

    let resp = kbs_types::Response {
        protected: "".to_string(),
        encrypted_key: "".to_string(),
        iv: "".to_string(),
        ciphertext: session.encrypted_resource(resource_name),
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
    pub fn encrypted_resource(&self, name: String) -> String {
        let (key, map) = self.resources.as_ref().unwrap();

        let val = match map.get(&name).unwrap() {
            Value::String(s) => s,
            _ => panic!("not a string"),
        };

        let mut encrypted = vec![0; key.size() as usize];
        key.public_encrypt(val.as_bytes(), &mut encrypted, Padding::PKCS1)
            .unwrap();

        hex::encode(encrypted)
    }
}
