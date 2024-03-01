// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, str::FromStr, sync::RwLock};

use actix_web::{cookie::Cookie, post, web, HttpRequest, HttpResponse, Result};
use kbs_types::{Challenge, Request};
use lazy_static::lazy_static;
use openssl::{pkey::Public, rsa::Rsa};
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
#[allow(unreachable_code, unused_variables)]
#[post("/attest")]
pub async fn attest(
    req: HttpRequest,
    attest: web::Json<kbs_types::Attestation>,
) -> Result<HttpResponse> {
    let id = Uuid::from_str(req.cookie("kbs-session-id").unwrap().value()).unwrap();

    let mut map = smap!();
    let session = map.get_mut(&id).unwrap();

    // TODO: Attest the workload.
    todo!();

    let cookie = Cookie::build("kbs-session-id", id.to_string()).finish();

    Ok(HttpResponse::Ok().cookie(cookie).finish())
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
}
