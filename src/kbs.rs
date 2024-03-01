// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::RwLock};

use actix_web::{cookie::Cookie, post, web, HttpResponse, Result};
use kbs_types::{Challenge, Request};
use lazy_static::lazy_static;
use openssl::{pkey::Public, rsa::Rsa};
use serde_json::{Map, Value};
use uuid::Uuid;

pub struct SessionMap(RwLock<HashMap<Uuid, Session>>);

lazy_static! {
    pub static ref SESSION_MAP: SessionMap = SessionMap(RwLock::new(HashMap::new()));
}

#[macro_export]
macro_rules! smap {
    () => {
        SESSION_MAP.0.write().unwrap()
    };
}

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
    pub fn id(&self) -> Uuid {
        self.id
    }
}
