// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::{collections::HashMap, sync::RwLock};

use lazy_static::lazy_static;
use openssl::rsa::Padding;
use serde_json::{Map as JsonMap, Value};

lazy_static! {
    pub static ref SESSION_MAP: SessionMap = SessionMap(RwLock::new(HashMap::new()));
}

pub struct SessionMap(pub RwLock<HashMap<Uuid, Session>>);

pub struct Session {
    pub id: Uuid,
    pub tee: KBS::Tee,
    pub resources: Option<(Rsa<Public>, JsonMap<String, Value>)>,
}

impl Session {
    pub fn new(tee: KBS::Tee) -> Self {
        let id = Uuid::new_v4();

        Self {
            id,
            tee,
            resources: None,
        }
    }

    pub fn resources_set(&mut self, r: Rsa<Public>, m: JsonMap<String, Value>) {
        self.resources = Some((r, m));
    }

    pub fn encrypted_resource(&self, id: String) -> KBS::Response {
        let (key, map) = self.resources.as_ref().unwrap();

        let val = match map.get(&id).unwrap() {
            Value::String(s) => s,
            _ => panic!("not a string"),
        };

        let mut encrypted = vec![0; key.size() as usize];
        key.public_encrypt(val.as_bytes(), &mut encrypted, Padding::PKCS1)
            .unwrap();

        let encoded = hex::encode(encrypted);

        KBS::Response {
            protected: "".to_string(),
            encrypted_key: "".to_string(),
            iv: "".to_string(),
            ciphertext: encoded,
            tag: "".to_string(),
        }
    }
}
