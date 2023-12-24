// SPDX-License-Identifier: Apache-2.0

mod registration;

pub use registration::*;
pub(super) use resource::*;
pub(super) use rv::*;

use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    sync::Mutex,
};

use actix_web::{
    error::ResponseError,
    http::{header::ContentType, StatusCode},
    HttpResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod rv {
    use super::*;

    lazy_static::lazy_static! {
        pub static ref REFERENCE_VALUES: Mutex<HashMap<String, ReferenceValues>> = Mutex::new(HashMap::new());
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ReferenceValues {
        pub policy: String,
        pub queries: Vec<String>,
        pub reference: String,
    }

    #[macro_export]
    macro_rules! rv_map {
        () => {
            REFERENCE_VALUES.lock().unwrap()
        };
    }

    pub fn rv_new(id: Uuid, r: ReferenceValues) {
        rv_map!().insert(id.to_string(), r);
    }

    pub fn rv_get(id: Uuid) -> Result<ReferenceValues, Error> {
        let rv = rv_map!()
            .remove(&id.to_string())
            .ok_or(Error::RvNotFound(id))?;

        Ok(rv)
    }
}

mod resource {
    use super::*;

    use serde_json::{Map as JsonMap, Value};

    lazy_static::lazy_static! {
        pub static ref RESOURCE_VALUES: Mutex<HashMap<Uuid, JsonMap<String, Value>>> = Mutex::new(HashMap::new());
    }

    #[macro_export]
    macro_rules! resource_map {
        () => {
            RESOURCE_VALUES.lock().unwrap()
        };
    }

    pub fn resources_new(id: Uuid, r: JsonMap<String, Value>) {
        resource_map!().insert(id, r);
    }

    pub fn resources_get(id: Uuid) -> Result<JsonMap<String, Value>, Error> {
        let resources = resource_map!()
            .remove(&id)
            .ok_or(Error::ResourceNotFound(id))?;

        Ok(resources)
    }
}

#[derive(Debug)]
pub enum Error {
    ResourceMapDecode(serde_json::Error),
    ResourceNotFound(Uuid),
    RvNotFound(Uuid),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let msg = match self {
            Error::ResourceMapDecode(s) => {
                format!("unable to deserialize resource input as a JSON map: {}", s)
            }
            Error::ResourceNotFound(u) => format!("no resources found for reference UUID: {}", u),
            Error::RvNotFound(u) => format!("no reference values found for reference UUID: {}", u),
        };

        write!(f, "{}", msg)
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}
