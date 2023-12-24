// SPDX-License-Identifier: Apache-2.0

use super::*;

use regorus::Value as RegoValue;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
pub struct OpaAppraiser {
    pub id: Uuid,
    pub policy: String,
    pub reference: String,
    pub input: String,
    pub queries: Vec<String>,
}

impl Appraiser for OpaAppraiser {
    fn appraise_claims(
        &self,
        policy: String,
        reference: String,
        input: String,
    ) -> Result<(), Error> {
        let mut engine = Engine::new();

        let reference = RegoValue::from_json_str(&reference).map_err(|_| Error::Reference)?;
        let input = RegoValue::from_json_str(&input).map_err(|_| Error::Input)?;

        engine
            .add_policy(format!("{}-policy.rego", self.id), policy)
            .map_err(|_| Error::Policy)?;

        engine.add_data(reference).map_err(|_| Error::Policy)?;
        engine.set_input(input);

        for q in &self.queries {
            self.evaluate_queryresults(engine.eval_query(q.to_string(), true).unwrap())?;
        }

        Ok(())
    }

    fn policy(&self) -> String {
        self.policy.clone()
    }

    fn reference_values(&self) -> String {
        self.reference.clone()
    }

    fn input(&self) -> String {
        self.input.clone()
    }
}

impl OpaAppraiser {
    fn evaluate_queryresults(&self, r: QueryResults) -> Result<(), Error> {
        for q in r.result {
            for e in q.expressions {
                if let Value::Bool(false) = e.value {
                    println!("\n\nFALSE\n\n");
                }
            }
        }

        Ok(())
    }
}
