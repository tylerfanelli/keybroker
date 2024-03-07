// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

#[allow(dead_code)]
pub trait Appraiser {
    fn appraise(&self) -> Result<()> {
        let policy = self.policy();
        let reference_values = self.reference_values();
        let input = self.input();

        self.appraise_claims(policy, reference_values, input)
    }
    fn appraise_claims(&self, policy: String, reference: String, input: String) -> Result<()>;
    fn policy(&self) -> String;
    fn reference_values(&self) -> String;
    fn input(&self) -> String;
}

pub mod opa {
    use super::{super::rvp::RvpRefValues, *};

    use std::sync::Mutex;

    use lazy_static::lazy_static;
    use regorus::{Engine, QueryResults, Value};
    use serde::{Deserialize, Serialize};

    lazy_static! {
        pub static ref OPA_POLICY: Mutex<String> = Mutex::new("package policy".to_string());
    }

    macro_rules! opa_policy {
        () => {
            OPA_POLICY.lock().unwrap().clone()
        };
    }

    #[derive(Deserialize, Serialize)]
    pub struct OpaAppraiser {
        pub policy: String,
        pub reference: String,
        pub input: String,
        pub queries: Vec<String>,
    }

    impl TryFrom<(RvpRefValues, serde_json::Value)> for OpaAppraiser {
        type Error = anyhow::Error;

        fn try_from(data: (RvpRefValues, serde_json::Value)) -> Result<Self, Self::Error> {
            Ok(Self {
                policy: opa_policy!(),
                reference: serde_json::to_string(&data.0.reference_values).unwrap(),
                input: serde_json::to_string(&data.1).unwrap(),
                queries: data.0.query,
            })
        }
    }

    impl Appraiser for OpaAppraiser {
        fn appraise_claims(&self, policy: String, reference: String, input: String) -> Result<()> {
            let mut engine = Engine::new();

            let reference = regorus::Value::from_json_str(&reference).unwrap();
            let input = regorus::Value::from_json_str(&input).unwrap();

            engine
                .add_policy("policy.rego".to_string(), policy)
                .unwrap();
            engine.add_data(reference).unwrap();
            engine.set_input(input);

            for q in &self.queries {
                self.evaluate_queryresult(engine.eval_query(q.to_string(), true).unwrap())
                    .unwrap();
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
        fn evaluate_queryresult(&self, r: QueryResults) -> Result<()> {
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
}
