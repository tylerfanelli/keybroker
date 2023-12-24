// SPDX-License-Identifier: Apache-2.0

pub mod opa;

use regorus::*;

pub trait Appraiser {
    fn appraise(&self) -> Result<(), Error> {
        let policy = self.policy();
        let reference_values = self.reference_values();
        let input = self.input();

        self.appraise_claims(policy, reference_values, input)
    }
    fn appraise_claims(
        &self,
        policy: String,
        reference: String,
        input: String,
    ) -> Result<(), Error>;
    fn policy(&self) -> String;
    fn reference_values(&self) -> String;
    fn input(&self) -> String;
}

#[derive(Debug)]
pub enum Error {
    Policy,
    Reference,
    Input,
}
