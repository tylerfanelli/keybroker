// SPDX-License-Identifier: Apache-2.0

pub(super) mod rvp;
mod verifier;

use super::kbs;
use verifier::{snp::SnpVerifier, Verifier};

use anyhow::{anyhow, Result};
use kbs_types::Tee;
use serde_json::{Map, Value};

#[allow(dead_code)]
pub fn attest(
    attestation: kbs_types::Attestation,
    session: &mut kbs::Session,
) -> Result<Map<String, Value>> {
    let verifier: Box<dyn Verifier> = match session.tee() {
        Tee::Snp => Box::new(SnpVerifier::try_from((attestation, session.id()))?),
        _ => return Err(anyhow!("selected TEE is not supported")),
    };

    let _claims = verifier.verify()?;

    todo!()
}
