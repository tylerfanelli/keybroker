// SPDX-License-Identifier: Apache-2.0

mod appraisal;
pub(super) mod rvp;
mod verifier;

use super::kbs;

use appraisal::{opa::OpaAppraiser, Appraiser};
use rvp::{rvp_map, RVP_MAP};
use verifier::{snp::SnpVerifier, Verifier};

use anyhow::{anyhow, Result};
use kbs_types::Tee;
use serde_json::{Map, Value};

pub fn attest(
    attestation: kbs_types::Attestation,
    session: &mut kbs::Session,
) -> Result<Map<String, Value>> {
    let verifier: Box<dyn Verifier> = match session.tee() {
        Tee::Snp => Box::new(SnpVerifier::try_from((attestation, session.id()))?),
        _ => return Err(anyhow!("selected TEE is not supported")),
    };

    let (claims, rvp_id) = verifier.verify()?;

    let ref_vals = rvp_map!().get(&rvp_id)?;
    let opa = OpaAppraiser::try_from((ref_vals, claims)).unwrap();

    opa.appraise().unwrap();

    todo!()
}
