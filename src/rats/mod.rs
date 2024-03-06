// SPDX-License-Identifier: Apache-2.0

mod appraisal;
pub(super) mod rvp;
mod verifier;

use super::kbs;

use appraisal::{opa::OpaAppraiser, Appraiser};
use rvp::{rvp_map, RVP_MAP};
use verifier::{snp::SnpVerifier, Verifier};

use anyhow::{anyhow, Context, Result};
use kbs_types::Tee;
use openssl::{base64, bn::BigNum, pkey::Public, rsa::Rsa};
use serde_json::{Map, Value};

pub fn attest(
    attestation: kbs_types::Attestation,
    session: &mut kbs::Session,
) -> Result<(Map<String, Value>, Rsa<Public>)> {
    let pkey = pkey(attestation.tee_pubkey.clone())?;

    let verifier: Box<dyn Verifier> = match session.tee() {
        Tee::Snp => Box::new(SnpVerifier::try_from((attestation, session.id(), pkey))?),
        _ => return Err(anyhow!("selected TEE is not supported")),
    };

    let (claims, rvp_id) = verifier.verify()?;

    let ref_vals = rvp_map!().get(&rvp_id)?;
    let opa = OpaAppraiser::try_from((ref_vals, claims)).unwrap();

    opa.appraise().unwrap();

    todo!()
}

fn pkey(kbs: kbs_types::TeePubKey) -> Result<Rsa<Public>> {
    let n_bytes = base64::decode_block(&kbs.k_mod)
        .context("unable to decode RSA public key modulus from base64")?;
    let e_bytes = base64::decode_block(&kbs.k_exp)
        .context("unable to decode RSA public key exponent from base64")?;

    let n = BigNum::from_slice(&n_bytes).context("invalid RSA public key modulus")?;
    let e = BigNum::from_slice(&e_bytes).context("invalid RSA public key exponent")?;

    Rsa::from_public_components(n, e).context("invalid RSA public key components")
}
