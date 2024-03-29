// SPDX-License-Identifier: Apache-2.0

mod appraisal;
pub(super) mod rvp;
mod verifier;

use super::kbs;

use appraisal::{opa::OpaAppraiser, Appraiser};
use rvp::{rvp_map, RVP_MAP};
use verifier::Verifier;

use anyhow::{Context, Result};
use openssl::{base64, bn::BigNum, pkey::Public, rsa::Rsa};
use serde_json::{Map, Value};

pub fn attest(
    attestation: kbs_types::Attestation,
    session: &mut kbs::Session,
) -> Result<(Rsa<Public>, Map<String, Value>)> {
    let pkey = pkey(attestation.tee_pubkey.clone())?;

    let verifier: Box<dyn Verifier> =
        (session.tee(), attestation, session.id(), pkey.clone()).try_into()?;

    let (claims, rvp_id) = verifier.verify()?;

    let ref_vals = rvp_map!().get(&rvp_id)?;
    let opa = OpaAppraiser::try_from((ref_vals.clone(), claims)).unwrap();

    opa.appraise().unwrap();

    Ok((pkey, ref_vals.resources))
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
