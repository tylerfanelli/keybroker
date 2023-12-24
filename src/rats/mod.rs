// SPDX-License-Identifier: Apache-2.0

mod appraisal;
pub(super) mod rvp;
mod verifier;

use appraisal::{opa::OpaAppraiser, Appraiser};
use rvp::{resources_get, rv_get, ReferenceValues};
use verifier::Verifier;

use crate::kbs::session::Session;

use std::ptr::read;

use kbs_types::{self as KBS, Tee};

pub struct RatsAttester<'a> {
    pub s: &'a mut Session,
    pub a: KBS::Attestation,
}

impl<'a> RatsAttester<'a> {
    pub fn new(s: &'a mut Session, a: KBS::Attestation) -> Self {
        Self { s, a }
    }

    pub fn attest(&mut self) -> Result<(), Error> {
        match self.s.tee {
            Tee::Snp => snp::attest(self.s, self.a.clone()),
            _ => Err(Error::TeeUnsupported),
        }
    }
}

pub mod snp {
    use super::*;

    use crate::rats::verifier::snp::SnpVerifier;

    use openssl::{base64::decode_block, bn::BigNum, rsa::Rsa};
    use sev::{firmware::guest::AttestationReport, Generation};
    use uuid::Uuid;

    pub(super) fn attest(s: &mut Session, a: KBS::Attestation) -> Result<(), Error> {
        let (report, gen, n, e) = args(a)?;

        let rsa = Rsa::from_public_components(n, e).unwrap();

        let reference = rv_vals(&report);
        let claims = SnpVerifier::new(s.id, report, gen, rsa.clone())
            .verify()
            .unwrap();

        let opa = OpaAppraiser {
            id: reference_id(&report),
            policy: reference.policy.clone(),
            reference: reference.reference,
            input: claims.to_string(),
            queries: reference.queries,
        };

        opa.appraise().unwrap();

        let map = resources_get(reference_id(&report)).unwrap();

        s.resources_set(rsa, map);

        Ok(())
    }

    fn args(a: KBS::Attestation) -> Result<(AttestationReport, Generation, BigNum, BigNum), Error> {
        let snp: KBS::SnpAttestation = serde_json::from_str(&a.tee_evidence).unwrap();
        let report = unsafe { report_from_json_hex(&snp) };
        let gen = match &snp.gen[..] {
            "milan" => Generation::Milan,
            "genoa" => Generation::Genoa,
            _ => panic!(),
        };

        //let (report, gen): (AttestationReport, Generation) = snp.try_into().unwrap();

        let n = pkey_decode(a.tee_pubkey.k_mod)?;
        let e = pkey_decode(a.tee_pubkey.k_exp)?;

        Ok((report, gen, n, e))
    }

    fn pkey_decode(b64: String) -> Result<BigNum, Error> {
        let bytes = decode_block(&b64).unwrap();

        Ok(BigNum::from_slice(&bytes).unwrap())
    }

    fn rv_vals(report: &AttestationReport) -> ReferenceValues {
        rv_get(reference_id(report)).unwrap()
    }

    fn reference_id(report: &AttestationReport) -> Uuid {
        let mut id = [0u8; 16];
        id.copy_from_slice(&report.host_data[..16]);

        Uuid::from_bytes(id)
    }

    unsafe fn report_from_json_hex(snp: &KBS::SnpAttestation) -> AttestationReport {
        let bytes = hex::decode(snp.report.clone()).unwrap();

        read(bytes.as_ptr() as *const AttestationReport)
    }
}

#[derive(Debug)]
pub enum Error {
    TeeUnsupported,
}
