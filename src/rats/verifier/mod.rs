// SPDX-License-Identifier: Apache-2.0

mod endorser;

use endorser::Endorser;

use anyhow::{anyhow, Context, Result};
use openssl::base64;
use uuid::Uuid;

/// A Verifer for each specific TEE architecture. Verification of hardware evidence (i.e.
/// attestation reports) encompasses both endorsement and "freshness".
///
/// Endorsement ensures that the evidence is legitimate, it is done by tracing the evidence's
/// signature back to the root of trust of the specific TEE hardware maufacturer.
///
/// "Freshness" ensures that the guest is responsible for the evidence. Earlier in KBS attestation,
/// a "freshness hash" is calculated using the nonce and TEE public key. The resulting hashed is
/// re-calculated and checked with a certain field of the TEE evidence.
///
/// On successful, a JSON-encoded string containing all of the parsed claims found from the TEE
/// evidence is returned to be checked by the appraisal policy.
pub trait Verifier {
    /// Verify that attestation evidence is both endorsed by the hardware manufacturer, as
    /// well as ruled "fresh" by checking its nonce hash and public key.
    fn verify(&self) -> Result<(serde_json::Value, Uuid)> {
        self.endorse()?;
        self.freshness()?;

        Ok((self.claims(), self.rvp_id()))
    }

    /// Ensure that the attestation evidence is endorsed by the hardware manufacturer.
    fn endorse(&self) -> Result<()>;

    /// Ensure that the attestation evidence is "fresh" by checking its nonce hash and public key.
    fn freshness(&self) -> Result<()>;

    /// Return a JSON-encoded string of all of the parsed claims of the respective TEE's
    /// attestation report.
    fn claims(&self) -> serde_json::Value;

    /// Get the UUID used to identify this client's reference values in the RVP storage.
    fn rvp_id(&self) -> Uuid;
}

pub mod snp {
    use super::{endorser::snp::SnpEndorser, *};

    use std::{convert::From, ptr::read};

    use openssl::{bn::BigNum, pkey::Public, rsa::Rsa, sha::Sha512};
    use sev::{firmware::guest::AttestationReport, Generation};
    use uuid::Uuid;

    pub struct SnpVerifier {
        nonce: Uuid,
        report: AttestationReport,
        gen: Generation,
        pkey: Rsa<Public>,
    }

    impl Verifier for SnpVerifier {
        fn endorse(&self) -> Result<()> {
            let endorser = SnpEndorser::from((&self.report, self.gen));

            endorser.endorse()
        }

        fn freshness(&self) -> Result<()> {
            let b64_n = base64::encode_block(&self.pkey.n().to_vec());
            let b64_e = base64::encode_block(&self.pkey.e().to_vec());

            let expect = {
                let mut hash = Sha512::new();

                hash.update(self.nonce.to_string().as_bytes());
                hash.update(b64_n.as_bytes());
                hash.update(b64_e.as_bytes());

                hash.finish()
            };

            if expect != self.report.report_data {
                return Err(anyhow!("freshness hash mismatch"));
            }

            Ok(())
        }

        fn claims(&self) -> serde_json::Value {
            serde_json::json!({
                "measurement": format!("{}", hex::encode(self.report.measurement)),
                "policy_abi_major": format!("{}", self.report.policy.abi_major()),
                "policy_abi_minor": format!("{}", self.report.policy.abi_minor()),
                "policy_smt_allowed": format!("{}", self.report.policy.smt_allowed()),
                "policy_migrate_ma": format!("{}", self.report.policy.migrate_ma_allowed()),
                "policy_debug_allowed": format!("{}", self.report.policy.debug_allowed()),
                "policy_single_socket": format!("{}", self.report.policy.single_socket_required()),
                "reported_tcb_bootloader": format!("{}", self.report.reported_tcb.bootloader),
                "reported_tcb_tee": format!("{}", self.report.reported_tcb.tee),
                "reported_tcb_snp": format!("{}", self.report.reported_tcb.snp),
                "reported_tcb_microcode": format!("{}", self.report.reported_tcb.microcode),
                "platform_tsme_enabled": format!("{}", self.report.plat_info.tsme_enabled()),
                "platform_smt_enabled": format!("{}", self.report.plat_info.smt_enabled()),
            })
        }

        fn rvp_id(&self) -> Uuid {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&self.report.host_data[..16]);

            Uuid::from_bytes(bytes)
        }
    }

    impl TryFrom<(kbs_types::Attestation, Uuid)> for SnpVerifier {
        type Error = anyhow::Error;

        fn try_from(attestation: (kbs_types::Attestation, Uuid)) -> Result<Self> {
            let args: kbs_types::SnpAttestation = serde_json::from_str(&attestation.0.tee_evidence)
                .context(
                    "unable to parse SNP attestation args from KBS attestation type's TEE evidence field"
                )?;

            let report = unsafe {
                let bytes = hex::decode(args.report.clone())
                    .context("unable to decode attestation report from hex")?;

                read(bytes.as_ptr() as *const AttestationReport)
            };

            let gen = match Generation::try_from(args.gen.to_string()) {
                Ok(g) => g,
                Err(_) => return Err(anyhow!("invalid TEE generation")),
            };

            let n = pkey_decode(attestation.0.tee_pubkey.k_mod)?;
            let e = pkey_decode(attestation.0.tee_pubkey.k_exp)?;

            Ok(Self {
                nonce: attestation.1,
                report,
                gen,
                pkey: Rsa::from_public_components(n, e)
                    .context("unable to build RSA public key from submitted public components")?,
            })
        }
    }

    fn pkey_decode(b64: String) -> Result<BigNum> {
        let bytes = base64::decode_block(&b64).context("unable to decode block from base64")?;

        BigNum::from_slice(&bytes).context("unable to convert public key encoding")
    }
}
