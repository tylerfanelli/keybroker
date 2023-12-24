// SPDX-License-Identifier: Apache-2.0

use super::*;

use endorser::{snp::SnpEndorser, Endorser};

use openssl::base64::encode_block as b64_encode;
use sev::{firmware::guest::AttestationReport, Generation};

pub struct SnpVerifier {
    id: Uuid,
    report: AttestationReport,
    gen: Generation,
    pkey: Rsa<Public>,
}

impl Verifier for SnpVerifier {
    fn endorse(&self) -> Result<(), endorser::Error> {
        let endorser = SnpEndorser::new(&self.report, self.gen);
        endorser.endorse()
    }

    fn freshness(&self) -> Result<(), Error> {
        let b64_n = b64_encode(&self.pkey.n().to_vec());
        let b64_e = b64_encode(&self.pkey.e().to_vec());

        let expect = {
            let mut hash = Sha512::new();

            hash.update(self.id.to_string().as_bytes());
            hash.update(b64_n.as_bytes());
            hash.update(b64_e.as_bytes());

            hash.finish()
        };

        if expect == self.report.report_data {
            Ok(())
        } else {
            Err(Error::Freshness)
        }
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
}

impl SnpVerifier {
    pub fn new(id: Uuid, report: AttestationReport, gen: Generation, pkey: Rsa<Public>) -> Self {
        Self {
            id,
            report,
            gen,
            pkey,
        }
    }
}
