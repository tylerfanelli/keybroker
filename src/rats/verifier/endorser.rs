// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use curl::easy::Easy;

#[allow(dead_code)]
pub trait Endorser {
    fn endorse(&self) -> Result<()>;
}

pub mod snp {
    use super::*;

    use std::convert::From;

    use openssl::x509::X509;
    use sev::{
        certs::snp::{ca, Chain, Verifiable},
        firmware::guest::AttestationReport,
        Generation,
    };

    pub struct SnpEndorser<'a> {
        report: &'a AttestationReport,
        gen: Generation,
    }

    impl<'a> Endorser for SnpEndorser<'a> {
        fn endorse(&self) -> Result<()> {
            let chain = self.chain().context("unable to fetch AMD ARK/ASK chain")?;

            if let Err(e) = (&chain, self.report).verify() {
                return Err(anyhow!(format!(
                    "unable to verify ARK/ASK/VCEK/Attestation report signature: {}",
                    e
                )));
            }

            Ok(())
        }
    }

    impl<'a> From<(&'a AttestationReport, Generation)> for SnpEndorser<'a> {
        fn from(data: (&'a AttestationReport, Generation)) -> Self {
            Self {
                report: data.0,
                gen: data.1,
            }
        }
    }

    impl<'a> SnpEndorser<'a> {
        fn chain(&self) -> Result<Chain> {
            let ca = ca::Chain::from(self.gen);
            ca.verify().context("unable to verify AMD CA chain")?;

            let vcek = self.vcek()?;

            let chain = Chain {
                ca,
                vek: vcek.clone().into(),
            };

            Ok(chain)
        }

        fn vcek(&self) -> Result<X509> {
            let id = hex::encode(self.report.chip_id);
            let url = format!(
            "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                self.gen.titlecase(), id,
                self.report.current_tcb.bootloader,
                self.report.current_tcb.tee,
                self.report.current_tcb.snp,
                self.report.current_tcb.microcode);

            let der = curl_get(url).context("unable to fetch VCEK from AMD KDS")?;

            X509::from_der(&der).context("unable to decode VCEK from AMD KDS")
        }
    }
}

fn curl_get(url: String) -> Result<Vec<u8>, curl::Error> {
    let mut handle = Easy::new();
    let mut buf: Vec<u8> = Vec::new();

    handle.url(&url)?;
    handle.get(true)?;

    let mut transfer = handle.transfer();
    transfer.write_function(|data| {
        buf.extend_from_slice(data);
        Ok(data.len())
    })?;

    transfer.perform()?;

    drop(transfer);

    Ok(buf)
}
