// SPDX-License-Identifier: Apache-2.0

use super::{curl_get, Endorser};

use std::io;

use sev::{
    certs::snp::{ca, Certificate, Chain, Verifiable},
    firmware::guest::AttestationReport,
    Generation,
};

use openssl::{ecdsa::EcdsaSig, sha::Sha384, x509::X509};

pub struct SnpEndorser<'a> {
    report: &'a AttestationReport,
    gen: Generation,
}

impl<'a> Endorser for SnpEndorser<'a> {
    fn endorse(&self) -> Result<(), super::Error> {
        let chain = self.chain().map_err(super::Error::Snp)?;

        chain
            .verify()
            .map_err(Error::VcekVerify)
            .map_err(super::Error::Snp)?;

        let signature = EcdsaSig::try_from(&self.report.signature)
            .map_err(|_| Error::EcdsaSigDecode)
            .map_err(super::Error::Snp)?;

        self.report_signed(signature, chain.vcek)
            .map_err(super::Error::Snp)
    }
}

impl<'a> SnpEndorser<'a> {
    pub fn new(report: &'a AttestationReport, gen: Generation) -> Self {
        Self { report, gen }
    }

    fn vcek(&self) -> Result<X509, Error> {
        let id = hex::encode(self.report.chip_id);
        let url = format!(
        "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                self.gen.titlecase(), id,
                self.report.current_tcb.bootloader,
                self.report.current_tcb.tee,
                self.report.current_tcb.snp,
                self.report.current_tcb.microcode);

        let der = curl_get(url).map_err(Error::VcekFetch)?;

        match X509::from_der(&der) {
            Err(_) => Err(Error::VcekDecode),
            Ok(c) => Ok(c),
        }
    }

    fn chain(&self) -> Result<Chain, Error> {
        let ca = ca::Chain::from(self.gen);
        ca.verify().map_err(Error::CaVerify)?;

        let vcek = self.vcek()?;

        let chain = Chain {
            ca,
            vcek: vcek.clone().into(),
        };

        Ok(chain)
    }

    fn measured_bytes(&self) -> Result<[u8; 48], Error> {
        let b = bincode::serialize(&self.report).map_err(Error::ReportSerialize)?;
        let measureable_bytes = &b[0..0x2a0];

        let mut hasher = Sha384::new();
        hasher.update(measureable_bytes);

        Ok(hasher.finish())
    }

    fn report_signed(&self, signature: EcdsaSig, vcek: Certificate) -> Result<(), Error> {
        let measured = self.measured_bytes()?;
        let pkey = vcek.public_key().map_err(|_| Error::VcekPublicKey)?;
        let ec = pkey.ec_key().map_err(|_| Error::VcekEcKey)?;

        signature
            .verify(&measured, &ec)
            .map_err(|_| Error::VcekSign)?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    CaVerify(io::Error),
    EcdsaSigDecode,
    ReportSerialize(bincode::Error),
    VcekDecode,
    VcekEcKey,
    VcekFetch(curl::Error),
    VcekPublicKey,
    VcekSign,
    VcekVerify(io::Error),
}
