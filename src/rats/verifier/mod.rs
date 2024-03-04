// SPDX-License-Identifier: Apache-2.0

mod endorser;

use anyhow::Result;

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
#[allow(dead_code)]
pub trait Verifier {
    /// Verify that attestation evidence is both endorsed by the hardware manufacturer, as
    /// well as ruled "fresh" by checking its nonce hash and public key.
    fn verify(&self) -> Result<serde_json::Value> {
        self.endorse()?;
        self.freshness()?;

        Ok(self.claims())
    }

    /// Ensure that the attestation evidence is endorsed by the hardware manufacturer.
    fn endorse(&self) -> Result<()>;

    /// Ensure that the attestation evidence is "fresh" by checking its nonce hash and public key.
    fn freshness(&self) -> Result<()>;

    /// Return a JSON-encoded string of all of the parsed claims of the respective TEE's
    /// attestation report.
    fn claims(&self) -> serde_json::Value;
}
