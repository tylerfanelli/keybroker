// SPDX-License-Identifier: Apache-2.0

pub mod snp;

use curl::easy::Easy;

pub trait Endorser {
    fn endorse(&self) -> Result<(), Error>;
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

#[derive(Debug)]
pub enum Error {
    Snp(snp::Error),
}
