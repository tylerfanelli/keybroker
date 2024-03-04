// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use curl::easy::Easy;

#[allow(dead_code)]
pub trait Endorser {
    fn endorse(&self) -> Result<()>;
}

#[allow(dead_code)]
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
