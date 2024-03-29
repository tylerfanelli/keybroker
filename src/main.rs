// SPDX-License-Identifier: Apache-2.0

mod kbs;
mod rats;

use std::io;

use actix_web::{web, App, HttpServer};
use structopt::StructOpt;

/// Command line arguments.
#[derive(StructOpt)]
struct Args {
    /// IP address to run the server.
    #[structopt(long)]
    ip: String,

    /// Port to run the server.
    #[structopt(short, long)]
    port: u16,
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let args = Args::from_args();

    HttpServer::new(|| {
        App::new()
            .service(web::scope("/rvp").service(rats::rvp::register))
            .service(
                web::scope("/kbs/v0")
                    .service(kbs::auth)
                    .service(kbs::attest)
                    .service(kbs::resource),
            )
    })
    .bind((args.ip, args.port))?
    .run()
    .await
}
