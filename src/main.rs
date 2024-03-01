// SPDX-License-Identifier: Apache-2.0

mod kbs;
mod rats;

use std::io;

use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(web::scope("/rvp").service(rats::rvp::register))
            .service(
                web::scope("/kbs/v0")
                    .service(kbs::auth)
                    .service(kbs::attest),
            )
    })
    .bind(("0.0.0.0", 8000))?
    .run()
    .await
}
