//! This file contains all the network endpoints used for the extender dashbaord.

use actix::System;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use std::thread;

pub fn start_extender_dashboard(rita_dashboard_port: u16) {
    // dashboard
    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            let _res = HttpServer::new(|| App::new().route("/status", web::get().to(status_check)))
                .workers(1)
                .bind(format!("[::0]:{rita_dashboard_port}"))
                .unwrap()
                .shutdown_timeout(0)
                .run()
                .await;
        });
    });
}

async fn status_check(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(())
}
