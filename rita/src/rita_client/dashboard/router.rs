use crate::KI;
use actix_web::{HttpRequest, HttpResponse};
use failure::Error;

pub fn reboot_router(_req: HttpRequest) -> Result<HttpResponse, Error> {
    if KI.is_openwrt() {
        KI.run_command("reboot", &[])?;
        Ok(HttpResponse::Ok().json(()))
    } else {
        Ok(HttpResponse::Ok().json("This isn't an OpenWRT device, doing nothing"))
    }
}

pub fn update_router(_req: HttpRequest) -> Result<HttpResponse, Error> {
    if KI.is_openwrt() {
        KI.run_command("ash", &["/etc/update.ash"])?;
        Ok(HttpResponse::Ok().json(()))
    } else {
        Ok(HttpResponse::Ok().json("This isn't an OpenWRT device, doing nothing"))
    }
}
