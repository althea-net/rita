use crate::token_bridge::get_bridge_status as get_status;
use actix_web::{HttpRequest, HttpResponse};

pub async fn get_bridge_status(_req: HttpRequest) -> HttpResponse {
    trace!("/token_bridge/status hit");
    HttpResponse::Ok().json(get_status())
}
