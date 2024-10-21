use crate::usage_tracker::get_payments_data;
use ::actix_web::HttpRequest;
use actix_web::HttpResponse;

pub async fn get_payments(_req: HttpRequest) -> HttpResponse {
    trace!("/usage/relay hit");

    HttpResponse::Ok().json(get_payments_data())
}
