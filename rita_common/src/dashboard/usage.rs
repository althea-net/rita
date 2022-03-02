use crate::usage_tracker::get_payments_data;
use ::actix_web_async::HttpRequest;
use actix_web_async::HttpResponse;

pub async fn get_payments(_req: HttpRequest) -> HttpResponse {
    trace!("/usage/relay hit");

    HttpResponse::Ok().json(get_payments_data())
}
