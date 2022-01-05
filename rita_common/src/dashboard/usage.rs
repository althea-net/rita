use crate::usage_tracker::{get_payments_data, PaymentHour};
use ::actix_web::{HttpRequest, Json};
use std::collections::VecDeque;

pub fn get_payments(_req: HttpRequest) -> Json<VecDeque<PaymentHour>> {
    trace!("/usage/relay hit");

    Json(get_payments_data())
}
