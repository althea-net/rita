use crate::usage_tracker::handle_get_payments_data;
use crate::usage_tracker::GetPayments;
use crate::usage_tracker::PaymentHour;
use ::actix_web::{HttpRequest, Json};
use std::collections::VecDeque;

pub fn get_payments(_req: HttpRequest) -> Json<VecDeque<PaymentHour>> {
    trace!("/usage/relay hit");

    Json(handle_get_payments_data(GetPayments {}))
}