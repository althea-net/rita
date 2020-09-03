use crate::rita_common::debt_keeper::get_debts_list;
use crate::rita_common::debt_keeper::traffic_replace;
use crate::rita_common::debt_keeper::GetDebtsResult;
use crate::rita_common::debt_keeper::Traffic;
use ::actix_web::{HttpRequest, HttpResponse, Json};
use althea_types::Identity;
use failure::Error;

pub fn get_debts(_req: HttpRequest) -> Result<Json<Vec<GetDebtsResult>>, Error> {
    trace!("get_debts: Hit");
    Ok(Json(get_debts_list()))
}

pub fn reset_debt(user_to_forgive: Json<Identity>) -> HttpResponse {
    traffic_replace(Traffic {
        from: user_to_forgive.into_inner(),
        amount: 0.into(),
    });
    HttpResponse::Ok().json(())
}
