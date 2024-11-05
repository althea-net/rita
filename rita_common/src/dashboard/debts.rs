use crate::debt_keeper::get_debts_list;
use crate::debt_keeper::traffic_replace;
use crate::debt_keeper::Traffic;
use actix_web_async::{web::Json, HttpRequest, HttpResponse};
use althea_types::identity::Identity;

pub async fn get_debts(_req: HttpRequest) -> HttpResponse {
    trace!("get_debts: Hit");
    HttpResponse::Ok().json(get_debts_list())
}

pub async fn reset_debt(user_to_forgive: Json<Identity>) -> HttpResponse {
    traffic_replace(Traffic {
        from: user_to_forgive.into_inner(),
        amount: 0.into(),
    });
    HttpResponse::Ok().json(())
}
