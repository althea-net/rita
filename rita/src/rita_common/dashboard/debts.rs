use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::GetDebtsList;
use crate::rita_common::debt_keeper::GetDebtsResult;
use crate::rita_common::debt_keeper::Traffic;
use crate::rita_common::debt_keeper::TrafficReplace;
use ::actix::SystemService;
use ::actix_web::{AsyncResponder, HttpRequest, HttpResponse, Json};
use althea_types::Identity;
use failure::Error;
use futures01::Future;
use std::boxed::Box;

pub fn get_debts(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<Vec<GetDebtsResult>>, Error = Error>> {
    trace!("get_debts: Hit");
    DebtKeeper::from_registry()
        .send(GetDebtsList {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn reset_debt(user_to_forgive: Json<Identity>) -> HttpResponse {
    let forgiven_traffic = TrafficReplace {
        traffic: Traffic {
            from: user_to_forgive.into_inner(),
            amount: 0.into(),
        },
    };
    DebtKeeper::from_registry().do_send(forgiven_traffic);
    HttpResponse::Ok().json(())
}
