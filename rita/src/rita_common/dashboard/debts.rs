use crate::rita_common::debt_keeper::GetDebtsList;
use crate::rita_common::debt_keeper::{DebtKeeper, GetDebtsResult};
use ::actix::registry::SystemService;
use ::actix_web::{AsyncResponder, HttpRequest, Json};
use failure::Error;
use futures::Future;
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
