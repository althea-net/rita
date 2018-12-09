use super::*;

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
