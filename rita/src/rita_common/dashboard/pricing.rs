use super::*;

pub fn auto_pricing_status(_req: HttpRequest) -> Result<Json<bool>, Error> {
    debug!("Get Auto pricing enabled hit!");
    Ok(Json(SETTING.get_payment().price_oracle_enabled))
}

pub fn set_auto_pricing(path: Path<bool>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let value = path.into_inner();
    debug!("Set Auto pricing enabled hit!");
    SETTING.get_payment_mut().price_oracle_enabled = value;
    Box::new(future::ok(HttpResponse::Ok().json(())))
}
