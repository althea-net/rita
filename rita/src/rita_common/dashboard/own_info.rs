use super::*;

#[derive(Debug, Fail)]
enum OwnInfoError {
    #[fail(display = "Unable to round balance of {} down to 1 ETH", _0)]
    RoundDownError(Uint256),
    #[fail(display = "Unable to downcast value {} to signed 64 bits", _0)]
    DownCastError(Uint256),
}

#[derive(Serialize)]
pub struct OwnInfo {
    pub address: Address,
    pub balance: i64,
    pub local_fee: u32,
    pub metric_factor: u32,
    pub device: Option<String>,
    pub version: String,
}

pub struct GetOwnInfo;

impl Message for GetOwnInfo {
    type Result = Result<OwnInfo, Error>;
}

impl Handler<GetOwnInfo> for Dashboard {
    type Result = ResponseFuture<OwnInfo, Error>;

    fn handle(&mut self, _msg: GetOwnInfo, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            PaymentController::from_registry()
                .send(GetOwnBalance {})
                .from_err()
                .and_then(|own_balance| match own_balance {
                    Ok(balance) => {
                        let balance = balance
                            .checked_div(&Uint256::from(1_000_000_000u64))
                            .ok_or(OwnInfoError::RoundDownError(balance.clone()))?;

                        Ok(OwnInfo {
                            address: SETTING.get_payment().eth_address,
                            balance: balance
                                .to_i64()
                                .ok_or(OwnInfoError::DownCastError(balance))?,
                            local_fee: SETTING.get_local_fee(),
                            metric_factor: SETTING.get_metric_factor(),
                            device: SETTING.get_network().device.clone(),
                            version: env!("CARGO_PKG_VERSION").to_string(),
                        })
                    }
                    Err(e) => Err(e),
                }),
        )
    }
}

pub fn get_own_info(_req: HttpRequest) -> Box<Future<Item = Json<OwnInfo>, Error = Error>> {
    debug!("Get own info endpoint hit!");
    Dashboard::from_registry()
        .send(GetOwnInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
