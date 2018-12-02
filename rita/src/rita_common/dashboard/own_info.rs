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
    pub balance: String,
    pub local_fee: u32,
    pub metric_factor: u32,
    pub device: Option<String>,
    pub version: String,
}

pub fn get_own_info(_req: HttpRequest) -> Result<Json<OwnInfo>, Error> {
    debug!("Get own info endpoint hit!");
    let balance = SETTING.get_payment().balance.clone();

    let reply = OwnInfo {
        address: SETTING.get_payment().eth_address,
        balance: format!("{:#x}", balance),
        local_fee: SETTING.get_local_fee(),
        metric_factor: SETTING.get_metric_factor(),
        device: SETTING.get_network().device.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    Ok(Json(reply))
}
