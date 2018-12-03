use super::*;

#[derive(Serialize)]
pub struct OwnInfo {
    pub address: Address,
    pub balance: u128,
    pub local_fee: u32,
    pub metric_factor: u32,
    pub pay_threshold: i128,
    pub close_threshold: i128,
    pub device: Option<String>,
    pub version: String,
}

pub fn get_own_info(_req: HttpRequest) -> Result<Json<OwnInfo>, Error> {
    debug!("Get own info endpoint hit!");
    let payment_settings = SETTING.get_payment();
    let eth_address = payment_settings.eth_address.clone();
    let balance = payment_settings.balance.clone();
    let pay_threshold = payment_settings.pay_threshold.clone();
    let close_threshold = payment_settings.close_threshold.clone();

    let network_settings = SETTING.get_network();
    let local_fee = SETTING.get_local_fee();
    let metric_factor = SETTING.get_metric_factor();
    let device = network_settings.device.clone();

    let reply = OwnInfo {
        address: eth_address,
        balance: balance.into(),
        local_fee: local_fee.into(),
        metric_factor: metric_factor,
        pay_threshold: pay_threshold.into(),
        close_threshold: close_threshold.into(),
        device: device,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    Ok(Json(reply))
}
