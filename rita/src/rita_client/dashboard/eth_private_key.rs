use super::*;
use clarity::PrivateKey;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct EthPrivateKey {
    pub eth_private_key: String,
}

pub fn get_eth_private_key(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/eth_private_key GET hit");

    let mut ret = HashMap::new();

    match SETTING.get_payment().eth_private_key {
        Some(pk) => {
            ret.insert("eth_private_key".to_owned(), format!("{:x}", pk));
        }
        None => {
            let error_msg = "No mesh IP configured yet";
            warn!("{}", error_msg);
            ret.insert("error".to_owned(), error_msg.to_owned());
        }
    }

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_eth_private_key(data: Json<EthPrivateKey>) -> Result<HttpResponse, Error> {
    debug!("/eth_private_key POST hit");

    let pk: PrivateKey = data.into_inner().eth_private_key.parse()?;
    SETTING.get_payment_mut().eth_private_key = Some(pk);
    SETTING.get_payment_mut().eth_address = Some(pk.to_public_key()?);

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }

    // it's now safe to restart the process, return an error if that fails somehow
    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Err(e);
    }

    Ok(HttpResponse::Ok().finish())
}
