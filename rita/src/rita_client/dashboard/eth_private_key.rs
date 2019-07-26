use crate::ARGS;
use crate::KI;
use crate::SETTING;
use actix_web::{HttpRequest, HttpResponse, Json};
use althea_types::ExitState;
use clarity::PrivateKey;
use failure::Error;
use settings::client::RitaClientSettings;
use settings::FileWrite;
use settings::RitaCommonSettings;
use std::collections::HashMap;

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
            let error_msg = "No eth key configured yet";
            warn!("{}", error_msg);
            ret.insert("error".to_owned(), error_msg.to_owned());
        }
    }

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_eth_private_key(data: Json<EthPrivateKey>) -> Result<HttpResponse, Error> {
    debug!("/eth_private_key POST hit");

    let pk: PrivateKey = data.into_inner().eth_private_key.parse()?;

    let mut payment_settings = SETTING.get_payment_mut();
    payment_settings.eth_private_key = Some(pk);
    payment_settings.eth_address = Some(pk.to_public_key()?);
    drop(payment_settings);

    // remove the wg_public_key and regenerate wg private key, we don't do that here
    // so it will happen on process restart. We could just call the linux client init
    // from clu but we would need to handle already deployed tunnels and it's just not
    // worth the trouble.
    let mut network_settings = SETTING.get_network_mut();
    network_settings.wg_private_key = None;
    network_settings.wg_public_key = None;
    network_settings.mesh_ip = None;
    drop(network_settings);

    // unset current exit
    let mut exit_client_settings = SETTING.get_exit_client_mut();
    exit_client_settings.current_exit = None;
    drop(exit_client_settings);

    let mut exit_settings = SETTING.get_exits_mut();
    for mut exit in exit_settings.iter_mut() {
        exit.1.info = ExitState::New;
    }
    drop(exit_settings);

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }

    // it's now safe to reboot the router
    if let Err(e) = KI.run_command("reboot", &[]) {
        return Err(e);
    }

    Ok(HttpResponse::Ok().finish())
}
