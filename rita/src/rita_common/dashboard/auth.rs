use crate::ARGS;
use crate::KI;
use crate::SETTING;
use ::actix_web::{HttpResponse, Json};
use ::settings::FileWrite;
use failure::Error;
use settings::RitaCommonSettings;
use sha3::{Digest, Sha3_256};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct RouterPassword {
    pub password: String,
}

pub fn set_pass(router_pass: Json<RouterPassword>) -> Result<HttpResponse, Error> {
    debug!("/router/password hit with {:?}", router_pass);
    let router_pass = router_pass.into_inner();
    // scoped to drop the write reference before we write to the disk
    let mut hasher = Sha3_256::new();
    hasher.input(router_pass.password.clone() + "RitaSalt");
    let hashed_pass = String::from_utf8(hasher.result().to_vec())?;
    SETTING.get_network_mut().rita_dashboard_password = Some(hashed_pass);
    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }

    if KI.is_openwrt() {
        KI.set_system_password(router_pass.password)?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
    }

    Ok(HttpResponse::Ok().json(()))
}
