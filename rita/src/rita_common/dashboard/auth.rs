use crate::ARGS;
use crate::SETTING;
use ::actix_web::{HttpResponse, Json};
use ::settings::FileWrite;
use failure::Error;
use settings::RitaCommonSettings;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct RouterPassword {
    pub password: String,
}

pub fn set_pass(router_pass: Json<RouterPassword>) -> Result<HttpResponse, Error> {
    debug!("/router/password hit with {:?}", router_pass);
    let router_pass = router_pass.into_inner();
    // scoped to drop the write reference before we write to the disk
    SETTING.get_network_mut().rita_dashboard_password = Some(router_pass.password);
    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(HttpResponse::Ok().json(()))
}
