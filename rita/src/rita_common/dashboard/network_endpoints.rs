use actix::registry::SystemService;
use clu::cleanup;
use clu::linux_generate_mesh_ip;
use clu::linux_generate_wg_keys;
use std::path::Path;
use KI;

use futures::Future;

use std::boxed::Box;

use failure::Error;

use serde_json;

use settings::RitaCommonSettings;
use SETTING;

use super::{Dashboard, GetOwnInfo, OwnInfo};
use actix_web::*;

use rita_common::network_endpoints::JsonStatusResponse;

pub fn get_own_info(_req: HttpRequest) -> Box<Future<Item = Json<OwnInfo>, Error = Error>> {
    debug!("Get own info endpoint hit!");
    Dashboard::from_registry()
        .send(GetOwnInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_settings(_req: HttpRequest) -> Result<Json<serde_json::Value>, Error> {
    debug!("Get settings endpoint hit!");
    Ok(Json(SETTING.get_all()?))
}

pub fn set_settings(
    new_settings: Json<serde_json::Value>,
) -> Result<Json<JsonStatusResponse>, Error> {
    debug!("Set settings endpoint hit!");
    SETTING.merge(new_settings.into_inner())?;

    JsonStatusResponse::new(Ok("New settings applied".to_string()))
}

#[cfg(not(debug_assertions))]
pub fn wipe(_req: HttpRequest) -> Result<HttpResponse, Error> {
    // This is returned on production builds.
    Ok(HttpResponse::NotFound().finish());
}

#[cfg(debug_assertions)]
pub fn wipe(_req: HttpRequest) -> Result<HttpResponse, Error> {
    // Clean up existing WG interfaces
    match cleanup() {
        Ok(_) => trace!("wipe: Cleanup success!"),
        Err(e) => {
            warn!("wipe: Unable to complete cleanup: {:?}", e);
            return Err(e);
        }
    }

    // Restore default route
    match KI.restore_default_route(&mut SETTING.get_network_mut().default_route) {
        Ok(_) => trace!("wipe: Restore default route success!"),
        Err(e) => {
            warn!("wipe: Unable to restore default route: {:?}", e);
            return Err(e);
        }
    }

    // Create new WireGuard keys
    match linux_generate_wg_keys(&mut SETTING.get_network_mut()) {
        Ok(_) => trace!("wipe: Generated new WireGuard keys"),
        Err(e) => {
            warn!("wipe: Unable to generate new WireGuard keys: {:?}", e);
            return Err(e);
        }
    }
    // Generate new mesh IP
    match linux_generate_mesh_ip(&mut SETTING.get_network_mut()) {
        Ok(_) => trace!("wipe: Generated new mesh IP"),
        Err(e) => {
            warn!("wipe: Unable to generate new mesh IP: {:?}", e);
            return Err(e);
        }
    }

    // Creates file on disk containing key
    match KI.create_wg_key(
        &Path::new(&SETTING.get_network().wg_private_key_path),
        &SETTING.get_network().wg_private_key,
    ) {
        Ok(_) => trace!("wipe: Generated new WireGuard keys"),
        Err(e) => {
            warn!("wipe: Unable to generate new WireGuard keys: {:?}", e);
            return Err(e);
        }
    }

    Ok(HttpResponse::NoContent().finish())
}
