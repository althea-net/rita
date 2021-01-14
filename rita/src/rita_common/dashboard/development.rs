#[cfg(feature = "development")]
use crate::rita_common::rita_loop::fast_loop::Crash;
#[cfg(feature = "development")]
use crate::rita_common::rita_loop::fast_loop::RitaFastLoop as RitaCommonLoop;
#[cfg(feature = "development")]
use crate::KI;
#[cfg(feature = "development")]
use crate::SETTING;
#[cfg(feature = "development")]
use actix::SystemService;
use actix_web::{HttpRequest, HttpResponse, Result};
#[cfg(feature = "development")]
use clu::{cleanup, generate_mesh_ip};
use failure::Error;
#[cfg(feature = "development")]
use settings::RitaCommonSettings;
#[cfg(feature = "development")]
use std::path::Path;

#[cfg(not(feature = "development"))]
pub fn crash_actors(_req: HttpRequest) -> Result<HttpResponse, Error> {
    // This is returned on production builds.
    Ok(HttpResponse::NotFound().finish())
}

#[cfg(feature = "development")]
pub fn crash_actors(_req: HttpRequest) -> Result<HttpResponse, Error> {
    RitaCommonLoop::from_registry().do_send(Crash {});
    Ok(HttpResponse::Ok().json(()))
}

#[cfg(not(feature = "development"))]
pub fn wipe(_req: HttpRequest) -> Result<HttpResponse, Error> {
    // This is returned on production builds.
    Ok(HttpResponse::NotFound().finish())
}

#[cfg(feature = "development")]
pub fn wipe(_req: HttpRequest) -> Result<HttpResponse, Error> {
    let mut network_settings = SETTING.get_network_mut();

    // Clean up existing WG interfaces
    match cleanup() {
        Ok(_) => trace!("wipe: WireGuard interfaces cleanup success!"),
        Err(e) => {
            warn!(
                "wipe: Unable to complete WireGuard interfaces cleanup: {:?}",
                e
            );
            return Err(e);
        }
    }

    // Restore default route
    match KI.restore_default_route(&mut network_settings.last_default_route) {
        Ok(_) => trace!("wipe: Restore default route success!"),
        Err(e) => {
            warn!("wipe: Unable to restore default route: {:?}", e);
            return Err(e.into());
        }
    }

    // Create new WireGuard keys
    let keypair = KI.create_wg_keypair().expect("failed to generate wg keys");
    network_settings.wg_public_key = Some(keypair.public);
    network_settings.wg_private_key = Some(keypair.private);

    // Generate new mesh IP
    match generate_mesh_ip() {
        Ok(ip) => {
            trace!("wipe: Generated new mesh IP");
            network_settings.mesh_ip = Some(ip);
        }
        Err(e) => {
            warn!("wipe: Unable to generate new mesh IP: {:?}", e);
            return Err(e);
        }
    }

    // Creates file on disk containing key
    match KI.create_wg_key(
        &Path::new(&network_settings.wg_private_key_path),
        &network_settings.wg_private_key.unwrap(),
    ) {
        Ok(_) => trace!("wipe: Saved new WireGuard keys to disk"),
        Err(e) => {
            warn!("wipe: Unable to save new WireGuard keys: {:?}", e);
            return Err(e.into());
        }
    }

    Ok(HttpResponse::NoContent().finish())
}
