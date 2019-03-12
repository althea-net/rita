use ::actix_web::*;
use failure::Error;

#[cfg(not(feature = "development"))]
pub fn wipe(_req: HttpRequest) -> Result<HttpResponse, Error> {
    // This is returned on production builds.
    Ok(HttpResponse::NotFound().finish())
}

#[cfg(feature = "development")]
pub fn wipe(_req: HttpRequest) -> Result<HttpResponse, Error> {
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
        Ok(_) => trace!("wipe: Saved new WireGuard keys to disk"),
        Err(e) => {
            warn!("wipe: Unable to save new WireGuard keys: {:?}", e);
            return Err(e);
        }
    }

    Ok(HttpResponse::NoContent().finish())
}
