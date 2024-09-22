use althea_kernel_interface::{setup_wg_if::get_last_handshake_time, time::set_local_time};
use althea_types::{ExitIdentity, ExitSystemTime};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The max time difference between the local router's time and the exit's before resetting the local time to the exit's
const MAX_DIFF_LOCAL_EXIT_TIME: Duration = Duration::from_secs(60);

/// The max age of the exit tunnel before resetting the local time to the exit's
/// The handshake normally renews every 2 mins, so waiting 3 mins is a reasonable amount
const MAX_EXIT_TUNNEL_HANDSHAKE: Duration = Duration::from_secs(60 * 3);

/// Retrieve a unix timestamp from the exit's mesh IPv6
pub async fn get_exit_time(exit: ExitIdentity) -> Option<SystemTime> {
    info!("Getting the exit time");
    let exit_port = exit.registration_port;
    let exit_ip = exit.mesh_ip;
    let url = format!("http://[{exit_ip}]:{exit_port}/time");

    let client = awc::Client::default();
    let response = match client.get(&url).send().await {
        Ok(mut response) => {
            trace!("Response is {:?}", response.status());
            trace!("Response is {:?}", response.headers());
            response.json().await
        }
        Err(e) => {
            error!("Failed to get exit time stamp {:?}", e);
            return None;
        }
    };

    let exit_time: ExitSystemTime = match response {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to get exit time stamp {:?}", e);
            return None;
        }
    };

    Some(exit_time.system_time)
}

// try to get the latest handshake for the wg_exit tunnel
pub fn get_latest_exit_handshake() -> Option<SystemTime> {
    match get_last_handshake_time("wg_exit") {
        Ok(results) => results.first().map(|(_, time)| {
            info!("last exit handshake {:?}", time);
            *time
        }),
        Err(_) => None,
    }
}

/// Check for a handshake time for wg_exit. We might not get one if there's no tunnel
/// if there's no handshake or the handshake is more than 10 mins old, then try to get the exit time
/// if we do get the exit time and it's more than 60 secs different than local time, then set the local time to it
pub async fn maybe_set_local_to_exit_time(exit: ExitIdentity) {
    let now = SystemTime::now();

    if let Some(last_handshake) = get_latest_exit_handshake() {
        if last_handshake == UNIX_EPOCH {
            // if there's a tunnel but no handshake (0, or UNIX_EPOCH) then we should still be able to get time from it
            info!("There's an exit tunnel with no handshake time");
        } else {
            match now.duration_since(last_handshake) {
                Ok(diff) => {
                    if diff < MAX_EXIT_TUNNEL_HANDSHAKE {
                        // we got an existing exit handshake of a reasonable age
                        return;
                    } else {
                        info!(
                            "It's been {:?} secs since the last exit handshake",
                            diff.as_secs()
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "The last exit handshake time \"was\" {} secs in the future",
                        e.duration().as_secs()
                    );
                }
            }
        }
    }

    // if we're here, then it means we didn't get a reasonable handshake
    if let Some(exit_time) = get_exit_time(exit).await {
        // if exit time is more than 60 secs later than our time, set ours to its
        if let Ok(diff) = exit_time.duration_since(now) {
            if diff > MAX_DIFF_LOCAL_EXIT_TIME {
                // if we're here, then it's time to set our time
                if set_local_time(exit_time).is_ok() {
                    info!("Local time was reset to the exit's time: {:?}", exit_time);
                }
            }
        }
    }
}
