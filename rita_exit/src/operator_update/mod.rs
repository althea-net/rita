//! This module is responsible for checking in with the operator server and getting updated local settings
pub mod update_loop;
use althea_types::OperatorExitCheckinMessage;
use rita_common::KI;
use std::time::{Duration, Instant};

use crate::rita_loop::EXIT_INTERFACE;

pub struct UptimeStruct {
    pub prev_time: Duration,
}
impl Default for UptimeStruct {
    fn default() -> Self {
        UptimeStruct {
            prev_time: Duration::new(0, 0),
        }
    }
}

/// Perform operator updates every UPDATE_FREQUENCY seconds,
const UPDATE_FREQUENCY: Duration = Duration::from_secs(60);

/// How long we wait for a response from the server
pub const OPERATOR_UPDATE_TIMEOUT: Duration = Duration::from_secs(4);

/// Checks in with the operator server
pub async fn operator_update(rita_started: Instant) {
    let url: &str;
    if cfg!(feature = "dev_env") {
        url = "http://7.7.7.7:8080/exitcheckin";
    } else if cfg!(feature = "operator_debug") {
        url = "http://192.168.10.2:8080/exitcheckin";
    } else {
        url = "https://operator.althea.net:8080/exitcheckin";
    }

    let rita_exit = settings::get_rita_exit();
    let id = rita_exit.get_identity().unwrap();

    if let Some(pass) = rita_exit.exit_network.pass {
        info!("About to perform operator update with {}", url);

        let client = awc::Client::default();
        let _response = client
            .post(url)
            .timeout(OPERATOR_UPDATE_TIMEOUT)
            .send_json(&OperatorExitCheckinMessage {
                id,
                pass,
                exit_uptime: rita_started.elapsed(),
                // Since this checkin works only from b20, we only need to look on wg_exit_v2
                users_online: KI.get_wg_exit_clients_online(EXIT_INTERFACE).ok(),
            })
            .await;
    }
}
