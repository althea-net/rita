//! This module is responsible for checking in with the operator server and getting updated local settings
pub mod update_loop;

use althea_types::ExitClientIdentity;
use althea_types::OperatorExitCheckinMessage;
use althea_types::OperatorExitUpdateMessage;
use rita_common::KI;
use std::time::{Duration, Instant};

use crate::database::signup_client;

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

lazy_static! {
    /// stores the startup time for Rita, used to compute uptime
    static ref RITA_UPTIME: Instant = Instant::now();
}

/// Perform operator updates every UPDATE_FREQUENCY seconds,
const UPDATE_FREQUENCY: Duration = Duration::from_secs(60);

/// How long we wait for a response from the server
pub const OPERATOR_UPDATE_TIMEOUT: Duration = Duration::from_secs(4);

/// Checks in with the operator server
pub async fn operator_update() {
    let url: &str;
    if cfg!(feature = "dev_env") {
        url = "http://0.0.0.0:8080/exitcheckin";
    } else if cfg!(feature = "operator_debug") {
        url = "http://192.168.10.2:8080/exitcheckin";
    } else {
        url = "https://operator.althea.net:8080/exitcheckin";
    }

    let rita_exit = settings::get_rita_exit();
    let id = rita_exit.get_identity().unwrap();

    info!("About to perform operator update with {}", url);

    let client = awc::Client::default();
    let response = client
        .post(url)
        .timeout(OPERATOR_UPDATE_TIMEOUT)
        .send_json(&OperatorExitCheckinMessage {
            id,
            pass: rita_exit.exit_network.pass,
            exit_uptime: RITA_UPTIME.elapsed(),
            // Since this checkin works only from b20, we only need to look on wg_exit_v2
            users_online: KI.get_wg_exit_clients_online("wg_exit_v2").ok(),
        })
        .await;

    let response = match response {
        Ok(mut response) => {
            trace!("Response is {:?}", response.status());
            trace!("Response is {:?}", response.headers());
            response.json().await
        }
        Err(e) => {
            error!("Failed to perform exit operator checkin with {:?}", e);
            return;
        }
    };

    let new_settings: OperatorExitUpdateMessage = match response {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to perform exit operator checkin with {:?}", e);
            return;
        }
    };

    // Perform operator updates
    register_op_clients(new_settings.to_register).await;
}

async fn register_op_clients(clients: Vec<ExitClientIdentity>) {
    info!("Signing up ops clients {:?}", clients);
    for c in clients {
        // Though this is asnyc, it wont block since the only async part (sms handling)
        // is skiped in this function
        let c_key = c.global.wg_public_key;
        if let Err(e) = signup_client(c, true).await {
            error!("Unable to signup client {} with {:?}", c_key, e);
        };
    }
}
