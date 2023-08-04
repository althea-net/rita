//! This module is responsible for checking in with the operator server and getting updated local settings
pub mod update_loop;

use althea_types::ExitClientIdentity;
use althea_types::OperatorExitCheckinMessage;
use althea_types::OperatorExitUpdateMessage;
use althea_types::WgKey;
use diesel::QueryDsl;
use diesel::RunQueryDsl;
use exit_db::schema::clients::dsl::clients as db_client;
use exit_db::schema::clients::wg_pubkey;
use rita_common::KI;
use std::time::{Duration, Instant};

use crate::database::signup_client;
use crate::get_database_connection;
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
        url = "http://0.0.0.0:8080/exitcheckin";
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
        let response = client
            .post(url)
            .timeout(OPERATOR_UPDATE_TIMEOUT)
            .send_json(&OperatorExitCheckinMessage {
                id,
                pass,
                exit_uptime: rita_started.elapsed(),
                registered_keys: get_registered_list(),
                // Since this checkin works only from b20, we only need to look on wg_exit_v2
                users_online: KI.get_wg_exit_clients_online(EXIT_INTERFACE).ok(),
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

pub fn get_registered_list() -> Option<Vec<WgKey>> {
    match get_database_connection() {
        Ok(conn) => {
            let registered_routers = db_client.select(wg_pubkey);
            let registered_routers = match registered_routers.load::<String>(&conn) {
                Ok(a) => a,
                Err(e) => {
                    error!("Unable to retrive wg keys {}", e);
                    return None;
                }
            };
            Some(
                registered_routers
                    .iter()
                    .filter_map(|r| match r.parse() {
                        Ok(a) => Some(a),
                        Err(_) => {
                            error!("Invalid wg key in database! {}", r);
                            None
                        }
                    })
                    .collect::<Vec<WgKey>>(),
            )
        }
        Err(e) => {
            error!(
                "Unable to get a database connection to retrieve registered exits: {}",
                e
            );
            None
        }
    }
}
