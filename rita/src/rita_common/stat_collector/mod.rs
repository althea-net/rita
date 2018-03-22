use actix::prelude::*;
use rita_common::rita_loop::Tick;

use rita_common::debt_keeper::Dump;

use failure::Error;

use althea_kernel_interface::KernelInterface;
use reqwest;
use reqwest::StatusCode;

use althea_types::Identity;

use serde_json;

use SETTING;
use reqwest::Client;
use std::time::Duration;

pub struct StatCollector {
    pub client: Client,
}

impl StatCollector {
    pub fn new() -> StatCollector {
        StatCollector {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Statistics {
    proc_stat: String,
    proc_load_avg: String,
    devices: String,
    netstat: String,
    routes: String,
    snmp: String,
    wg: String,
    from: Identity,
}

impl Actor for StatCollector {
    type Context = SyncContext<Self>;
}

impl Handler<Tick> for StatCollector {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, ctx: &mut SyncContext<Self>) -> Self::Result {
        if let Some(stat_server_settings) = SETTING.read().unwrap().stat_server.clone() {
            trace!("preparing to send stats...");

            let ki = KernelInterface {};

            let stats = Statistics {
                proc_stat: ki.get_proc_stat()?,
                proc_load_avg: ki.get_proc_load_avg()?,
                devices: ki.get_device_stats()?,
                netstat: ki.get_netstat()?,
                routes: ki.get_route_stats()?,
                snmp: ki.get_snmp_stats()?,
                wg: ki.get_wg_stats()?,
                from: SETTING.read().unwrap().get_identity(),
            };

            info!("Sending stat server update: {:?}", stats);
            let stat_server_url = format!(
                "http://{}:{}/stats/data/",
                stat_server_settings.stat_address, stat_server_settings.stat_port,
            );

            trace!("stat server url: {}", stat_server_url);

            let mut r = self.client.post(&stat_server_url).json(&stats).send()?;

            if r.status().is_success() {
                trace!("Successfully in sending stats {:?}", r.text());
            } else {
                trace!("Unsuccessfully in sending stats");
                trace!(
                    "Received error from stats server: {:?}",
                    r.text().unwrap_or(String::from("No message received"))
                );
            }
        };

        Ok(())
    }
}
