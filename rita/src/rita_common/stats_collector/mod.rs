use actix::prelude::*;
use rita_common::rita_loop::Tick;

use althea_types::interop::Stats;

use failure::Error;

use reqwest;

use KI;

use settings::RitaCommonSettings;
use SETTING;

use reqwest::Client;
use std::time::Duration;

pub struct StatsCollector {
    pub client: Client,
}

impl StatsCollector {
    pub fn new() -> StatsCollector {
        StatsCollector {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }
}

impl Actor for StatsCollector {
    type Context = SyncContext<Self>;
}

impl Handler<Tick> for StatsCollector {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let stats_server = SETTING.get_stats_server_settings();

        if stats_server.is_some() && stats_server.unwrap().stats_enabled {
            trace!("preparing to send stats...");

            let stats_server = SETTING.get_stats_server_settings().unwrap();

            trace!("building stats struct...");
            let stats = Stats {
                proc_stat: KI.get_proc_stat()?,
                proc_load_avg: KI.get_proc_load_avg()?,
                devices: KI.get_device_stats()?,
                routes: KI.get_route_stats()?,
                meminfo: KI.get_meminfo_stats()?,
                cpuinfo: KI.get_cpuinfo_stats()?,
            };

            info!("Sending stat server update: {:?}", stats);
            let stat_server_url = format!(
                "http://{}:{}/stats/",
                stats_server.stats_address, stats_server.stats_port,
            );

            trace!("stat server url: {}", stat_server_url);

            let mut r = self.client.post(&stat_server_url).json(&stats).send()?;

            if r.status().is_success() {
                trace!("Successful at sending stats {:?}", r.text());
            } else {
                error!("Unsuccessful at sending stats");
                info!(
                    "Received error from stats server: {:?}",
                    r.text().unwrap_or(String::from("No message received"))
                );
            }
        };

        Ok(())
    }
}
