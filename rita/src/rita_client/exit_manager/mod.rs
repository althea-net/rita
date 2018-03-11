use actix::prelude::*;

use std::net::IpAddr;
use std::collections::{HashMap, VecDeque};
use std::thread;
use std::time::Duration;
use std::sync::mpsc::{channel, Receiver, Sender};

use althea_types::{EthAddress, Identity, LocalIdentity, PaymentTx};

use num256::{Int256, Uint256};

use eui48::MacAddress;

use SETTING;

use rita_client::rita_loop::Tick;
use rita_client::traffic_watcher::{TrafficWatcher, Watch};
use rita_common::payment_controller::{MakePayment, PaymentController};

use serde_json;

use failure::Error;

use reqwest;
use reqwest::{Client, StatusCode};

#[derive(Debug, Fail)]
pub enum ExitManagerError {
    #[fail(display = "Exit request Error: {:?}", _0)]
    ExitRequestError(String),
}

/// An actor which pays the exit
pub struct ExitManager {
    client: Client,
}

impl Actor for ExitManager {
    type Context = Context<Self>;
}

impl Supervised for ExitManager {}
impl SystemService for ExitManager {
    fn service_started(&mut self, ctx: &mut Context<Self>) {
        info!("Exit Manager started");
    }
}

impl Default for ExitManager {
    fn default() -> ExitManager {
        ExitManager {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }
}

impl Handler<Tick> for ExitManager {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        if let Some(ref exit_details) = SETTING.read().unwrap().exit_client.details {
            TrafficWatcher::from_registry().do_send(Watch(
                Identity {
                    mesh_ip: SETTING.read().unwrap().exit_client.exit_ip,
                    wg_public_key: exit_details.wg_public_key.clone(),
                    eth_address: exit_details.eth_address,
                },
                exit_details.exit_price,
            ))
        };

        Ok(())
    }
}
