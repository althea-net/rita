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
    exit_id: Option<LocalIdentity>,
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
            exit_id: None,
        }
    }
}

impl Handler<Tick> for ExitManager {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        if let Some(ref id) = self.exit_id {
            let exit_debt_url = format!(
                "[{}]:{}/get_debt",
                id.global.mesh_ip,
                SETTING.read().unwrap().network.rita_port
            );
            trace!("sending payment query to {}", exit_debt_url);

            let mut r = self.client
                .get(&exit_debt_url)
                .body(serde_json::to_string(&SETTING
                    .read()
                    .unwrap()
                    .get_identity())?)
                .send()?;

            if r.status() == StatusCode::Ok {
                let owes: Uint256 = r.json()?;

                trace!("we owe {:?}", owes);

                let pmt = PaymentTx {
                    from: SETTING.read().unwrap().get_identity(),
                    to: id.global.clone(),
                    amount: owes,
                };

                PaymentController::from_registry().do_send(MakePayment(pmt));
                ctx.notify_later(Tick, Duration::from_secs(5));
                Ok(())
            } else {
                ctx.notify_later(Tick, Duration::from_secs(5));
                Err(ExitManagerError::ExitRequestError(String::from(format!(
                    "Received error from exit: {:?}",
                    r.text().unwrap_or(String::from("No message received"))
                ))).into())
            }
        } else {
            if let Some(ref exit_details) = SETTING.read().unwrap().exit_client.details {
                self.exit_id = Some(LocalIdentity {
                    local_ip: SETTING.read().unwrap().exit_client.exit_ip,
                    wg_port: exit_details.wg_exit_port,
                    global: SETTING.read().unwrap().get_exit_id().unwrap(),
                })
            }
            ctx.notify_later(Tick, Duration::from_secs(5));
            Ok(())
        }
    }
}
