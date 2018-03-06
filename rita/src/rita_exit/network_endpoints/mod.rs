use althea_types::{ExitIdentity, Identity, LocalIdentity, PaymentTx};
use num256::Uint256;

use actix;
use actix::registry::SystemService;
use actix_web::*;
use actix_web::dev::*;

use futures::Future;

use rita_common::payment_controller;
use rita_common::payment_controller::PaymentController;

use rita_common::debt_keeper;
use rita_common::debt_keeper::{DebtKeeper, GetDebt};

use rita_exit::db_client::{DbClient, SetupClient};

use althea_kernel_interface::KernelInterface;

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::io::Read;
use std::boxed::Box;
use std::net::SocketAddr;

use serde_json;

use bytes::Bytes;

use SETTING;

use failure::Error;

pub fn get_debt(req: HttpRequest) -> Box<Future<Item = Json<Uint256>, Error = Error>> {
    trace!("Getting debt for {:?}", req.connection_info().remote());

    let conn_info: SocketAddr = req.connection_info().remote().unwrap().parse().unwrap();

    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            trace!("Debt request body: {:?} from {:?}", bytes, conn_info);
            let their_id: Identity = serde_json::from_slice(&bytes[..]).unwrap();

            trace!("Received requester identity, {:?}", their_id);
            DebtKeeper::from_registry()
                .send(GetDebt {
                    from: their_id.clone(),
                })
                .from_err()
                .and_then(move |reply| {
                    trace!("got debt {:?} for {:?}", reply, their_id);

                    Ok(Json(reply.unwrap()))
                })
        })
        .responder()
}

pub fn setup_request(req: HttpRequest) -> Box<Future<Item = Json<LocalIdentity>, Error = Error>> {
    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            trace!("setup request body: {:?}", bytes);
            let their_id: ExitIdentity = serde_json::from_slice(&bytes[..]).unwrap();

            trace!("Received requester identity, {:?}", their_id);
            DbClient::from_registry()
                .send(SetupClient(their_id))
                .from_err()
                .and_then(move |reply| {
                    Ok(Json(LocalIdentity {
                        global: SETTING.read().unwrap().get_identity(),
                        local_ip: reply.unwrap(),
                        wg_port: SETTING.read().unwrap().exit_network.wg_tunnel_port,
                    }))
                })
        })
        .responder()
}
