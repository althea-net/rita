use actix::prelude::*;

use failure::Error;
use futures;
use futures::Future;
use serde_json;

use rita_common::debt_keeper::{DebtKeeper, Dump};
use rita_common::payment_controller::{GetOwnBalance, PaymentController};

pub mod network_endpoints;

pub struct Dashboard;

impl Actor for Dashboard {
    type Context = Context<Self>;
}

impl Supervised for Dashboard {}
impl SystemService for Dashboard {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Dashboard started");
    }
}

impl Default for Dashboard {
    fn default() -> Dashboard {
        Dashboard {}
    }
}

#[derive(Serialize)]
pub struct NodeInfo {
    pub nickname: String,
    pub route_metric_to_exit: u64,
    pub total_payments: i64,
    pub debt: i64,
}

pub struct GetNodeInfo;

impl Message for GetNodeInfo {
    type Result = Result<Vec<NodeInfo>, Error>;
}

impl Handler<GetNodeInfo> for Dashboard {
    type Result = ResponseFuture<Vec<NodeInfo>, Error>;

    fn handle(&mut self, _msg: GetNodeInfo, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            DebtKeeper::from_registry()
                .send(Dump {})
                .and_then(|res| {
                    let res = res.unwrap();

                    let mut output = Vec::new();

                    for (k, v) in res.iter() {
                        output.push(NodeInfo {
                            nickname: serde_json::to_string(&k.mesh_ip).unwrap(),
                            route_metric_to_exit: 0,
                            total_payments: v.total_payment_recieved.clone().into(),
                            debt: v.debt.clone().into(),
                        })
                    }

                    futures::future::ok(output)
                })
                .from_err(),
        )
    }
}

#[derive(Serialize)]
pub struct OwnInfo {
    pub balance: i64,
}

pub struct GetOwnInfo;

impl Message for GetOwnInfo {
    type Result = Result<OwnInfo, Error>;
}

impl Handler<GetOwnInfo> for Dashboard {
    type Result = ResponseFuture<OwnInfo, Error>;

    fn handle(&mut self, _msg: GetOwnInfo, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            PaymentController::from_registry()
                .send(GetOwnBalance {})
                .from_err()
                .and_then(|res| Ok(OwnInfo { balance: res? })),
        )
    }
}
