use actix::prelude::*;

use failure::Error;
use futures::Future;

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
pub struct OwnInfo {
    pub balance: i64,
    pub version: String,
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
                .and_then(|own_balance| match own_balance {
                    Ok(balance) => Ok(OwnInfo {
                        balance: balance,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    }),
                    Err(e) => Err(e),
                }),
        )
    }
}
