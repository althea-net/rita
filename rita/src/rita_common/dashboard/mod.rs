use actix::prelude::*;
use actix::registry::SystemService;

use failure::Error;
#[cfg(not(feature = "guac"))]
use futures;

#[cfg(feature = "guac")]
use futures::Future;

#[cfg(feature = "guac")]
use guac_actix::{GetOwnBalance, PaymentController};

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
        #[cfg(feature = "guac")]
        let ret = PaymentController::from_registry()
            .send(GetOwnBalance {})
            .from_err()
            .and_then(|res| {
                Ok(OwnInfo {
                    balance: res?.as_u64() as i64,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                })
            });
        #[cfg(not(feature = "guac"))]
        let ret = futures::future::ok(OwnInfo {
            balance: 0.into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        Box::new(ret)
    }
}
