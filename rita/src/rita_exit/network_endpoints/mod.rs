use althea_types::{ExitIdentity, LocalIdentity};

use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use rita_exit::db_client::{DbClient, SetupClient};

use std::boxed::Box;

use serde_json;

use bytes::Bytes;

use SETTING;

use failure::Error;

pub fn setup_request(
    req: HttpRequest,
) -> Box<Future<Item = Json<(LocalIdentity, u64)>, Error = Error>> {
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
                    Ok(Json((
                        LocalIdentity {
                            global: SETTING.read().unwrap().get_identity(),
                            local_ip: reply.unwrap(),
                            wg_port: SETTING.read().unwrap().exit_network.wg_tunnel_port,
                        },
                        SETTING.read().unwrap().exit_network.exit_price,
                    )))
                })
        })
        .responder()
}
