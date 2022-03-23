//! Function used for handling the dispatch of hello messages
//!
//! The call path goes like this
//!
//! peer listener gets udp ImHere -> TunnelManager tries to contact peer with hello
//! -> hello manager actually manages that request -> hello manager calls back to tunnel manager

use std::time::Duration;

use crate::peer_listener::Peer;
use crate::tm_identity_callback;
use crate::tunnel_manager::id_callback::IdentityCallback;

use althea_types::LocalIdentity;

#[derive(Default)]
pub struct HelloHandler;

#[derive(Debug)]
pub struct Hello {
    pub my_id: LocalIdentity,
    pub to: Peer,
}

/// Handler for sending hello messages
pub async fn handle_hello(msg: Hello) {
    trace!("Sending Hello {:?}", msg);

    // ipv6 addresses need the [] bracket format, ipv4 address literals do not
    let endpoint = if msg.to.contact_socket.is_ipv4() {
        format!(
            "http://{}:{}/hello",
            msg.to.contact_socket.ip(),
            msg.to.contact_socket.port()
        )
    } else {
        format!(
            "http://[{}]:{}/hello",
            msg.to.contact_socket.ip(),
            msg.to.contact_socket.port()
        )
    };

    let client = awc::Client::default();
    info!("Sending hello request to manual peer: {}", endpoint);
    let response = client
        .post(endpoint)
        .timeout(Duration::from_secs(5))
        .send_json(&msg.my_id)
        .await;

    let mut response = match response {
        Ok(a) => a,
        Err(e) => {
            error!("Error serializing our request {:?}", e);
            return;
        }
    };

    let value: LocalIdentity = match response.json().await {
        Ok(a) => a,
        Err(e) => {
            error!("Got error deserializing Hello {:?}", e);
            return;
        }
    };

    info!("Received a local identity, setting a tunnel");
    let peer = msg.to;
    let wg_port = msg.my_id.wg_port;
    tm_identity_callback(IdentityCallback::new(value, peer, Some(wg_port), None));
}
