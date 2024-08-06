use std::{thread, time::Duration};

use actix_async::System;
use actix_web_actors::ws;
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;

const SOCKET_UPDATE_FREQUENCY: Duration = Duration::from_secs(15);

/// The message we send to the operator server websocket to request a websocket url
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSocketRequest {
    pub user_id: u64,
}

// serializing with JSON to send info through websocket:
// serde_json::to_string(info).unwrap_or_default()

/// Send an update to ops server via websocket
pub fn send_websocket_update() {
    thread::spawn(|| loop {
        let runner = System::new();
        runner.block_on(async move {
            let (res, mut ws) = awc::Client::new()
                .ws("ws://127.0.0.1:8080/ws/")
                .connect()
                .await
                .unwrap();
            print!("Actor is connected {:?}", res);

            let rita_client = settings::get_rita_client();
            let id = rita_client.get_identity().unwrap();
            loop {
                let text = serde_json::to_string(&id).unwrap();
                ws.send(ws::Message::Text(text.into()))
                    .await
                    .unwrap();
                let res = timeout(Duration::from_millis(10), ws.next()).await;
                println!("Actor received {:?}", res);
                let res = timeout(Duration::from_millis(10), ws.next()).await;
                println!("Actor received {:?}", res);
                thread::sleep(SOCKET_UPDATE_FREQUENCY);
            }
        });
    });
}
