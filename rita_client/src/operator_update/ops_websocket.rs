use std::{thread, time::Duration};

use actix_async::System;
use actix_web_actors::ws;
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;

const SOCKET_UPDATE_FREQUENCY: Duration = Duration::from_secs(1);

/// The message we send to the operator server websocket to request a websocket url
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSocketRequest {
    pub user_id: u64,
}

// serializing with JSON to send info through websocket:
// serde_json::to_string(info).unwrap_or_default()

/// Send an update to ops server via websocket
pub fn send_websocket_update() {
    let url: &str;
    if cfg!(feature = "dev_env") {
        url = "http://7.7.7.7:8080/ws/";
    } else if cfg!(feature = "operator_debug") {
        url = "http://192.168.1.214:8080/ws/";
    } else {
        url = "https://operator.althea.net:8080/ws/";
    }
    thread::spawn(move || loop {
        let runner = System::new();
        runner.block_on(async move {
            let res = awc::Client::new().ws(url).connect().await;
            match res {
                Ok((res, mut ws)) => {
                    info!("Websocket actor is connected {:?}", res);
                    let rita_client = settings::get_rita_client();
                    let id = rita_client.get_identity().unwrap();
                    loop {
                        let text = serde_json::to_string(&id).unwrap();
                        info!("Sending id through websocket!");
                        let did_send = ws.send(ws::Message::Text(text.into())).await;
                        match did_send {
                            Ok(_) => {
                                let res = timeout(Duration::from_millis(10), ws.next()).await;
                                println!("Actor received {:?}", res);
                                let res = timeout(Duration::from_millis(10), ws.next()).await;
                                println!("Actor received {:?}", res);
                                thread::sleep(SOCKET_UPDATE_FREQUENCY);
                            },
                            Err(e) => {
                                error!("Failed to send id through websocket; attempting to restart loop... {:?}", e);
                                break;
                            }
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to connect to websocket; attempting to restart loop... {:?}", e);
                    thread::sleep(SOCKET_UPDATE_FREQUENCY);
                }

            }
        });
        info!("Restarting websocket loop...");
    });
}
