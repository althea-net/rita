use std::{str, thread, time::Duration};

use actix_async::System;
use actix_web_actors::ws;
use althea_types::OperatorUpdateMessage;
use awc::ws::Frame;
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;

use crate::operator_update::{get_operator_checkin_data, handle_operator_update};

/// This function spawns a thread solely responsible for performing the websocket operator update
pub fn start_operator_socket_update_loop() {
    // first actually get the websocket address
    info!("Starting operator socket update loop");
    send_websocket_update();
}

// How long we wait between checkins with the operator server
const SOCKET_UPDATE_FREQUENCY: Duration = Duration::from_secs(10);

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
                    let mut ops_last_seen_usage_hour: Option<u64> = None;
                    loop {
                            // check if there is anything to read first
                            let res = timeout(Duration::from_millis(10), ws.next()).await;
                            if let Ok(Some(res)) = res {
                                let msg = res.unwrap();
                                ops_last_seen_usage_hour = handle_received_operator_message(msg);
                            }

                            // then send over new checkin data
                            let update_data = get_operator_checkin_data(ops_last_seen_usage_hour);
                            if update_data.is_err() {
                                error!("Failed to get operator checkin data, cannot check in with operator server");
                                break;
                            }
                            let serialized = serde_json::to_vec(&update_data.unwrap()).unwrap();
                            info!("Sending checkin through websocket!");
                            let did_send = ws.send(ws::Message::Binary(serialized.into())).await;
                            match did_send {
                            Ok(_) => {
                                // check again for any responses to read
                                let res = timeout(Duration::from_millis(10), ws.next()).await;
                                if let Ok(Some(res)) = res {
                                    let msg = res.unwrap();
                                    ops_last_seen_usage_hour = handle_received_operator_message(msg);
                                }
                                info!("Sleeping until next checkin...");
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

/// Handles reception of OperatorUpdateMessage from a given Message, returns the last seen usage hour if 
/// the message was successfully parsed and handled
fn handle_received_operator_message(msg: Frame) -> Option<u64> {
    match msg {
        ws::Frame::Binary(bytes) =>{
            let info = serde_json::from_slice::<OperatorUpdateMessage>(&bytes);
            match info {
                Ok(info) => {
                    info!("Received operator update message: {:?}", info);
                    match handle_operator_update(info) {
                        Ok(last) => {
                            Some(last)
                        },
                        Err(e) => {
                            error!("Failed to handle operator update message: {:?}", e);
                            None
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to parse operator update message: {:?}", e);
                    None
                }
            }            
        },
        _ => {
            error!("Received unexpected message type from operator server: {:?}", msg);
            None
        }
    }

}