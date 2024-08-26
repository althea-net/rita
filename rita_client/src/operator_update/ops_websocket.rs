use std::{
    str, thread,
    time::{Duration, Instant},
};

use actix_async::System;
use actix_web_actors::ws;
use althea_types::{
    websockets::{OperatorWebsocketMessage, RouterWebsocketMessage},
    Identity,
};
use awc::ws::Frame;
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;

use crate::operator_update::{
    get_billing_details, get_client_mbps, get_contact_info, get_exit_con, get_hardware_info_update,
    get_install_details, get_neighbor_info, get_operator_address, get_relay_mbps, get_rita_uptime,
    get_system_chain, get_user_bandwidth_limit, get_user_bandwidth_usage, handle_operator_update,
};

/// This function spawns a thread solely responsible for performing the websocket operator update
pub fn start_operator_socket_update_loop() {
    // first actually get the websocket address
    info!("Starting operator socket update loop");
    send_websocket_update();
}

// How long we wait between checkins with the operator server
const SOCKET_UPDATE_FREQUENCY: Duration = Duration::from_secs(10);

const TEN_MINUTES: Duration = Duration::from_secs(600);
const FIVE_MINUTES: Duration = Duration::from_secs(300);
// Timeout for checking if there is anything to read from the websocket; this is intentionally low
// because we don't need to wait if there is nothing to read which will be the case most of the time
const SOCKET_CHECKER_TIMEOUT: Duration = Duration::from_millis(10);

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
                    // we only need to get the identity once
                    let rita_client = settings::get_rita_client();
                    let id = rita_client.get_identity().unwrap();

                    let mut ten_minute_timer: Instant = Instant::now();
                    let mut five_minute_timer: Instant = Instant::now();
                    loop {
                        // check if there is anything to read first
                        let res = timeout(SOCKET_CHECKER_TIMEOUT, ws.next()).await;
                        if let Ok(Some(res)) = res {
                            let msg = res.unwrap();
                            ops_last_seen_usage_hour = handle_received_operator_message(msg);
                        }

                        // then send over new checkin data where applicable
                        if Instant::now() - ten_minute_timer > TEN_MINUTES {
                            info!("Ten minutes have passed, sending data to operator server");
                            let messages = get_ten_minute_update_data(id);
                            for message in messages {
                                // if this unwrap panics, send has failed because the socket has disconnected;
                                // the thread will simply reconnect the socket and retry
                                ws.send(message).await.unwrap();
                            }
                            ten_minute_timer = Instant::now();
                        }
                        if Instant::now() - five_minute_timer > FIVE_MINUTES {
                            info!("Five minutes have passed, sending data to operator server");
                            let messages =
                                get_five_minute_update_data(id, ops_last_seen_usage_hour);
                            for message in messages {
                                ws.send(message).await.unwrap();
                            }
                            five_minute_timer = Instant::now();
                        }
                        // the rest of these are 5 second interval updates and run every iteration of the loop
                        let messages = get_ten_second_update_data(id);
                        for message in messages {
                            ws.send(message).await.unwrap();
                        }

                        // check again for any responses to read
                        let res = timeout(SOCKET_CHECKER_TIMEOUT, ws.next()).await;
                        if let Ok(Some(res)) = res {
                            let msg = res.unwrap();
                            if let Some(last) = handle_received_operator_message(msg) {
                                ops_last_seen_usage_hour = Some(last);
                            }
                        }
                        info!("Sleeping until next checkin...");
                        thread::sleep(SOCKET_UPDATE_FREQUENCY);
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to connect to websocket; attempting to restart loop... {:?}",
                        e
                    );
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
        ws::Frame::Binary(bytes) => {
            let info = serde_json::from_slice::<OperatorWebsocketMessage>(&bytes);
            match info {
                Ok(info) => {
                    info!("Received operator update message: {:?}", info);
                    match handle_operator_update(info) {
                        Ok(last) => last,
                        Err(e) => {
                            error!("Failed to handle operator update message: {:?}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to parse operator socket message: {:?}", e);
                    None
                }
            }
        }
        _ => {
            error!(
                "Received unexpected message type from operator server: {:?}",
                msg
            );
            None
        }
    }
}

/// gets checkin data for the ten minute update and converts it to a Vec of ws Binary messages
/// to be sent to the operator server
fn get_ten_minute_update_data(id: Identity) -> Vec<ws::Message> {
    let mut messages = Vec::new();

    let contact_info = get_contact_info();
    let install_details = get_install_details();
    let billing_details = get_billing_details();
    let data = RouterWebsocketMessage::CustomerDetails {
        id,
        contact_info,
        install_details,
        billing_details,
    };
    let serialized = serde_json::to_vec(&data).unwrap();
    messages.push(ws::Message::Binary(serialized.into()));

    let address = get_operator_address();
    let chain = get_system_chain();
    let data = RouterWebsocketMessage::OperatorAddress { id, address, chain };
    let serialized = serde_json::to_vec(&data).unwrap();
    messages.push(ws::Message::Binary(serialized.into()));

    messages
}

/// gets checkin data for the five minute update and converts it to a Vec of ws Binary messages
fn get_five_minute_update_data(
    id: Identity,
    ops_last_seen_usage_hour: Option<u64>,
) -> Vec<ws::Message> {
    let mut messages = Vec::new();

    let exit_con = get_exit_con();
    let user_bandwidth_limit = get_user_bandwidth_limit();
    let user_bandwidth_usage = get_user_bandwidth_usage(ops_last_seen_usage_hour);
    let client_mbps = get_client_mbps();
    let relay_mbps = get_relay_mbps();
    let data = RouterWebsocketMessage::ConnectionDetails {
        id,
        exit_con,
        user_bandwidth_limit,
        user_bandwidth_usage,
        client_mbps,
        relay_mbps,
    };
    let serialized = serde_json::to_vec(&data).unwrap();
    messages.push(ws::Message::Binary(serialized.into()));

    messages
}

/// gets checkin data for the ten second upate and converts it to a Vec of ws Binary messages
fn get_ten_second_update_data(id: Identity) -> Vec<ws::Message> {
    let mut messages = Vec::new();

    let neighbor_info = get_neighbor_info();
    let hardware_info = get_hardware_info_update();
    let rita_uptime = get_rita_uptime();
    let data = RouterWebsocketMessage::TimeseriesData {
        id,
        neighbor_info,
        hardware_info,
        rita_uptime,
    };
    let serialized = serde_json::to_vec(&data).unwrap();
    messages.push(ws::Message::Binary(serialized.into()));

    messages
}
