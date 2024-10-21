use crate::operator_update::{
    get_client_mbps, get_exit_con, get_hardware_info_update, get_neighbor_info, get_relay_mbps,
    get_rita_uptime, get_user_bandwidth_usage, handle_operator_update,
};
use actix::System;
use actix_web_actors::ws;
use althea_types::{
    websockets::{
        OperatorWebsocketResponse, RouterWebsocketMessage, WsConnectionDetailsStruct,
        WsCustomerDetailsStruct, WsOperatorAddressStruct, WsTimeseriesDataStruct,
    },
    Identity,
};
use awc::ws::Frame;
use crypto_box::{PublicKey, SecretKey};
use futures::{SinkExt, StreamExt};
use settings::{
    get_billing_details, get_contact_info, get_install_details, get_operator_address,
    get_system_chain, get_user_bandwidth_limit,
};
use std::{
    str, thread,
    time::{Duration, Instant},
};
use tokio::time::timeout;

use super::ReceivedOpsData;

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
        url = "http://192.168.10.2:8080/ws/";
    } else {
        url = "https://operator.althea.net:8080/ws/";
    }
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || {
                let runner = System::new();
                runner.block_on(async move {
                    let client = awc::Client::builder()
                        .max_http_version(awc::http::Version::HTTP_11)
                        .finish();
                    loop {
                        info!("Websocket connecting to {:?}", url);
                        let res = client.ws(url).connect().await;
                        match res {
                            Ok((res, mut ws)) => {
                                info!("Websocket actor is connected {:?}", res);
                                let mut ops_last_seen_usage_hour: Option<u64> = None;
                                // we only need to get the identity once
                                let rita_client = settings::get_rita_client();
                                let id = rita_client.get_identity().unwrap();
                                let our_secretkey = match rita_client.network.wg_private_key {
                                    Some(key) => SecretKey::from(key),
                                    None => {
                                        error!("No private key found, can't connect to operator server");
                                        return;
                                    }
                                };
                                let mut ops_pubkey;
                                // we must receive the ops pubkey before we can proceed with encryption and sending! 
                                // ops sends this on websocket open and on ping response, so if for some reason we don't receive it 
                                // automatically after opening the connection, send a ping
                                loop {
                                    // check if we have received the ops pubkey
                                    if let Ok(Some(msg)) =
                                        timeout(SOCKET_CHECKER_TIMEOUT, ws.next()).await
                                    {
                                        let msg = msg.unwrap();
                                        if let Some(data) = handle_received_operator_message(msg, &our_secretkey, None) {
                                            match data {
                                                ReceivedOpsData::WgKey(public_key) => {
                                                    ops_pubkey = public_key;
                                                    break;
                                                },
                                                // we cannot actually decrypt any messages until we have the ops pubkey so this will never reach panic
                                                _ => panic!("Why are we receiving a usage hour from ops on socket startup? restarting!"),
                                            }
                                        }
                                    } else {
                                        ws.send(ws::Message::Ping("ping".into())).await.unwrap();
                                        thread::sleep(Duration::from_secs(1));
                                    }
                                }

                                let mut ten_minute_timer: Instant = Instant::now();
                                let mut five_minute_timer: Instant = Instant::now();
                                loop {
                                    // check if there is anything to read first
                                    while let Ok(Some(msg)) =
                                        timeout(SOCKET_CHECKER_TIMEOUT, ws.next()).await
                                    {
                                        // we will panic here with a connection reset if the socket has disconnected
                                        // tht will then fall out of this loop into the outer loop, restarting the whole thing
                                        // and reconnecting the socket
                                        let msg = msg.unwrap();
                                        if let Some(hour) = handle_received_operator_message(msg, &our_secretkey, Some(&ops_pubkey)) {
                                            match hour {
                                                ReceivedOpsData::UsageHour(hour) => {
                                                    ops_last_seen_usage_hour = Some(hour);
                                                },
                                                ReceivedOpsData::WgKey(public_key) => {
                                                    ops_pubkey = public_key;
                                                },
                                            }
                                        }
                                    }

                                    // then send over new checkin data where applicable
                                    if Instant::now() - ten_minute_timer > TEN_MINUTES {
                                        info!(
                                        "Ten minutes have passed, sending data to operator server"
                                    );
                                        let messages = get_ten_minute_update_data(id, &our_secretkey, &ops_pubkey);
                                        for message in messages {
                                            // if this unwrap panics, send has failed because the socket has disconnected;
                                            // the thread will simply reconnect the socket and retry
                                            ws.send(message).await.unwrap();
                                        }
                                        info!("Ten minute websocket update sent");
                                        ten_minute_timer = Instant::now();
                                    }
                                    if Instant::now() - five_minute_timer > FIVE_MINUTES {
                                        info!(
                                        "Five minutes have passed, sending data to operator server"
                                    );
                                        let messages = get_five_minute_update_data(
                                            id,
                                            ops_last_seen_usage_hour,
                                            &our_secretkey, &ops_pubkey
                                        );
                                        for message in messages {
                                            ws.send(message).await.unwrap();
                                        }
                                        info!("Five minute websocket update sent");
                                        five_minute_timer = Instant::now();
                                    }
                                    // the rest of these are 10 second interval updates and run every iteration of the loop
                                    let messages = get_ten_second_update_data(id,&our_secretkey, &ops_pubkey);
                                    for message in messages {
                                        ws.send(message).await.unwrap();
                                    }
                                    info!("Ten second websocket update sent");

                                    // check again for any responses to read
                                    while let Ok(Some(msg)) =
                                        timeout(SOCKET_CHECKER_TIMEOUT, ws.next()).await
                                    {
                                        let msg = msg.unwrap();
                                        if let Some(hour) = handle_received_operator_message(msg, &our_secretkey, Some(&ops_pubkey)) {
                                            match hour {
                                                ReceivedOpsData::UsageHour(hour) => {ops_last_seen_usage_hour = Some(hour);},
                                                ReceivedOpsData::WgKey(public_key) => {
                                                    ops_pubkey = public_key;
                                                },
                                            }
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
                    }
                });
            })
            .join()
        } {
            error!("Websocket loop thread panicked! Respawning {:?}", e);
        }
    });
}

/// Handles reception of OperatorUpdateMessage from a given Message, returns the a ReceivedOpsData if
/// the message was successfully parsed and handled. if ops_publickey is None, we will return the given pub key-
/// this is the first message we receive from the operator server.
fn handle_received_operator_message(
    msg: Frame,
    our_secretkey: &SecretKey,
    ops_publickey: Option<&PublicKey>,
) -> Option<ReceivedOpsData> {
    match msg {
        ws::Frame::Binary(bytes) => {
            let message = serde_json::from_slice::<OperatorWebsocketResponse>(&bytes);
            // check if we got a wg key or a message
            match message {
                Ok(message) => {
                    info!("Received operator websocket message");
                    match handle_operator_update(message, our_secretkey, ops_publickey) {
                        Ok(data) => data,
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
fn get_ten_minute_update_data(
    id: Identity,
    our_secretkey: &SecretKey,
    ops_pubkey: &PublicKey,
) -> Vec<ws::Message> {
    let mut messages = Vec::new();

    let contact_info = get_contact_info();
    let install_details = get_install_details();
    let billing_details = get_billing_details();
    let data = RouterWebsocketMessage::CustomerDetails(WsCustomerDetailsStruct {
        id,
        contact_info,
        install_details,
        billing_details,
    });
    // encrypt the data
    let encrypted_json = data
        .encrypt(id.wg_public_key, our_secretkey, ops_pubkey)
        .json();
    messages.push(ws::Message::Binary(encrypted_json.into()));

    let address = get_operator_address();
    let chain = get_system_chain();
    let data =
        RouterWebsocketMessage::OperatorAddress(WsOperatorAddressStruct { id, address, chain });
    let encrypted_json = data
        .encrypt(id.wg_public_key, our_secretkey, ops_pubkey)
        .json();
    messages.push(ws::Message::Binary(encrypted_json.into()));
    messages
}

/// gets checkin data for the five minute update and converts it to a Vec of ws Binary messages
fn get_five_minute_update_data(
    id: Identity,
    ops_last_seen_usage_hour: Option<u64>,
    our_secretkey: &SecretKey,
    ops_pubkey: &PublicKey,
) -> Vec<ws::Message> {
    let mut messages = Vec::new();

    let exit_con = get_exit_con();
    let user_bandwidth_limit = get_user_bandwidth_limit();
    let user_bandwidth_usage = get_user_bandwidth_usage(ops_last_seen_usage_hour);
    let client_mbps = get_client_mbps();
    let relay_mbps = get_relay_mbps();
    let data = RouterWebsocketMessage::ConnectionDetails(WsConnectionDetailsStruct {
        id,
        exit_con,
        user_bandwidth_limit,
        user_bandwidth_usage,
        client_mbps,
        relay_mbps,
    });
    let encrypted_json = data
        .encrypt(id.wg_public_key, our_secretkey, ops_pubkey)
        .json();
    messages.push(ws::Message::Binary(encrypted_json.into()));
    messages
}

/// gets checkin data for the ten second upate and converts it to a Vec of ws Binary messages
fn get_ten_second_update_data(
    id: Identity,
    our_secretkey: &SecretKey,
    ops_pubkey: &PublicKey,
) -> Vec<ws::Message> {
    let mut messages = Vec::new();

    let neighbor_info = get_neighbor_info();
    let hardware_info = get_hardware_info_update();
    let rita_uptime = get_rita_uptime();
    let data = RouterWebsocketMessage::TimeseriesData(WsTimeseriesDataStruct {
        id,
        neighbor_info,
        hardware_info,
        rita_uptime,
    });
    let encrypted_json = data
        .encrypt(id.wg_public_key, our_secretkey, ops_pubkey)
        .json();
    messages.push(ws::Message::Binary(encrypted_json.into()));

    messages
}
