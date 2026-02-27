use crate::operator_update::{
    get_client_mbps, get_hardware_info_update, get_neighbor_info, get_relay_mbps,
    get_rita_uptime, get_user_bandwidth_usage, handle_operator_update,
};
use actix::System;
use actix_web_actors::ws;
use althea_types::{
    identity::Identity,
    websockets::{
        OperatorWebsocketResponse, RouterWebsocketMessage, WsConnectionDetailsStruct,
        WsCustomerDetailsStruct, WsOperatorAddressStruct, WsTimeseriesDataStruct,
    },
};
use awc::ws::Frame;
use bytes::Bytes;
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

// How long we wait between checkins with the operator server
const SOCKET_UPDATE_FREQUENCY: Duration = Duration::from_secs(10);

const TEN_MINUTES: Duration = Duration::from_secs(600);
const FIVE_MINUTES: Duration = Duration::from_secs(300);

/// Result of processing a received websocket message
enum MessageResult {
    /// Successfully received and processed data from ops
    Data(ReceivedOpsData),
    /// Received a ping frame that needs a pong response
    Ping(Bytes),
    /// Message was processed but produced no actionable data (e.g., settings update applied)
    Handled,
    /// Failed to decrypt message - likely have wrong/stale key, should reconnect
    DecryptionError,
    /// Failed to parse the message format
    ParseError(String),
    /// Received an unexpected message type
    UnexpectedMessage(String),
    /// Server is closing the connection
    Close(String),
}

/// What action the main loop should take after processing a message
enum MessageAction {
    /// Continue processing, optionally with a pong to send
    Continue(Option<Bytes>),
    /// Fatal error, should reconnect
    Reconnect(String),
}

/// Process a MessageResult and update state. Returns the action the caller should take.
fn process_message_result(
    result: MessageResult,
    ops_pubkey: &mut Option<PublicKey>,
    ops_last_seen_usage_hour: &mut Option<u64>,
) -> MessageAction {
    match result {
        MessageResult::Data(data) => {
            match data {
                ReceivedOpsData::UsageHour(hour) => {
                    *ops_last_seen_usage_hour = Some(hour);
                }
                ReceivedOpsData::WgKey(public_key) => {
                    info!("Received ops public key");
                    *ops_pubkey = Some(public_key);
                }
            }
            MessageAction::Continue(None)
        }
        MessageResult::Ping(ping) => MessageAction::Continue(Some(ping)),
        MessageResult::Handled => MessageAction::Continue(None),
        MessageResult::DecryptionError => {
            MessageAction::Reconnect("Decryption failed - key may be stale".to_string())
        }
        MessageResult::ParseError(e) => {
            error!("Parse error (continuing): {e}");
            MessageAction::Continue(None)
        }
        MessageResult::UnexpectedMessage(e) => {
            error!("Unexpected message (continuing): {e}");
            MessageAction::Continue(None)
        }
        MessageResult::Close(reason) => MessageAction::Reconnect(reason),
    }
}

/// This function spawns a thread solely responsible for performing the websocket operator update
pub fn start_operator_socket_update_loop() {
    info!("Starting operator socket update loop");
    let url: String = if cfg!(feature = "dev_env") {
        "http://7.7.7.7:8080/ws/".to_string()
    } else if cfg!(feature = "operator_debug") {
        "http://192.168.10.2:8080/ws/".to_string()
    } else {
        "https://operator.althea.net:8080/ws/".to_string()
    };

    // outer thread is a watchdog, inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            let url = url.clone();
            thread::spawn(move || {
                let runner = System::new();
                runner.block_on(async move {
                    loop {
                        if let Err(e) = run_websocket_loop(&url).await {
                            error!("Websocket loop error, reconnecting: {e:?}");
                            thread::sleep(SOCKET_UPDATE_FREQUENCY);
                        }
                    }
                });
            })
            .join()
        } {
            error!("Websocket loop thread panicked! Respawning {e:?}");
        }
    });
}

/// The main websocket loop. Connects to the server and handles all communication.
/// Returns an error if the connection should be restarted.
async fn run_websocket_loop(url: &str) -> Result<(), String> {
    info!("Websocket connecting to {:?}", url);
    let client = awc::Client::builder()
        .max_http_version(awc::http::Version::HTTP_11)
        .finish();

    let (res, mut ws) = client
        .ws(url)
        .connect()
        .await
        .map_err(|e| format!("Failed to connect to websocket: {e:?}"))?;
    info!("Websocket actor is connected {res:?}");

    let mut ops_last_seen_usage_hour: Option<u64> = None;
    // ops_pubkey starts as None - we can receive messages but can't send encrypted updates until we have it
    let mut ops_pubkey: Option<PublicKey> = None;

    let rita_client = settings::get_rita_client();
    let id = match rita_client.get_identity() {
        Some(id) => id,
        None => {
            return Err("No identity found, can't connect to operator server".to_string());
        }
    };
    let our_secretkey = match rita_client.network.wg_private_key {
        Some(key) => SecretKey::from(key),
        None => {
            return Err("No private key found, can't connect to operator server".to_string());
        }
    };

    // this means a router will never check in until 10 seconds after this loop starts
    // this protects us from rapid reboots causing us to spam the operator server with checkins
    let mut last_send = Instant::now();
    let mut ten_minute_timer = Instant::now();
    let mut five_minute_timer = Instant::now();

    // this loop will spend the vast majority of its time just waiting for the next message on ws.next with timeout
    // every time it gets a message it just loops early back to the top to check if it's time to send updates
    loop {
        // Check if it's time to send updates
        if last_send.elapsed() >= SOCKET_UPDATE_FREQUENCY {
            if let Some(ref ops_key) = ops_pubkey {
                // Send timed updates
                if ten_minute_timer.elapsed() > TEN_MINUTES {
                    info!("Ten minutes have passed, sending data to operator server");
                    let messages = get_ten_minute_update_data(id, &our_secretkey, ops_key);
                    for message in messages {
                        if let Err(e) = ws.send(message).await {
                            return Err(format!("Failed to send ten minute update: {e:?}"));
                        }
                    }
                    info!("Ten minute websocket update sent");
                    ten_minute_timer = Instant::now();
                }

                if five_minute_timer.elapsed() > FIVE_MINUTES {
                    info!("Five minutes have passed, sending data to operator server");
                    let messages = get_five_minute_update_data(
                        id,
                        ops_last_seen_usage_hour,
                        &our_secretkey,
                        ops_key,
                    );
                    for message in messages {
                        if let Err(e) = ws.send(message).await {
                            return Err(format!("Failed to send five minute update: {e:?}"));
                        }
                    }
                    info!("Five minute websocket update sent");
                    five_minute_timer = Instant::now();
                }

                // 10 second interval updates
                let messages = get_ten_second_update_data(id, &our_secretkey, ops_key);
                for message in messages {
                    if let Err(e) = ws.send(message).await {
                        return Err(format!("Failed to send ten second update: {e:?}"));
                    }
                }
                trace!("Ten second websocket update sent");
            } else {
                // No ops key yet - send a ping to request it
                // Request the ops public key on connection by sending a ping
                // The server responds to pings with its public key
                trace!("Waiting for ops public key, sending ping");
                if let Err(e) = ws.send(ws::Message::Ping("ping".into())).await {
                    return Err(format!("Failed to send ping: {e:?}"));
                }
            }
            last_send = Instant::now();
        }

        // Wait for next message or until it's time to send again
        let remaining = SOCKET_UPDATE_FREQUENCY.saturating_sub(last_send.elapsed());
        match timeout(remaining, ws.next()).await {
            Ok(Some(Ok(msg))) => {
                let result =
                    handle_received_operator_message(msg, &our_secretkey, ops_pubkey.as_ref());
                match process_message_result(result, &mut ops_pubkey, &mut ops_last_seen_usage_hour)
                {
                    MessageAction::Continue(Some(ping)) => {
                        if let Err(e) = ws.send(ws::Message::Pong(ping)).await {
                            return Err(format!("Failed to send pong: {e:?}"));
                        }
                    }
                    MessageAction::Continue(None) => {}
                    MessageAction::Reconnect(reason) => return Err(reason),
                }
            }
            Ok(Some(Err(e))) => {
                return Err(format!("Websocket protocol error: {e:?}"));
            }
            Ok(None) => {
                return Err("Websocket connection closed".to_string());
            }
            Err(_) => {
                // Timeout - loop back to check if we should send
            }
        }
    }
}

/// Handles reception of OperatorUpdateMessage from a given Message.
/// Returns a MessageResult indicating what happened and what action (if any) the caller should take.
fn handle_received_operator_message(
    msg: Frame,
    our_secretkey: &SecretKey,
    ops_publickey: Option<&PublicKey>,
) -> MessageResult {
    match msg {
        ws::Frame::Binary(bytes) => {
            let message = match serde_json::from_slice::<OperatorWebsocketResponse>(&bytes) {
                Ok(msg) => msg,
                Err(e) => {
                    return MessageResult::ParseError(format!(
                        "Failed to parse operator socket message: {e:?}"
                    ));
                }
            };
            match handle_operator_update(message, our_secretkey, ops_publickey) {
                Ok(Some(data)) => MessageResult::Data(data),
                Ok(None) => MessageResult::Handled,
                Err(e) => {
                    // Check if this is a decryption error
                    if matches!(e, crate::RitaClientError::WebsocketEncryptionError(_)) {
                        error!("Decryption failed, key may be stale: {e:?}");
                        MessageResult::DecryptionError
                    } else {
                        MessageResult::ParseError(format!(
                            "Failed to handle operator update message: {e:?}"
                        ))
                    }
                }
            }
        }
        ws::Frame::Ping(ping) => MessageResult::Ping(ping),
        ws::Frame::Pong(_) => MessageResult::Handled,
        ws::Frame::Close(_) => MessageResult::Close("Received close frame".to_string()),
        other => {
            MessageResult::UnexpectedMessage(format!("Received unexpected message type: {other:?}"))
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

    // Note: exit_con requires ExitState which isn't available in refactored websocket code
    // For now we send None, this is acceptable for reporting purposes
    let exit_con = None;
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
        exit_mbps: None, // rita_client doesn't have exit traffic
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
