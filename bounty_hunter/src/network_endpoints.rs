use actix_web::{http::StatusCode, HttpRequest, HttpResponse, Json};
use clarity::Address;
use diesel::prelude::*;
use failure::Error;
use futures::{future, Future};
use num256::Uint256;

use std::collections::HashMap;

use models::{ChannelState, ChannelStateRecord, NewChannelStateRecord};
use schema::states::dsl::*;
use DB_CONN;

/// Pass channel state to the bounty hunter
pub fn handle_upload_channel_state(
    state_obj: Json<ChannelState>,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    trace!("Hit /upload_channel_state");

    let mut ret = HashMap::new();

    let state = state_obj.into_inner();
    debug!("Got state {:?}", state);

    // Check signatures
    if let Some(sig_a) = &state.signature_a {
        match state.verify(sig_a) {
            Ok(_) => debug!(
                "Channel {}: Signature A {:?} verification OK",
                state.channel_id, sig_a
            ),
            Err(e) => {
                let msg = format!(
                    "Channel {}: Signature A {:?} verification FAILED",
                    state.channel_id, sig_a
                );

                warn!("{}: {}", msg, e);
                ret.insert("error".to_owned(), msg);

                return Box::new(future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                ));
            }
        }
    }
    if let Some(sig_b) = &state.signature_b {
        match state.verify(sig_b) {
            Ok(_) => debug!(
                "Channel {}: Signature B {:?} verification OK",
                state.channel_id, sig_b
            ),
            Err(e) => {
                let msg = format!(
                    "Channel {}: Signature B {:?} verification FAILED",
                    state.channel_id, sig_b
                );

                warn!("{}: {}", msg, e);
                ret.insert("error".to_owned(), msg);

                return Box::new(future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                ));
            }
        }
    }

    // Multiple queries need to happen without interruption
    let db_conn = DB_CONN.lock().unwrap();

    /*
     * DO NOT "OPTIMIZE" `state_nonce_fixed` INTO A VEC. Fixed-length is critical for ordering to
     * work properly within the database (blob ordering in SQLite is analogous to string
     * ordering - string "9" goes AFTER string "10", but fixed-size would make this comparison
     * more like "09" vs. "10" which checks out).
     *
     * SCREWED UP ORDERING FOR NONCE/SEQNO VARIABLES MEANS HIDEOUS ERRORS AND REPLAY ATTACK
     * VULNERABILITIES.
     */
    let state_nonce_fixed: [u8; 32] = state.nonce.clone().into();

    // Look for newer nonces
    let better_nonces = match states
        .filter(channel_id.eq(state.channel_id.to_bytes_be()))
        .filter(nonce.ge(state_nonce_fixed.to_vec()))
        .load::<ChannelStateRecord>(&*db_conn)
    {
        Ok(values) => values,
        Err(e) => {
            let msg = format!(
                "Channel {}: Could not look for newer nonces in the database",
                state.channel_id
            );
            warn!("{}: {}", msg, e);

            ret.insert("error".to_owned(), msg);

            return Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(ret),
            ));
        }
    };

    debug!(
        "Channel {}: Nonce query found values: {:?}",
        state.channel_id, better_nonces
    );

    if !better_nonces.is_empty() {
        /* Better nonce available, bail */
        warn!(
            "Channel {}: Nonce {} is too old",
            state.channel_id, state.nonce
        );
        ret.insert("error".to_owned(), "Nonce too old".to_owned());
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }

    // No better nonce available, carry on
    debug!("Channel {}: Nonce {} OK", state.channel_id, state.nonce);
    let state_new_record = NewChannelStateRecord::from(state.clone());
    let existing_entry = states.filter(channel_id.eq(&state_new_record.channel_id));

    // Store the result so that db_conn ref is released in time. Would cause deadlock for the
    // rows_affected == 0 branch otherwise.
    let update_result = diesel::update(existing_entry)
        .set(&state_new_record)
        .execute(&*db_conn);

    match update_result {
        // The schema has `UNIQUE` on channel_id. This query must affect only one row
        // at all times.
        Ok(rows_affected) if rows_affected > 1 => {
            warn!("Channel {}: Update affected multiple ({}) rows. Make sure that your DB respects the UNIQUE constraint",
            state.channel_id,
            rows_affected);

            ret.insert(
                "error".to_owned(),
                "A DB integrity problem was detected in your channel's entries".to_owned(),
            );

            Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(ret),
            ))
        }
        Ok(rows_affected) if rows_affected == 1 => {
            info!("Channel {}: Update OK", state.channel_id);
            Box::new(future::ok(HttpResponse::Ok().json(ret)))
        }
        Ok(rows_affected) if rows_affected == 0 => {
            info!("Channel {}: Not in database, inserting", state.channel_id);

            match diesel::insert_into(states)
                .values(NewChannelStateRecord::from(state.clone()))
                .execute(&*db_conn)
            {
                Ok(_) => {
                    info!("Insert OK");
                    Box::new(future::ok(HttpResponse::Ok().json(ret)))
                }
                Err(e) => {
                    let msg = format!("Could not insert new channel into database");

                    warn!("Channel {}: {}: {}", state.channel_id, msg, e);

                    ret.insert("error".to_owned(), msg);

                    Box::new(future::ok(
                        HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                            .into_builder()
                            .json(ret),
                    ))
                }
            }
        }
        Ok(rows_affected_other) => {
            error!("Unknown Update result value: {}", rows_affected_other);
            Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(ret),
            ))
        }
        Err(e) => {
            let msg = format!("Could not update existing record");
            warn!("Channel {}: {}: {}", state.channel_id, msg, e);
            ret.insert("error".to_owned(), msg);
            Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(ret),
            ))
        }
    }
}

/// Query for the bounty hunter channel state from a requested time period
pub fn handle_get_channel_state(
    _req: HttpRequest,
    address: actix_web::Path<Address>,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let address = address.into_inner();
    trace!("Hit /get_channel_state/{:#x}", address);

    let matching_records = match states
        .filter(
            address_a
                .eq(address.as_bytes())
                .or(address_b.eq(address.as_bytes())),
        ).load::<ChannelStateRecord>(&*DB_CONN.lock().unwrap())
    {
        Ok(values) => values,
        Err(e) => {
            let mut err_ret = HashMap::new();
            let msg = format!("Could not retrieve record from database");

            warn!("Address {:#x}: {}: {}", address, msg, e);

            err_ret.insert("error".to_owned(), msg);

            return Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(err_ret),
            ));
        }
    };

    debug!(
        "Address {:#x}: query result: {:#?}",
        address, matching_records
    );

    let mut ok_ret = HashMap::new();
    ok_ret.insert(
        "record".to_owned(),
        matching_records
            .into_iter()
            .map(|record| record.to_state().unwrap())
            .collect::<Vec<ChannelState>>(),
    );

    return Box::new(future::ok(HttpResponse::Ok().json(ok_ret)));
}
