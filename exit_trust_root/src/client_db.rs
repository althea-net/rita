//! This file includes functions for interacting with the AltheaDB.sol contract in the solidity folder
//! the purpose of this contract is to act as a registration database for users and exits, so that both
//! exit and client routers can read it to coordinate user setup and two way key exchange with the blockchain
//! as the trusted party

use crate::sms_auth::convert_althea_types_to_web3_error;
use althea_types::{ExitIdentity, Identity, WgKey};
use clarity::{
    abi::{encode_call, AbiToken},
    Address, PrivateKey, Uint256,
};
use std::{collections::HashSet, net::IpAddr, time::Duration, vec};
use tokio::time::timeout as future_timeout;
use web30::{
    client::Web3,
    jsonrpc::error::Web3Error,
    types::{SendTxOption, TransactionRequest},
};

/// The EVM integer size
pub const WORD_SIZE: usize = 32;

pub async fn get_all_registered_clients(
    web30: &Web3,
    requester_address: Address,
    contract: Address,
) -> Result<HashSet<Identity>, Web3Error> {
    let payload = encode_call("getAllRegisteredUsers()", &[])?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(requester_address, contract, payload),
            None,
        )
        .await?;

    let val = convert_althea_types_to_web3_error(Identity::decode_array_from_eth_abi(res))?;
    Ok(val.into_iter().collect())
}

pub async fn get_registered_client_using_wgkey(
    key: WgKey,
    requester_address: Address,
    contract: Address,
    web30: &Web3,
) -> Result<Identity, Web3Error> {
    let payload = encode_call(
        "getRegisteredClientWithWgKey(uint256)",
        &[AbiToken::Uint(key.into())],
    )?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(requester_address, contract, payload),
            None,
        )
        .await?;

    // Parse resulting bytes
    convert_althea_types_to_web3_error(Identity::decode_from_eth_abi(res))
}

/// Function for bulk adding exits to the exits list, while the contract also provides addRegisteredClient() this function uses
/// addRegisteredClientsBulk() exclusively, simply pass a single client in if required.
pub async fn add_users_to_registered_list(
    web30: &Web3,
    users: Vec<Identity>,
    contract: Address,
    sender_private_key: PrivateKey,
    wait_timeout: Option<Duration>,
    options: Vec<SendTxOption>,
) -> Result<Uint256, Web3Error> {
    let mut encoded_clients = Vec::new();
    for user in users {
        if let IpAddr::V6(mesh_ip_v6) = user.mesh_ip {
            encoded_clients.push(AbiToken::Struct(vec![
                AbiToken::Uint(u128::from(mesh_ip_v6).into()),
                AbiToken::Uint(user.wg_public_key.into()),
                AbiToken::Address(user.eth_address),
            ]))
        } else {
            return Err(Web3Error::BadInput(format!(
                "Why is mesh ip a v4? {}",
                user.mesh_ip
            )));
        }
    }

    let tx = web30
        .prepare_transaction(
            contract,
            encode_call(
                "addRegisteredUsersBulk((uint128,uint256,address)[])",
                &[AbiToken::Dynamic(encoded_clients)],
            )?,
            0u32.into(),
            sender_private_key,
            options,
        )
        .await?;

    let tx_hash = web30.send_prepared_transaction(tx).await?;

    if let Some(timeout) = wait_timeout {
        future_timeout(timeout, web30.wait_for_transaction(tx_hash, timeout, None)).await??;
    }

    Ok(tx_hash)
}

/// Function for bulk adding exits to the exits list, while the contract also provides addRegisteredExit() this function uses
/// addRegisteredExitsBulk() exclusively, simply pass a single exit in if required.
pub async fn add_exits_to_registration_list(
    web30: &Web3,
    exits: Vec<ExitIdentity>,
    contract: Address,
    sender_private_key: PrivateKey,
    wait_timeout: Option<Duration>,
    options: Vec<SendTxOption>,
) -> Result<Uint256, Web3Error> {
    let encoded_exits = ExitIdentity::encode_array_to_eth_abi_token(exits);

    let tx = web30
        .prepare_transaction(
            contract,
            encode_call(
                "addRegisteredExitsBulk((uint128,uint256,address,uint16,uint16,uint256[],uint256[])[])",
                &[encoded_exits],
            )?,
            0u32.into(),
            sender_private_key,
            options,
        )
        .await?;

    let tx_hash = web30.send_prepared_transaction(tx).await?;

    if let Some(timeout) = wait_timeout {
        future_timeout(timeout, web30.wait_for_transaction(tx_hash, timeout, None)).await??;
    }

    Ok(tx_hash)
}

/// Checks if a given adress is an user admin, that is one of the addresses that is allowed to
/// add and remove users from the contract
pub async fn check_user_admin(
    web30: &Web3,
    contract: Address,
    user_admin: Address,
    our_private_key: PrivateKey,
) -> Result<bool, Web3Error> {
    // Check if we are already a user admin
    let payload = encode_call("isUserAdmin(address)", &[AbiToken::Address(user_admin)])?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(our_private_key.to_address(), contract, payload),
            None,
        )
        .await?;

    let is_admin = !res.is_empty()
        && Uint256::from_be_bytes(res.chunks(WORD_SIZE).collect::<Vec<_>>()[0]) == 1u8.into();

    Ok(is_admin)
}

/// A user admin has permissions to add and remove users from the registered list
/// this function adds them only if required
pub async fn check_and_add_user_admin(
    web30: &Web3,
    contract: Address,
    user_admin: Address,
    our_private_key: PrivateKey,
    wait_timeout: Option<Duration>,
    options: Vec<SendTxOption>,
) -> Result<(), Web3Error> {
    if !check_user_admin(web30, contract, user_admin, our_private_key).await? {
        let tx = web30
            .prepare_transaction(
                contract,
                encode_call("addUserAdmin(address)", &[AbiToken::Address(user_admin)])?,
                0u32.into(),
                our_private_key,
                options,
            )
            .await?;

        let tx_hash = web30.send_prepared_transaction(tx).await?;

        if let Some(timeout) = wait_timeout {
            future_timeout(timeout, web30.wait_for_transaction(tx_hash, timeout, None)).await??;
        }
    }
    Ok(())
}

/// Checks if a given address is an exit admin, that is one of the addresses that is allowed to
/// add and remove exits from the contract
pub async fn check_exit_admin(
    web30: &Web3,
    contract: Address,
    exit_admin: Address,
    our_private_key: PrivateKey,
) -> Result<bool, Web3Error> {
    let payload = encode_call("isExitAdmin(address)", &[AbiToken::Address(exit_admin)])?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(our_private_key.to_address(), contract, payload),
            None,
        )
        .await?;

    let is_admin =
        Uint256::from_be_bytes(res.chunks(WORD_SIZE).collect::<Vec<_>>()[0]) == 1u8.into();

    Ok(is_admin)
}

/// An exit admin has permissions to add and remove exits from the exit list. This is what is returned
/// to clients to register to exits
pub async fn add_exit_admin(
    web30: &Web3,
    contract: Address,
    exit_admin: Address,
    our_private_key: PrivateKey,
    wait_timeout: Option<Duration>,
    options: Vec<SendTxOption>,
) -> Result<(), Web3Error> {
    if !check_exit_admin(web30, contract, exit_admin, our_private_key).await? {
        let tx = web30
            .prepare_transaction(
                contract,
                encode_call("addExitAdmin(address)", &[AbiToken::Address(exit_admin)])?,
                0u32.into(),
                our_private_key,
                options,
            )
            .await?;

        let tx_hash = web30.send_prepared_transaction(tx).await?;

        if let Some(timeout) = wait_timeout {
            future_timeout(timeout, web30.wait_for_transaction(tx_hash, timeout, None)).await??;
        }
    }
    Ok(())
}

/// Gets the list of exits from the smart contract
pub async fn get_exits_list(
    web30: &Web3,
    requester_address: Address,
    contract: Address,
) -> Result<Vec<ExitIdentity>, Web3Error> {
    let payload = encode_call("getAllRegisteredExits()", &[])?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(requester_address, contract, payload),
            None,
        )
        .await?;

    // Parse resulting bytes
    convert_althea_types_to_web3_error(ExitIdentity::decode_array_from_eth_abi(res))
}
