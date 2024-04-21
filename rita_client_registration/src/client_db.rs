//! This file includes functions for interacting with the AltheaDB.sol contract in the solidity folder
//! the purpose of this contract is to act as a registration database for users and exits, so that both
//! exit and client routers can read it to coordinate user setup and two way key exchange with the blockchain
//! as the trusted party

use althea_types::{regions::Regions, ExitIdentity, Identity, SystemChain, WgKey};
use clarity::{
    abi::{encode_call, AbiToken},
    utils::bytes_to_hex_str,
    Address, PrivateKey, Uint256,
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr},
    time::Duration,
    vec,
};
use tokio::time::timeout as future_timeout;
use web30::{
    client::Web3,
    jsonrpc::error::Web3Error,
    types::{SendTxOption, TransactionRequest},
};

/// The EVM integer size
pub const WORD_SIZE: usize = 32;

/// This function takes a flat byte vector `input` and divides it into chunks of a specified
/// word size (`WORD_SIZE`). Each chunk is then converted into a separate vector of bytes,
/// resulting in a vector of EVM words.
fn to_evm_words(input: Vec<u8>) -> Vec<Vec<u8>> {
    input.chunks(WORD_SIZE).map(|i| i.to_vec()).collect()
}

pub async fn get_all_regsitered_clients(
    web30: &Web3,
    requester_address: Address,
    contract: Address,
) -> Result<Vec<Identity>, Web3Error> {
    let payload = encode_call("getAllRegisteredUsers()", &[])?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(requester_address, contract, payload),
            None,
        )
        .await?;

    parse_identity_array_abi(res)
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
    parse_identity_abi(res.chunks(WORD_SIZE).map(|i| i.to_vec()).collect())
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
    let mut encoded_exits = Vec::new();
    for exit in exits {
        if let IpAddr::V6(mesh_ip_v6) = exit.mesh_ip {
            encoded_exits.push(AbiToken::Struct(vec![
                AbiToken::Uint(u128::from(mesh_ip_v6).into()),
                AbiToken::Uint(exit.wg_key.into()),
                AbiToken::Address(exit.eth_addr),
                AbiToken::Uint(exit.registration_port.into()),
                AbiToken::Uint(exit.wg_exit_listen_port.into()),
                allowed_regions_abi_array(exit.allowed_regions).into(),
                payment_types_abi_array(exit.payment_types).into(),
            ]))
        } else {
            return Err(Web3Error::BadInput(format!(
                "Why is mesh ip a v4? {}",
                exit.mesh_ip
            )));
        }
    }

    let tx = web30
        .prepare_transaction(
            contract,
            encode_call(
                "addRegisteredExitsBulk((uint128,uint256,address,uint16,uint16,uint256[],uint256[])[])",
                &[AbiToken::Dynamic(encoded_exits)],
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

fn allowed_regions_abi_array(allowed_regions: HashSet<Regions>) -> Vec<AbiToken> {
    let mut ret = vec![];
    for reg in allowed_regions.iter() {
        let reg_int: u8 = (*reg).into();
        ret.push(AbiToken::Uint(reg_int.into()));
    }
    ret
}

fn payment_types_abi_array(payment_types: HashSet<SystemChain>) -> Vec<AbiToken> {
    let mut ret = vec![];
    for payment_type in payment_types.iter() {
        let pay_int: u8 = (*payment_type).into();
        ret.push(AbiToken::Uint(pay_int.into()));
    }
    ret
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
    parse_exit_identity_array_abi(res)
}

pub fn parse_identity_abi(byte_chunks: Vec<Vec<u8>>) -> Result<Identity, Web3Error> {
    /* Expected Input:
    00000000000000000000000000000000c5860e75c42cec1fe1d838a78de785fb // Mesh ip as u128
    c5860e75c42cec1fe1d838a78de785fbb687e85cbd5073a089b5395397423ccc // wgkey as u256
    00000000000000000000000052af7358f572812088ecf214e821ba45361e49bd // eth address
    */

    // A correct input should have only 3 lines for each entry of the id struct, anything else we return an error
    if byte_chunks.len() != 3 {
        return Err(Web3Error::BadInput(format!(
            "Received byte chunks: {byte_chunks:?}. Expected only 3 lines for meship, wgkey and ethaddress"
        )));
    }

    let mut index = 0;
    // 1st entry is the mes ip as a u128
    let mesh_ip: u128 = u128::from_be_bytes(match byte_chunks.get(index) {
        Some(a) => match a[16..32].try_into() {
            Ok(a) => a,
            Err(e) => {
                return Err(Web3Error::BadInput(format!(
                    "Why cant we get [u8; 16]? {byte_chunks:?}. Error is {e}"
                )))
            }
        },
        None => {
            return Err(Web3Error::BadInput(format!(
                "Cant meship with byte chunks {byte_chunks:?}"
            )))
        }
    });

    if mesh_ip == 0 {
        error!("Received a null entry! {:?}", byte_chunks);
        return Err(Web3Error::BadInput(format!(
            "Recived a null output {byte_chunks:?}."
        )));
    }

    let mesh_ip = IpAddr::V6(Ipv6Addr::from(mesh_ip));

    // 2nd entry is the wg key as Uint256
    index += 1;
    let wg_public_key: WgKey = Uint256::from_be_bytes(match byte_chunks.get(index) {
        Some(a) => a,
        None => {
            return Err(Web3Error::BadInput(format!(
                "Cant wg key with byte chunks {byte_chunks:?}"
            )))
        }
    })
    .into();

    // 3rd entry is the eth address
    index += 1;
    let eth_address: Address = match Address::from_slice(match byte_chunks.get(index) {
        Some(a) => &a[12..],
        None => {
            return Err(Web3Error::BadInput(format!(
                "Cant eth address with byte chunks {byte_chunks:?}"
            )))
        }
    }) {
        Ok(a) => a,
        Err(e) => {
            return Err(Web3Error::BadInput(format!(
                "Cant parse eth address with byte chunks {byte_chunks:?} with err {e}"
            )))
        }
    };

    Ok(Identity {
        mesh_ip,
        eth_address,
        wg_public_key,
        nickname: None,
    })
}

pub fn parse_identity_array_abi(bytes: Vec<u8>) -> Result<Vec<Identity>, Web3Error> {
    /*
    0000000000000000000000000000000000000000000000000000000000000020  // Array indexing
    0000000000000000000000000000000000000000000000000000000000000003  // Number of entries
    00000000000000000000000000000000412fdf2d26160b5f693389e60ac738ae  // First array entry
    412fdf2d26160b5f693389e60ac738ae3a98f1225eaf34999352dedae2b63741
    0000000000000000000000003735839458240fa26adacd11e1077dc835fc48fb
    00000000000000000000000000000000a92c2e36d844bc28d2c28c00de51f75b  // Second array entry
    a92c2e36d844bc28d2c28c00de51f75bf80411beb72c6e613301fa6887562906
    00000000000000000000000013911fdc06e18c5400e3c0e392a297148475dda6
    000000000000000000000000000000008ee6dfe50c499fd53ff15813cbd1cd20  // Third array entry
    8ee6dfe50c499fd53ff15813cbd1cd2053cdbea2045a60d789ab5c7c1f0e7270
    0000000000000000000000009074d62fbd0480730671c4404dbfaaff0090457c


    One entry array:
    0000000000000000000000000000000000000000000000000000000000000020 // Array index
    0000000000000000000000000000000000000000000000000000000000000001 // Number of entries in array
    000000000000000000000000000000002af12da887c83a605f53c3d29b80475d // Identity data
    2af12da887c83a605f53c3d29b80475d5c529ce02b567316ae19c99ca3f51187
    000000000000000000000000399f0f5f436513f8c3773f016eed931361c8f297
    */

    let mut ret = vec![];
    let byte_chunks = to_evm_words(bytes);

    // An empty list, the first word has a type identifier, the second is empty
    if byte_chunks.len() == 2 {
        return Ok(vec![]);
    }

    // A valid array with 1 entry has 5 lines. An empty list has 2 lines
    if byte_chunks.len() < 5 {
        return Err(Web3Error::BadInput(format!(
            "Received byte chunks: {byte_chunks:?}"
        )));
    }

    let mut index = 1;
    let arr_len = match usize::from_str_radix(
        &bytes_to_hex_str(match byte_chunks.get(index) {
            Some(a) => a,
            None => {
                return Err(Web3Error::BadInput(format!(
                    "Received invalid index {index} byte chunks: {byte_chunks:?}"
                )))
            }
        }),
        16,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Cannot parse array len {}", e);
            return Err(e.into());
        }
    };

    index += 1;
    for _ in 0..arr_len {
        let bytes_to_pass = match byte_chunks.get(index..(index + 3)) {
            Some(a) => a,
            None => {
                return Err(Web3Error::BadInput(format!(
                    "Received invalid index {} byte chunks: {byte_chunks:?}",
                    index + 3
                )))
            }
        };
        let bytes_to_pass: Vec<Vec<u8>> = bytes_to_pass.iter().map(|i| i.to_vec()).collect();

        // Increment index for next iteration
        index += 3;

        ret.push(match parse_identity_abi(bytes_to_pass) {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "Error parsing idenity for byte chunks {:?} with {}",
                    byte_chunks[index..].to_vec(),
                    e
                );
                continue;
            }
        });
    }

    Ok(ret)
}

pub fn parse_exit_identity_array_abi(bytes: Vec<u8>) -> Result<Vec<ExitIdentity>, Web3Error> {
    /* Exit Identity array, containing two allowed region entries and one system chain entry
        One entry
    0000000000000000000000000000000000000000000000000000000000000020    // Array Index
    0000000000000000000000000000000000000000000000000000000000000001    // Entries in array
    0000000000000000000000000000000000000000000000000000000000000020    // Start of data of array?
    00000000000000000000000000000000d5ce8b4de8234789da53bddd707db3d5    // Mesh ip
    d5ce8b4de8234789da53bddd707db3d589e00b5fce9d9b5f68cc7f3550d8944f    // wg key
    000000000000000000000000351634dbb20142a7f5ab996b96f71795e35e93f3    // eth address
    000000000000000000000000000000000000000000000000000000000000130b    // Registration pot
    000000000000000000000000000000000000000000000000000000000000ea5e    // wg listen port

    00000000000000000000000000000000000000000000000000000000000000a0    //
    0000000000000000000000000000000000000000000000000000000000000100    //
    0000000000000000000000000000000000000000000000000000000000000002    // Number of entries in region array
    0000000000000000000000000000000000000000000000000000000000000007    // First entry of regions array
    0000000000000000000000000000000000000000000000000000000000000008    // Second entry
    0000000000000000000000000000000000000000000000000000000000000001    // Number of entries in payment array
    0000000000000000000000000000000000000000000000000000000000000004    // First entry of payment array

        Two entries
    0000000000000000000000000000000000000000000000000000000000000020    // Array Indexing
    0000000000000000000000000000000000000000000000000000000000000002    // Number of entries in array
    0000000000000000000000000000000000000000000000000000000000000040    // Start of first entry
    0000000000000000000000000000000000000000000000000000000000000180    // Start of second entry

    000000000000000000000000000000009de79d5506c2d55aba50edaee3b9579f    // First entry mesh ip
    9de79d5506c2d55aba50edaee3b9579f75acd14a63c551c5595bbf66d074a379    // wg key
    000000000000000000000000dcc1137e069cab580fd4199ac682a81978e39bc5    // eth address
    000000000000000000000000000000000000000000000000000000000000130b    // Registration pot
    000000000000000000000000000000000000000000000000000000000000ea5e    // wg listen port

    00000000000000000000000000000000000000000000000000000000000000a0    // Position of first array len from start of array
    0000000000000000000000000000000000000000000000000000000000000100    // Postion of second array len form start
    0000000000000000000000000000000000000000000000000000000000000002    // Number of entries in regions array
    0000000000000000000000000000000000000000000000000000000000000007    // Regions array entry
    0000000000000000000000000000000000000000000000000000000000000008    // region array entry
    0000000000000000000000000000000000000000000000000000000000000001    // Number of entries in payment array
    0000000000000000000000000000000000000000000000000000000000000004    // payment entry

    000000000000000000000000000000007bbab1ac348ee5be29ac57e2c3e052a1    // Second array entry mesh ip
    7bbab1ac348ee5be29ac57e2c3e052a164bc756beb5063743399fd08fdb6c5bb
    000000000000000000000000a970fab4bff2530005fdb65eeb4fe88d228aa9f8
    000000000000000000000000000000000000000000000000000000000000130b    // Registration pot
    000000000000000000000000000000000000000000000000000000000000ea5e    // wg listen port

    00000000000000000000000000000000000000000000000000000000000000a0
    00000000000000000000000000000000000000000000000000000000000000e0
    0000000000000000000000000000000000000000000000000000000000000001    // Num entry in regions
    0000000000000000000000000000000000000000000000000000000000000006    // Region entry
    0000000000000000000000000000000000000000000000000000000000000001    // Num entries in payment
    0000000000000000000000000000000000000000000000000000000000000003    // Payment entry
    */
    let byte_chunks = to_evm_words(bytes);

    // An empty list, the first word has a type identifier, the second is empty
    if byte_chunks.len() == 2 {
        return Ok(vec![]);
    }

    // A valid array with 1 entry will have atleast 11 lines
    if byte_chunks.len() < 11 {
        return Err(Web3Error::BadInput(format!(
            "Empty or invalid array: {byte_chunks:?}"
        )));
    }

    // Get number of entries in the array
    let num_entries: usize = usize::from_be_bytes(match byte_chunks[1][24..WORD_SIZE].try_into() {
        Ok(a) => a,
        Err(e) => {
            let msg = format!("Cannot parse array len with {}", e);
            error!("{}", msg);
            return Err(Web3Error::BadInput(msg));
        }
    });

    let mut ret = vec![];
    // pass in each entry byte chunk to individual entry parser
    let index = 2;
    for i in index..index + num_entries {
        if i >= byte_chunks.len() {
            let msg = "Encoded array length longer than data".to_string();
            error!("{}", msg);
            return Err(Web3Error::BadInput(msg));
        }
        let next_index_pos: Uint256 = Uint256::from_be_bytes(&byte_chunks[i]) / WORD_SIZE.into();
        let next_index_pos: usize = usize::from_be_bytes(
            match next_index_pos.to_be_bytes()[24..WORD_SIZE].try_into() {
                Ok(a) => a,
                Err(e) => {
                    error!("Cannot get next array entry with {}", e);
                    return Err(Web3Error::BadInput(format!(
                        "Cannot get next array entry with {}",
                        e
                    )));
                }
            },
        );

        match parse_exit_identity_abi(match byte_chunks.get(index + next_index_pos..) {
            Some(a) => a.iter().map(|i| i.to_vec()).collect(),
            None => {
                error!(
                    "Invalid indexing? trying to get {}, with byte chunks {:?}",
                    index + next_index_pos,
                    byte_chunks
                );
                continue;
            }
        }) {
            Ok(a) => ret.push(a),
            Err(e) => {
                error!("Getting an entry failed! Continuing: {}", e);
            }
        }
    }

    Ok(ret)
}

// Parses a single entry of an abi encoded ExitIdentity
pub fn parse_exit_identity_abi(byte_chunks: Vec<Vec<u8>>) -> Result<ExitIdentity, Web3Error> {
    /*Expected input:
    000000000000000000000000000000007bbab1ac348ee5be29ac57e2c3e052a1    // Second array entry mesh ip
    7bbab1ac348ee5be29ac57e2c3e052a164bc756beb5063743399fd08fdb6c5bb
    000000000000000000000000a970fab4bff2530005fdb65eeb4fe88d228aa9f8
    000000000000000000000000000000000000000000000000000000000000130b    // Registration pot
    000000000000000000000000000000000000000000000000000000000000ea5e    // wg listen port

    00000000000000000000000000000000000000000000000000000000000000a0
    00000000000000000000000000000000000000000000000000000000000000e0
    0000000000000000000000000000000000000000000000000000000000000001    // Num entry in regions
    0000000000000000000000000000000000000000000000000000000000000006    // Region entry
    0000000000000000000000000000000000000000000000000000000000000001    // Num entries in payment
    0000000000000000000000000000000000000000000000000000000000000003    // Payment entry
    */

    // The smallest entry has 7 lines, with two empty arrays
    if byte_chunks.len() < 9 {
        return Err(Web3Error::BadInput(format!(
            "Received byte chunks: {byte_chunks:?}"
        )));
    }

    // Parse first 3 entries to get identity struct. Already validated length
    let exit_id = parse_identity_abi(byte_chunks[0..3].to_vec())?;

    let registration_port: Uint256 = Uint256::from_be_bytes(&byte_chunks[3]);
    let registration_port: u16 = u16::from_be_bytes(
        match registration_port.to_be_bytes()[30..WORD_SIZE].try_into() {
            Ok(a) => a,
            Err(e) => {
                error!("Cannot get registration port with {}", e);
                return Err(Web3Error::BadInput(format!(
                    "Cannot get registration port with {}",
                    e
                )));
            }
        },
    );

    let wg_exit_listen_port: Uint256 = Uint256::from_be_bytes(&byte_chunks[4]);
    let wg_exit_listen_port: u16 = u16::from_be_bytes(
        match wg_exit_listen_port.to_be_bytes()[30..WORD_SIZE].try_into() {
            Ok(a) => a,
            Err(e) => {
                error!("Cannot get wg_exit port with {}", e);
                return Err(Web3Error::BadInput(format!(
                    "Cannot get wg_exit port with {}",
                    e
                )));
            }
        },
    );

    let regions_start: Uint256 = Uint256::from_be_bytes(&byte_chunks[5]) / WORD_SIZE.into();
    let regions_start: usize = usize::from_be_bytes(
        match regions_start.to_be_bytes()[24..WORD_SIZE].try_into() {
            Ok(a) => a,
            Err(e) => {
                error!("Cannot get region array start with {}", e);
                return Err(Web3Error::BadInput(format!(
                    "Cannot get region array start with {}",
                    e
                )));
            }
        },
    );

    let payment_start: Uint256 = Uint256::from_be_bytes(&byte_chunks[6]) / WORD_SIZE.into();
    let payment_start: usize = usize::from_be_bytes(
        match payment_start.to_be_bytes()[24..WORD_SIZE].try_into() {
            Ok(a) => a,
            Err(e) => {
                error!("Cannot get region array start with {}", e);
                return Err(Web3Error::BadInput(format!(
                    "Cannot get region array start with {}",
                    e
                )));
            }
        },
    );

    let regions_arr_len: usize = usize::from_be_bytes(match byte_chunks.get(regions_start) {
        Some(a) => match a[24..WORD_SIZE].try_into() {
            Ok(res) => res,
            Err(e) => {
                return Err(Web3Error::BadInput(format!(
                    "Cannot get region array slice {}",
                    e
                )));
            }
        },
        None => {
            return Err(Web3Error::BadInput(format!(
                "Why cant we get region array len from slice {byte_chunks:?}"
            )))
        }
    });

    let payment_arr_len: usize = usize::from_be_bytes(match byte_chunks.get(payment_start) {
        Some(a) => match a[24..WORD_SIZE].try_into() {
            Ok(res) => res,
            Err(e) => {
                return Err(Web3Error::BadInput(format!(
                    "Cannot get payment array slice {}",
                    e
                )));
            }
        },
        None => {
            return Err(Web3Error::BadInput(format!(
                "Why cant we get payment array len from slice {byte_chunks:?}"
            )))
        }
    });

    // Validate length here to avoid tedious error handling later
    // Total len should be: 3 (3 id struct entries) + 2 (struct len localtion pointers) + 2 (len value of each array) +2(ports)
    // + len of region array + len of payment array

    if byte_chunks.len() < 9 + regions_arr_len + payment_arr_len {
        let msg = format!("Length validation failed, parsed incorrectly, expected length {}, got lent {}. Slice {byte_chunks:?}", 7+regions_arr_len+payment_arr_len, byte_chunks.len());
        error!("{}", msg);
        return Err(Web3Error::BadInput(msg));
    }

    let mut reg_arr: HashSet<Regions> = HashSet::new();
    for region in byte_chunks
        .iter()
        .take(regions_arr_len + regions_start + 1)
        .skip(regions_start + 1)
    {
        let region_code = region[WORD_SIZE - 1];
        reg_arr.insert(region_code.into());
    }

    let mut payment_arr: HashSet<SystemChain> = HashSet::new();
    for code in byte_chunks
        .iter()
        .take(payment_arr_len + payment_start + 1)
        .skip(payment_start + 1)
    {
        let system_chain_code = code[WORD_SIZE - 1];
        payment_arr.insert(system_chain_code.into());
    }
    Ok(ExitIdentity {
        mesh_ip: exit_id.mesh_ip,
        wg_key: exit_id.wg_public_key,
        eth_addr: exit_id.eth_address,
        registration_port,
        wg_exit_listen_port,
        allowed_regions: reg_arr,
        payment_types: payment_arr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{
        distributions::{Distribution, Uniform},
        rngs::ThreadRng,
        thread_rng, Rng,
    };
    use std::time::Instant;

    /// How long we fuzz the input
    const FUZZ_TIME: Duration = Duration::from_secs(30);

    fn get_fuzz_bytes(rng: &mut ThreadRng) -> Vec<Vec<u8>> {
        let outer_range = Uniform::from(1..200_000);
        let inner_range = Uniform::from(1..10_000);
        let outer_size: usize = outer_range.sample(rng);
        let mut fuzz_bytes = Vec::with_capacity(outer_size);
        for _ in 0..outer_size {
            let inner_size: usize = inner_range.sample(rng);
            let mut inner_bytes = Vec::with_capacity(inner_size);

            for _ in 0..inner_size {
                inner_bytes.push(rng.gen());
            }

            fuzz_bytes.push(inner_bytes);
        }
        fuzz_bytes
    }

    fn get_fuzz_bytes_flat(rng: &mut ThreadRng) -> Vec<u8> {
        let range = Uniform::from(1..200_000);
        let size: usize = range.sample(rng);
        let event_bytes: Vec<u8> = (0..size)
            .map(|_| {
                let val: u8 = rng.gen();
                val
            })
            .collect();
        event_bytes
    }

    #[test]
    fn fuzz_pase_identity_abi() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let bytes = get_fuzz_bytes(&mut rng);

            let res = parse_identity_abi(bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn fuzz_pase_identity_array_abi() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let bytes = get_fuzz_bytes_flat(&mut rng);

            let res = parse_identity_array_abi(bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn fuzz_pase_exit_identity_array() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let bytes = get_fuzz_bytes(&mut rng);

            let res = parse_exit_identity_abi(bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn fuzz_pase_exit_identity_array_abi() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let bytes = get_fuzz_bytes_flat(&mut rng);

            let res = parse_exit_identity_array_abi(bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn test_parse_abi() {
        use clarity::utils::hex_str_to_bytes;
        // test parsing an abi struct with various input types
        let id = Identity {
            mesh_ip: "e0b1:bf22:64ae:8e91:cc4e:5a1b:a0ef:8495".parse().unwrap(),
            eth_address: "0x090502B2fd4dE198554511C0a6fd4da5D41E7C49"
                .parse()
                .unwrap(),
            wg_public_key: "4LG/ImSujpHMTloboO+ElV7wgn2LRsUnZzoeZGMFO2Q="
                .parse()
                .unwrap(),
            nickname: None,
        };
        let bytes = "\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64\
    000000000000000000000000090502b2fd4de198554511c0a6fd4da5d41e7c49";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert_eq!(parse_identity_abi(to_evm_words(bytes)).unwrap(), id);

        // invalid input
        let bytes = "\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64\
    000000000000000000000000090502b2fd4de198554511c0a6fd4da5d41e7c49";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(parse_identity_abi(to_evm_words(bytes)).is_err());

        // invalid input
        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000000\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(parse_identity_abi(to_evm_words(bytes)).is_err());

        // invalid input
        let bytes = "\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(parse_identity_abi(to_evm_words(bytes)).is_err());
    }

    #[test]
    fn test_parse_abi_array() {
        use clarity::utils::hex_str_to_bytes;
        // empty string
        let bytes = "";
        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(parse_identity_array_abi(bytes).is_err());

        // valid entry
        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000020\
    0000000000000000000000000000000000000000000000000000000000000003\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64\
    000000000000000000000000090502b2fd4de198554511c0a6fd4da5d41e7c49\
    00000000000000000000000000000000b1b3443a5b70425797fa4e7d4a4f78fd\
    b1b3443a5b70425797fa4e7d4a4f78fd432f982373bdd879bda9c1a3508bbd01\
    0000000000000000000000003a7090f876ae036cfedefb5359c078032b968458\
    000000000000000000000000000000003ef17d634ede32665e35816eda438a84\
    3ef17d634ede32665e35816eda438a84aeeccf32f53327538f66d6ce859b2d23\
    000000000000000000000000d9474fa480aca506f14c439a738e6362bb66f654";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(parse_identity_array_abi(bytes.clone()).is_ok());
        assert!(parse_identity_array_abi(bytes).unwrap().len() == 3);

        // Second entry invalid
        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000020\
    0000000000000000000000000000000000000000000000000000000000000003\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64\
    000000000000000000000000090502b2fd4de198554511c0a6fd4da5d41e7c49\
    0000000000000000000000000000000000000000000000000000000000000000\
    b1b3443a5b70425797fa4e7d4a4f78fd432f982373bdd879bda9c1a3508bbd01\
    0000000000000000000000003a7090f876ae036cfedefb5359c078032b968458\
    000000000000000000000000000000003ef17d634ede32665e35816eda438a84\
    3ef17d634ede32665e35816eda438a84aeeccf32f53327538f66d6ce859b2d23\
    000000000000000000000000d9474fa480aca506f14c439a738e6362bb66f654";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(parse_identity_array_abi(bytes.clone()).is_ok());
        assert!(parse_identity_array_abi(bytes).unwrap().len() == 2);

        // No valid entries
        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000020\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000000\
    ";
        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(parse_identity_array_abi(bytes.clone()).is_err());
    }

    #[test]
    fn test_parse_exit_id_abi() {
        use clarity::utils::hex_str_to_bytes;

        let bytes = "\
    000000000000000000000000000000007bbab1ac348ee5be29ac57e2c3e052a1\
    7bbab1ac348ee5be29ac57e2c3e052a164bc756beb5063743399fd08fdb6c5bb\
    000000000000000000000000a970fab4bff2530005fdb65eeb4fe88d228aa9f8\
    000000000000000000000000000000000000000000000000000000000000130b\
    000000000000000000000000000000000000000000000000000000000000ea5e\
    00000000000000000000000000000000000000000000000000000000000000e0\
    0000000000000000000000000000000000000000000000000000000000000120\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000006\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000003";
        let bytes = hex_str_to_bytes(bytes).unwrap();

        let res = parse_exit_identity_abi(to_evm_words(bytes)).unwrap();
        assert!(res.allowed_regions.contains(&Regions::Colombia));
        assert!(res.payment_types.contains(&SystemChain::Sepolia));
        assert_eq!(res.allowed_regions.len(), 1);
        assert_eq!(res.payment_types.len(), 1);

        let bytes = "\
    00000000000000000000000000000000d5ce8b4de8234789da53bddd707db3d5\
    d5ce8b4de8234789da53bddd707db3d589e00b5fce9d9b5f68cc7f3550d8944f\
    000000000000000000000000351634dbb20142a7f5ab996b96f71795e35e93f3\
    000000000000000000000000000000000000000000000000000000000000130b\
    000000000000000000000000000000000000000000000000000000000000ea5e\
    00000000000000000000000000000000000000000000000000000000000000e0\
    0000000000000000000000000000000000000000000000000000000000000140\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000005\
    0000000000000000000000000000000000000000000000000000000000000006\
    0000000000000000000000000000000000000000000000000000000000000003\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000004";
        let bytes = hex_str_to_bytes(bytes).unwrap();

        let res = parse_exit_identity_abi(to_evm_words(bytes)).unwrap();
        assert_eq!(res.allowed_regions.len(), 2);
        assert_eq!(res.payment_types.len(), 3);

        // Valid input with a bunch of cruft at the end
        let bytes = "\
    00000000000000000000000000000000d5ce8b4de8234789da53bddd707db3d5\
    d5ce8b4de8234789da53bddd707db3d589e00b5fce9d9b5f68cc7f3550d8944f\
    000000000000000000000000351634dbb20142a7f5ab996b96f71795e35e93f3\
    000000000000000000000000000000000000000000000000000000000000130b\
    000000000000000000000000000000000000000000000000000000000000ea5e\
    00000000000000000000000000000000000000000000000000000000000000e0\
    0000000000000000000000000000000000000000000000000000000000000140\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000003\
    0000000000000000000000000000000000000000000000000000000000000004\
    0000000000000000000000000000000000000000000000000000000000000003\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000004\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000002";
        let bytes = hex_str_to_bytes(bytes).unwrap();

        let res = parse_exit_identity_abi(to_evm_words(bytes)).unwrap();
        print!("{:?}", res);
    }

    #[test]
    fn test_exit_array_abi() {
        use clarity::utils::hex_str_to_bytes;

        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000020\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000040\
    0000000000000000000000000000000000000000000000000000000000000180\
    000000000000000000000000000000009de79d5506c2d55aba50edaee3b9579f\
    9de79d5506c2d55aba50edaee3b9579f75acd14a63c551c5595bbf66d074a379\
    000000000000000000000000dcc1137e069cab580fd4199ac682a81978e39bc5\
    000000000000000000000000000000000000000000000000000000000000130b\
    000000000000000000000000000000000000000000000000000000000000ea5e\
    00000000000000000000000000000000000000000000000000000000000000e0\
    0000000000000000000000000000000000000000000000000000000000000140\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000005\
    0000000000000000000000000000000000000000000000000000000000000006\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000004\
    000000000000000000000000000000007bbab1ac348ee5be29ac57e2c3e052a1\
    7bbab1ac348ee5be29ac57e2c3e052a164bc756beb5063743399fd08fdb6c5bb\
    000000000000000000000000a970fab4bff2530005fdb65eeb4fe88d228aa9f8\
    000000000000000000000000000000000000000000000000000000000000130b\
    000000000000000000000000000000000000000000000000000000000000ea5e\
    00000000000000000000000000000000000000000000000000000000000000e0\
    0000000000000000000000000000000000000000000000000000000000000120\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000006\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000003";
        let bytes = hex_str_to_bytes(bytes).unwrap();

        let res = parse_exit_identity_array_abi(bytes).unwrap();
        println!("{:?}", res);
    }
}
