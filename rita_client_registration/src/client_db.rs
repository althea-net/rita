use std::{net::IpAddr, time::Duration};

use althea_types::{Identity, WgKey};
use clarity::{
    abi::{encode_call, AbiToken},
    utils::bytes_to_hex_str,
    Address, PrivateKey, Uint256,
};
use web30::{
    client::Web3,
    jsonrpc::error::Web3Error,
    types::{SendTxOption, TransactionRequest},
};

use tokio::time::timeout as future_timeout;

pub const WORD_SIZE: usize = 32;

pub async fn get_all_regsitered_clients(
    web30: &Web3,
    requester_address: Address,
    contract: Address,
) -> Result<Vec<Identity>, Web3Error> {
    let payload = encode_call("get_all_registered_users()", &[])?;
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
        "get_registered_client_with_wg_key(string)",
        &[AbiToken::String(key.to_string())],
    )?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(requester_address, contract, payload),
            None,
        )
        .await?;

    // Parse resulting bytes
    parse_identity_abi(res)
}

pub async fn get_registered_client_using_ethkey(
    key: Address,
    requester_address: Address,
    contract: Address,
    web30: &Web3,
) -> Result<Identity, Web3Error> {
    let payload = encode_call(
        "get_registered_client_with_eth_addr(address)",
        &[key.into()],
    )?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(requester_address, contract, payload),
            None,
        )
        .await?;

    // Parse resulting bytes
    parse_identity_abi(res)
}

pub async fn get_registered_client_using_meship(
    ip: IpAddr,
    requester_address: Address,
    contract: Address,
    web30: &Web3,
) -> Result<Identity, Web3Error> {
    let payload = encode_call(
        "get_registered_client_with_mesh_ip(string)",
        &[AbiToken::String(ip.to_string())],
    )?;
    let res = web30
        .simulate_transaction(
            TransactionRequest::quick_tx(requester_address, contract, payload),
            None,
        )
        .await?;

    // Parse resulting bytes
    parse_identity_abi(res)
}

pub async fn add_client_to_registered_list(
    web30: &Web3,
    user: Identity,
    contract: Address,
    sender_private_key: PrivateKey,
    wait_timeout: Option<Duration>,
    options: Vec<SendTxOption>,
) -> Result<Uint256, Web3Error> {
    let tx_hash = web30
        .send_transaction(
            contract,
            encode_call(
                "add_registered_user((string,string,address))",
                &[AbiToken::Struct(vec![
                    AbiToken::String(user.mesh_ip.to_string()),
                    AbiToken::String(user.wg_public_key.to_string()),
                    AbiToken::Address(user.eth_address),
                ])],
            )?,
            0u32.into(),
            sender_private_key,
            options,
        )
        .await?;

    if let Some(timeout) = wait_timeout {
        future_timeout(timeout, web30.wait_for_transaction(tx_hash, timeout, None)).await??;
    }

    Ok(tx_hash)
}

fn parse_identity_abi_internal(byte_chunks: Vec<&[u8]>) -> Result<Identity, Web3Error> {
    // 3th entry is the address chunk
    let eth_address = match Address::from_slice(&byte_chunks[2][12..]) {
        Ok(a) => a,
        Err(e) => {
            error!("Error parse eth address chunk: {}", e);
            return Err(e.into());
        }
    };

    // length of mesh ip
    let mut index = 3;
    let mut mesh_len = match usize::from_str_radix(&bytes_to_hex_str(byte_chunks[index]), 16) {
        Ok(a) => a,
        Err(e) => {
            error!("Error parsing len of mesh ip: {}", e);
            return Err(e.into());
        }
    };
    let mut mesh_bytes: Vec<u8> = vec![];
    loop {
        index += 1;
        let curr_word = byte_chunks[index];
        if mesh_len >= WORD_SIZE {
            mesh_bytes.extend(curr_word);
            mesh_len -= WORD_SIZE
        } else {
            mesh_bytes.extend(&(byte_chunks[index])[..mesh_len]);
            break;
        }
    }

    let mesh_ip = match String::from_utf8(mesh_bytes) {
        Ok(a) => a,
        Err(e) => {
            error!("Error parsing mesh ip bytes: {}", e);
            return Err(Web3Error::BadInput(format!(
                "Error parsing mesh ip bytes: {}",
                e
            )));
        }
    };

    let mesh_ip: IpAddr = match mesh_ip.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Cannot parse mesh ip {} with {}", mesh_ip, e);
            return Err(Web3Error::BadInput(format!(
                "Cannot parse mesh ip {} with {}",
                mesh_ip, e
            )));
        }
    };

    // Find length of wg key
    index += 1;
    let mut wgkey_len = match usize::from_str_radix(&bytes_to_hex_str(byte_chunks[index]), 16) {
        Ok(a) => a,
        Err(e) => {
            error!("Error parsing len of wg key: {}", e);
            return Err(e.into());
        }
    };
    let mut wgkey_bytes: Vec<u8> = vec![];
    loop {
        index += 1;
        let curr_word = byte_chunks[index];
        if wgkey_len >= WORD_SIZE {
            wgkey_bytes.extend(curr_word);
            wgkey_len -= WORD_SIZE
        } else {
            wgkey_bytes.extend(&(byte_chunks[index])[..wgkey_len]);
            break;
        }
    }

    let wg_key = match String::from_utf8(wgkey_bytes) {
        Ok(a) => a,
        Err(e) => {
            error!("Error parsing wg key bytes: {}", e);
            return Err(Web3Error::BadInput(format!(
                "Error parsing wg key bytes: {}",
                e
            )));
        }
    };

    let wg_public_key: WgKey = match wg_key.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Cannot parse wg key {} with {}", wg_key, e);
            return Err(Web3Error::BadInput(format!(
                "Cannot parse wg key {} with {}",
                wg_key, e
            )));
        }
    };

    Ok(Identity {
        mesh_ip,
        eth_address,
        wg_public_key,
        nickname: None,
    })
}

pub fn parse_identity_abi(bytes: Vec<u8>) -> Result<Identity, Web3Error> {
    /* Expected input from contract call
    0000000000000000000000000000000000000000000000000000000000000020 // Location of address information
    0000000000000000000000000000000000000000000000000000000000000060 // Location of the actual address
    00000000000000000000000000000000000000000000000000000000000000a0 // Location of first dynamic value information
    00000000000000000000000002ad6b480dfed806c63a0839c6f1f3136c5fd515 // Address bytes
    000000000000000000000000000000000000000000000000000000000000000a // Length of first string in bytes a = 10, so 20 characters
    666430303a3a3133333700000000000000000000000000000000000000000000 // String bytes, padding on the right
    000000000000000000000000000000000000000000000000000000000000002c // Length of second string in bytes 2c = 44, so 88 characters
    7350744e475162795070437371534b443650626e666c42316c49554364323539 // String bytes
    566864306d4a664a65476f3d0000000000000000000000000000000000000000 // String bytes continued, padding on the right
    */

    let byte_chunks: Vec<&[u8]> = bytes.chunks(WORD_SIZE).collect();
    // Remove start offset info
    parse_identity_abi_internal(byte_chunks[1..].to_vec())
}

pub fn parse_identity_array_abi(bytes: Vec<u8>) -> Result<Vec<Identity>, Web3Error> {
    /*
    Two entry array:
    0000000000000000000000000000000000000000000000000000000000000020 // Info offset
    0000000000000000000000000000000000000000000000000000000000000002 // Entries in array
    0000000000000000000000000000000000000000000000000000000000000040 // Offset to first id struct from start after metadata
    0000000000000000000000000000000000000000000000000000000000000140 // Offset to second id struct from start after metadata

    0000000000000000000000000000000000000000000000000000000000000060 // Offset to first dynamic entry
    00000000000000000000000000000000000000000000000000000000000000a0 // Offset to second dynamic entry
    00000000000000000000000002ad6b480dfed806c63a0839c6f1f3136c5fd515 // Address
    000000000000000000000000000000000000000000000000000000000000000a // Len of first dynamic entry (mesh ip)
    666430303a3a3133333700000000000000000000000000000000000000000000 // Mesh ip
    000000000000000000000000000000000000000000000000000000000000002c // Len of second dynamic entry (wgkey)
    7350744e475162795070437371534b443650626e666c42316c49554364323539 // wg key
    566864306d4a664a65476f3d0000000000000000000000000000000000000000 // wg key

    0000000000000000000000000000000000000000000000000000000000000060 // Second id struct, same as above
    00000000000000000000000000000000000000000000000000000000000000a0
    0000000000000000000000001994a73f79f9648d4a8064d9c0f221fb1007fd2f
    000000000000000000000000000000000000000000000000000000000000000f
    666430303a3a313434373a313434370000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000000000002c
    5968796a2b434b5a6279454b65612f39686449466a65393879633543756b7431
    50627130715742344171773d0000000000000000000000000000000000000000


    One entry array:
    0000000000000000000000000000000000000000000000000000000000000020
    0000000000000000000000000000000000000000000000000000000000000001
    0000000000000000000000000000000000000000000000000000000000000020
    0000000000000000000000000000000000000000000000000000000000000060
    00000000000000000000000000000000000000000000000000000000000000a0
    00000000000000000000000002ad6b480dfed806c63a0839c6f1f3136c5fd515
    000000000000000000000000000000000000000000000000000000000000000a
    666430303a3a3133333700000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000000000002c
    7350744e475162795070437371534b443650626e666c42316c49554364323539
    566864306d4a664a65476f3d0000000000000000000000000000000000000000
    */

    let mut ret = vec![];
    let byte_chunks: Vec<&[u8]> = bytes.chunks(WORD_SIZE).collect();

    let mut index = 1;
    let arr_len = match usize::from_str_radix(&bytes_to_hex_str(byte_chunks[index]), 16) {
        Ok(a) => a,
        Err(e) => {
            error!("Cannot parse array len {}", e);
            return Err(e.into());
        }
    };

    index += 1;
    for i in 0..arr_len {
        let arr_start_offset =
            match usize::from_str_radix(&bytes_to_hex_str(byte_chunks[index + i]), 16) {
                Ok(a) => a / WORD_SIZE,
                Err(e) => {
                    error!(
                        "Cannot parse array offset: {:?} with {}",
                        byte_chunks[index + 1],
                        e
                    );
                    continue;
                }
            };

        ret.push(
            match parse_identity_abi_internal(byte_chunks[(index + arr_start_offset)..].to_vec()) {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        "Error parsing idenity for byte chunks {:?} with {}",
                        byte_chunks[(index + arr_start_offset)..].to_vec(),
                        e
                    );
                    continue;
                }
            },
        );
    }

    Ok(ret)
}
