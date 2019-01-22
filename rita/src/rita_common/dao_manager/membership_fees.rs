use super::*;

fn get_dao_fee(dao_address: Address) {
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node);
    let payment_settings = SETTING.get_payment();
    let our_address = payment_settings.eth_address.expect("No address!");
    drop(payment_settings);
    let ip = match SETTING.get_network().mesh_ip.expect("No ip!") {
        IpAddr::V6(ip) => ip.octets(),
        _ => {
            error!("MeshIP must be ipv6 and is not!");
            return;
        }
    };
    trace!("Getting DAO fee from {}", full_node);
    let get_per_block_fee = [0x60, 0xe3, 0x47, 0x17];
    let mut call_data = Vec::new();
    for byte in get_per_block_fee.iter() {
        call_data.push(*byte);
    }
    for byte in ip.iter() {
        call_data.push(*byte);
    }

    // since this is a read-only request so lots of values are None
    let tx = TransactionRequest {
        from: our_address,
        to: Some(dao_address),
        gas: None,
        gas_price: None,
        value: None,
        data: Some(Data(call_data)),
        nonce: None,
    };

    let res = web3.eth_call(tx).then(move |response| match response {
        Ok(val) => {
            assert!(val.len() == 32);
            let fee: Uint256 = val[0..32].into();

            Ok(())
        }
        Err(e) => {
            warn!("Get Membership Web3 call failed {:?}", e);
            Ok(())
        }
    });
    Arbiter::spawn(res);
}
