use super::*;

pub fn withdraw(path: Path<(Address, u64)>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let address = path.0;
    let amount = path.1;
    debug!("/withdraw/{:#x}/{} hit", address, amount);

    let full_node = get_web3_server();
    let web3 = Web3Client::new(&full_node);

    let tx = Transaction {
        nonce: Uint256::from_str_radix("00", 16).unwrap(),
        // TODO: replace with sane defaults
        gas_price: "1000000000000".parse().unwrap(),
        gas_limit: "21000".parse().unwrap(),
        to: address,
        value: amount.into(),
        data: Vec::new(),
        signature: None,
    };
    // TODO figure out the whole network id thing
    let transaction_signed = tx.sign(
        &SETTING
            .get_payment()
            .eth_private_key
            .expect("No private key configured!"),
        None,
    );

    let transaction_bytes = match transaction_signed.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::from_u16(504u16).unwrap())
                    .into_builder()
                    .json(format!("Transaction to bytes failed! {:?}", e)),
            ))
        }
    };

    let transaction_status = web3.eth_send_raw_transaction(transaction_bytes);

    Box::new(transaction_status.then(|result| {
        match result {
            Ok(tx_id) => Box::new(future::ok(
                HttpResponse::Ok().json(format!("tx-id:{}", tx_id)),
            )),
            Err(e) => Box::new(future::ok(
                HttpResponse::new(StatusCode::from_u16(504u16).unwrap())
                    .into_builder()
                    .json(format!("Full node failed to send transaction! {:?}", e)),
            )),
        }
    }))
}
