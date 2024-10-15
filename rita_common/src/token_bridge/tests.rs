use crate::token_bridge::xdai_bridge::*;
use crate::token_bridge::*;
use auto_bridge::default_bridge_addresses;
use auto_bridge::TokenBridge;
use auto_bridge::{encode_relaytokens, get_relay_message_hash};
use clarity::Address;
use clarity::PrivateKey;
use num256::Uint256;
use serial_test::serial;
use std::str::FromStr;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(600);

/// This simply test that the lazy static lock is being updated correctly after calling the function setup_withdrawal.
/// We call the function with the 'Withdraw' struct and check if the information is being updated correctly. This is necessary
/// that the correct information about the withdrawal is being processed.
#[test]
#[serial]
fn test_xdai_setup_withdraw() {
    let pk = PrivateKey::from_str(&format!(
        "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
        "632c1e54099", "51b0281"
    ))
    .unwrap();

    let _bridge = TokenBridge::new(
        default_bridge_addresses(),
        pk.to_address(),
        pk,
        "https://eth.altheamesh.com".into(),
        "https://dai.altheamesh.com".into(),
        TIMEOUT,
    );

    let address = "0x9CAFD25b8b5982F1edA0691DEF8997C55a4d8188";
    let address = Address::parse_and_validate(address);
    if address.is_err() {
        panic!("withdraw address is wrong");
    }
    let withdraw = Withdraw {
        to: address.unwrap(),
        amount: 11646660293665450_u64.into(),
    };

    println!("ready for setup");
    let res = setup_withdraw(withdraw.clone());
    if res.is_err() {
        panic!("Error with setup withdrawal");
    }

    println!("setup done");

    let reader = BRIDGE.read().unwrap();
    let withdraw_setup = match &reader.withdraw_details {
        Some(a) => a.clone(),
        None => panic!("No value set in withdraw setup"),
    };

    //check lazy static
    assert!(reader.withdraw_in_progress);
    assert_eq!(withdraw_setup, withdraw);
}

/// Calls the encode_relaytokens and initiates the withdrawal process from xdai chain to an external address. Does not however unlock the funds on the eth side.
/// Refer to test_xdai_unlock_withdraw() to check unlocking funds
#[test]
#[ignore]
fn test_xdai_transfer_withdraw() {
    let pk = PrivateKey::from_str(&format!(
        "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
        "632c1e54099", "51b0281"
    ))
    .unwrap();

    let bridge = TokenBridge::new(
        default_bridge_addresses(),
        pk.to_address(),
        pk,
        "https://eth.altheamesh.com".into(),
        "https://dai.altheamesh.com".into(),
        TIMEOUT,
    );

    let address = "0x9CAFD25b8b5982F1edA0691DEF8997C55a4d8188";
    let address = Address::parse_and_validate(address);
    if address.is_err() {
        panic!("withdraw address is wrong");
    }
    let to = address.unwrap();
    //10 xdai
    let amount = 10000000000000000000_u128;

    //Run the withdrawal process
    let runner = actix_async::System::new();
    runner.block_on(async move {
        //do encode relay token call with our token bridge
        let res = encode_relaytokens(bridge, to, amount.into(), Duration::from_secs(600)).await;
        match res {
            Ok(_) => println!("withdraw successful to address {to}"),
            Err(e) => panic!("Error during withdraw: {}", e),
        }
    })
}

/// This tests the the funds that were initially transfered by test_xdai_transfer_withdraw can we unlocked, Note that the event you are trying to unlock
/// needs to be within 40k blocks of the current xdai chain block height, or the withdraw event will not be found.
#[test]
#[ignore]
fn test_xdai_unlock_withdraw() {
    let pk = PrivateKey::from_str(&format!(
        "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
        "632c1e54099", "51b0281"
    ))
    .unwrap();

    let bridge = TokenBridge::new(
        default_bridge_addresses(),
        pk.to_address(),
        pk,
        "https://eth.altheamesh.com".into(),
        "https://dai.altheamesh.com".into(),
        TIMEOUT,
    );

    let runner = actix_async::System::new();

    runner.block_on(async move {
        match simulated_withdrawal_on_eth(&bridge).await {
            Ok(()) => {
                println!(
                    "Checking for withdraw events related to us (address: {})",
                    bridge.own_address
                );
            }
            Err(e) => {
                println!("Received error when trying to unlock funds: {e}");
            }
        }
    })
}

/// This tests the function simulate_signature_submission(), which is used to tests if a transaction needs to be unlocked on eth side or not.
/// This function not currently in use and we instead use check_relayed_message because of simplicity, but simulate_signature_submission() is also functional and
/// checks the same thing as check_relayed_message() does.
#[test]
#[ignore]
fn test_simulate_unlock_funds() {
    let pk = PrivateKey::from_str(&format!(
        "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
        "632c1e54099", "51b0281"
    ))
    .unwrap();

    let bridge = TokenBridge::new(
        default_bridge_addresses(),
        pk.to_address(),
        pk,
        "https://eth.altheamesh.com".into(),
        "https://dai.altheamesh.com".into(),
        TIMEOUT,
    );

    let address = "0x9CAFD25b8b5982F1edA0691DEF8997C55a4d8188";
    let address = Address::parse_and_validate(address).unwrap();

    let tx_hash = "0xf75cd74e3643bb0d17780589e0f18840c89ff77532f5ac38fbff885468091620";
    let tx_hash = Uint256::from_str(tx_hash).unwrap();

    let amount = 10000000000000000000_u128;

    let runner = actix_async::System::new();

    runner.block_on(async move {
        let withdraw_info = get_relay_message_hash(
            bridge.own_address,
            bridge.xdai_web3.clone(),
            bridge.helper_on_xdai,
            address,
            tx_hash,
            amount.into(),
        )
        .await
        .unwrap();

        match simulate_signature_submission(&bridge, &withdraw_info).await {
            Ok(_) => println!("Successful simulation"),
            Err(e) => println!("Simulation failed {e}"),
        }
    })
}

/// Tests that funds in dai are being transfered over to the xdai blockchain as long as dai funds are greater than
/// minimum amount to exchange (cost of a withdrawal + cost of swap to dai + cost of transfer)
#[test]
#[ignore]
fn test_transfer_dai() {
    let pk = PrivateKey::from_str(&format!(
        "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
        "632c1e54099", "51b0281"
    ))
    .unwrap();

    let bridge = TokenBridge::new(
        default_bridge_addresses(),
        pk.to_address(),
        pk,
        "https://eth.altheamesh.com".into(),
        "https://dai.altheamesh.com".into(),
        TIMEOUT,
    );

    let runner = actix_async::System::new();
    runner.block_on(async move {
        let res = transfer_dai(bridge.clone(), bridge.get_dai_balance().await.unwrap()).await;
        if res.is_err() {
            panic!("Failed to rescue dai with {:?}", res);
        }
    })
}
