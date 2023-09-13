use std::{thread, time::Duration};

use althea_types::Identity;
use rita_client_registration::client_db::{
    add_client_to_registered_list, get_all_regsitered_clients, get_registered_client_using_ethkey,
    get_registered_client_using_meship, get_registered_client_using_wgkey,
};
use web30::client::Web3;

use crate::{
    payments_eth::{ETH_MINER_KEY, WEB3_TIMEOUT},
    utils::{get_altheadb_contract_addr, get_eth_node},
};

pub async fn run_altheadb_contract_test() {
    // Try adding a dummy entry and validating that we can retrive them
    validate_contract_functionality().await;

    thread::sleep(Duration::from_secs(1000));
}

pub async fn validate_contract_functionality() {
    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);

    // Define the users
    let user = Identity {
        mesh_ip: "fd00::1337".parse().unwrap(),
        eth_address: "0x02ad6b480DFeD806C63a0839C6f1f3136c5fD515"
            .parse()
            .unwrap(),
        wg_public_key: "sPtNGQbyPpCsqSKD6PbnflB1lIUCd259Vhd0mJfJeGo="
            .parse()
            .unwrap(),
        nickname: None,
    };

    let user_2 = Identity {
        mesh_ip: "fd00::1447:1447".parse().unwrap(),
        eth_address: "0x1994A73F79F9648d4a8064D9C0F221fB1007Fd2F"
            .parse()
            .unwrap(),
        wg_public_key: "Yhyj+CKZbyEKea/9hdIFje98yc5Cukt1Pbq0qWB4Aqw="
            .parse()
            .unwrap(),
        nickname: None,
    };

    let user_3 = Identity {
        mesh_ip: "fd00::3000:1117".parse().unwrap(),
        eth_address: "0x9c33D0dFdc9E3f7cC73bE3A575C31cfe3059C76a"
            .parse()
            .unwrap(),
        wg_public_key: "fzOUfEqYzRE0MwfR5o7XV+MKZKj/qEfELRzQTRTKAB8="
            .parse()
            .unwrap(),
        nickname: None,
    };

    // Try requests when there are no users present
    let res = get_all_regsitered_clients(
        &contact,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        get_altheadb_contract_addr(),
    )
    .await
    .unwrap();

    assert!(res.is_empty());

    let res = get_registered_client_using_wgkey(
        user.wg_public_key,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        get_altheadb_contract_addr(),
        &contact,
    )
    .await;

    assert!(res.is_err());

    // Add the first user
    let _res = add_client_to_registered_list(
        &contact,
        user,
        get_altheadb_contract_addr(),
        ETH_MINER_KEY.parse().unwrap(),
        None,
        vec![],
    )
    .await
    .unwrap();

    thread::sleep(Duration::from_secs(5));

    // Try requesting some info that doesnt exist
    let res = get_registered_client_using_ethkey(
        "0x3d261902a988d94599d7f0Bd4c2e4514D73BB329"
            .parse()
            .unwrap(),
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        get_altheadb_contract_addr(),
        &contact,
    )
    .await;

    assert!(res.is_err());

    // Add the second user
    let _res = add_client_to_registered_list(
        &contact,
        user_2,
        get_altheadb_contract_addr(),
        ETH_MINER_KEY.parse().unwrap(),
        None,
        vec![],
    )
    .await
    .unwrap();

    thread::sleep(Duration::from_secs(5));

    // Add the third user
    let _res = add_client_to_registered_list(
        &contact,
        user_3,
        get_altheadb_contract_addr(),
        ETH_MINER_KEY.parse().unwrap(),
        None,
        vec![],
    )
    .await
    .unwrap();

    thread::sleep(Duration::from_secs(10));

    let res = get_all_regsitered_clients(
        &contact,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        get_altheadb_contract_addr(),
    )
    .await;

    println!("All users are : {:?}", res);

    thread::sleep(Duration::from_secs(5));

    let res = get_registered_client_using_wgkey(
        user.wg_public_key,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        get_altheadb_contract_addr(),
        &contact,
    )
    .await
    .unwrap();
    assert_eq!(res, user);

    let res = get_registered_client_using_ethkey(
        user_2.eth_address,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        get_altheadb_contract_addr(),
        &contact,
    )
    .await
    .unwrap();
    assert_eq!(res, user_2);

    let res = get_registered_client_using_meship(
        user_3.mesh_ip,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        get_altheadb_contract_addr(),
        &contact,
    )
    .await
    .unwrap();
    assert_eq!(res, user_3);
}
