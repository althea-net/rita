use std::{thread, time::Duration};

use clarity::{Address, PrivateKey};
use log::info;
use rita_client_registration::client_db::{
    add_client_to_registered_list, get_all_regsitered_clients, get_registered_client_using_ethkey,
    get_registered_client_using_meship, get_registered_client_using_wgkey,
};
use rita_common::usage_tracker::tests::test::random_identity;
use web30::client::Web3;

use crate::{
    payments_eth::{get_miner_key, WEB3_TIMEOUT},
    utils::{deploy_contracts, get_eth_node},
};

pub async fn run_altheadb_contract_test() {
    info!("Waiting to deploy contracts");
    let althea_db_addr = deploy_contracts().await;
    info!("DB addr is {}", althea_db_addr);

    // Try adding a dummy entry and validating that we can retrive them
    validate_contract_functionality(althea_db_addr).await;
}

pub async fn validate_contract_functionality(db_addr: Address) {
    let miner_private_key: PrivateKey = get_miner_key();
    let miner_pub_key = miner_private_key.to_address();

    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);

    // Define the users
    let user_1 = random_identity();
    let user_2 = random_identity();
    let user_3 = random_identity();

    // Try requests when there are no users present
    let res = get_all_regsitered_clients(&contact, miner_pub_key, db_addr).await;

    assert!(res.is_err());

    let res =
        get_registered_client_using_wgkey(user_1.wg_public_key, miner_pub_key, db_addr, &contact)
            .await;

    assert!(res.is_err());

    // Add the first user
    let _res =
        add_client_to_registered_list(&contact, user_1, db_addr, miner_private_key, None, vec![])
            .await
            .unwrap();

    thread::sleep(Duration::from_secs(5));

    // Try requesting some info that doesnt exist
    let res = get_registered_client_using_ethkey(
        "0x3d261902a988d94599d7f0Bd4c2e4514D73BB329"
            .parse()
            .unwrap(),
        miner_pub_key,
        db_addr,
        &contact,
    )
    .await;

    assert!(res.is_err());

    // Add the second user
    let _res =
        add_client_to_registered_list(&contact, user_2, db_addr, miner_private_key, None, vec![])
            .await
            .unwrap();

    thread::sleep(Duration::from_secs(5));

    // Add the third user
    let _res =
        add_client_to_registered_list(&contact, user_3, db_addr, miner_private_key, None, vec![])
            .await
            .unwrap();

    thread::sleep(Duration::from_secs(10));

    let res = get_all_regsitered_clients(&contact, miner_pub_key, db_addr).await;

    info!("All users are : {:?}", res);

    thread::sleep(Duration::from_secs(5));

    info!("Trying to retrive user 1");
    let res =
        get_registered_client_using_wgkey(user_1.wg_public_key, miner_pub_key, db_addr, &contact)
            .await
            .unwrap();
    assert_eq!(res, user_1);

    info!("Trying to retrive user 2");
    let res =
        get_registered_client_using_ethkey(user_2.eth_address, miner_pub_key, db_addr, &contact)
            .await
            .unwrap();
    assert_eq!(res, user_2);

    info!("Trying to retrive user 3");
    let res = get_registered_client_using_meship(user_3.mesh_ip, miner_pub_key, db_addr, &contact)
        .await
        .unwrap();
    assert_eq!(res, user_3);
}
