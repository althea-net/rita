use althea_types::{ExitIdentity, Regions, SystemChain};
use clarity::{Address, PrivateKey};
use rita_client_registration::client_db::{
    add_exit_admin, add_exits_to_registration_list, add_users_to_registered_list,
    check_and_add_user_admin, get_all_regsitered_clients, get_exits_list,
    get_registered_client_using_wgkey,
};
use rita_common::usage_tracker::tests::test::random_identity;
use std::collections::HashSet;
use web30::{client::Web3, types::SendTxOption};

use crate::{
    payments_eth::WEB3_TIMEOUT,
    utils::{deploy_contracts, get_eth_node, wait_for_txids, MINER_PRIVATE_KEY, TX_TIMEOUT},
};

pub async fn run_altheadb_contract_test() {
    info!("Waiting to deploy contracts");
    let althea_db_addr = deploy_contracts().await;
    info!("DB addr is {}", althea_db_addr);

    // Validate that we can add remove exit list entries
    validate_contract_exit_functionality(althea_db_addr).await;

    // Try adding a dummy entry and validating that we can retrive them
    validate_contract_user_functionality(althea_db_addr).await;
}

pub async fn validate_contract_exit_functionality(db_addr: Address) {
    let miner_private_key: PrivateKey = MINER_PRIVATE_KEY.parse().unwrap();
    let miner_pub_key = miner_private_key.to_address();

    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);

    let exit_1 = random_identity();
    let exit_1 = ExitIdentity {
        mesh_ip: exit_1.mesh_ip,
        wg_key: exit_1.wg_public_key,
        eth_addr: exit_1.eth_address,
        registration_port: 4875,
        wg_exit_listen_port: 59998,
        allowed_regions: {
            let mut ret = HashSet::new();
            ret.insert(Regions::Nigeria);
            ret.insert(Regions::Mexico);
            ret
        },
        payment_types: {
            let mut ret = HashSet::new();
            ret.insert(SystemChain::Xdai);
            ret
        },
    };

    let exit_2 = random_identity();
    let exit_2 = ExitIdentity {
        mesh_ip: exit_2.mesh_ip,
        wg_key: exit_2.wg_public_key,
        eth_addr: exit_2.eth_address,
        registration_port: 4875,
        wg_exit_listen_port: 59998,
        allowed_regions: HashSet::new(),
        payment_types: HashSet::new(),
    };

    let exit_3 = random_identity();
    let exit_3 = ExitIdentity {
        mesh_ip: exit_3.mesh_ip,
        wg_key: exit_3.wg_public_key,
        eth_addr: exit_3.eth_address,
        registration_port: 4888,
        wg_exit_listen_port: 60000,
        allowed_regions: {
            let mut ret = HashSet::new();
            ret.insert(Regions::Columbia);
            ret.insert(Regions::US);
            ret.insert(Regions::Canada);
            ret.insert(Regions::Mexico);
            ret
        },
        payment_types: {
            let mut ret = HashSet::new();
            ret.insert(SystemChain::Althea);
            ret.insert(SystemChain::Ethereum);

            ret
        },
    };
    add_exit_admin(
        &contact,
        db_addr,
        miner_pub_key,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    add_exit_admin(
        &contact,
        db_addr,
        miner_pub_key,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    let res = get_exits_list(&contact, miner_pub_key, db_addr).await;

    assert_eq!(res.unwrap(), vec![]);

    let _res = add_exits_to_registration_list(
        &contact,
        vec![exit_1.clone()],
        db_addr,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    let _res = add_exits_to_registration_list(
        &contact,
        vec![exit_2.clone()],
        db_addr,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    let res = get_exits_list(&contact, miner_pub_key, db_addr)
        .await
        .unwrap();

    println!("res is {:?}", res);

    assert_eq!(res, vec![exit_1.clone(), exit_2.clone()]);

    let _res = add_exits_to_registration_list(
        &contact,
        vec![exit_3.clone()],
        db_addr,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    let res = get_exits_list(&contact, miner_pub_key, db_addr)
        .await
        .unwrap();

    println!("res is {:?}", res);

    assert_eq!(res, vec![exit_1, exit_2, exit_3]);
}

pub async fn validate_contract_user_functionality(db_addr: Address) {
    let miner_private_key: PrivateKey = MINER_PRIVATE_KEY.parse().unwrap();
    let miner_pub_key = miner_private_key.to_address();

    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);

    // Define the users
    let user_1 = random_identity();
    let user_2 = random_identity();
    let user_3 = random_identity();
    let user_4 = random_identity();
    let user_5 = random_identity();
    let user_6 = random_identity();

    check_and_add_user_admin(
        &contact,
        db_addr,
        miner_pub_key,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    check_and_add_user_admin(
        &contact,
        db_addr,
        miner_pub_key,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    // Try requests when there are no users present
    let res = get_all_regsitered_clients(&contact, miner_pub_key, db_addr).await;

    assert_eq!(res.unwrap(), vec![]);

    let res =
        get_registered_client_using_wgkey(user_1.wg_public_key, miner_pub_key, db_addr, &contact)
            .await;

    assert!(res.is_err());

    // Add the first user
    let res = add_users_to_registered_list(
        &contact,
        vec![user_1],
        db_addr,
        miner_private_key,
        None,
        vec![],
    )
    .await
    .unwrap();

    contact
        .wait_for_transaction(res, TX_TIMEOUT, None)
        .await
        .unwrap();

    // Try requesting some info that doesnt exist
    let res = get_registered_client_using_wgkey(
        "mhfl9SGT30hoJdYppfakekeyO8/94SY+orvbr0ZFMjs="
            .parse()
            .unwrap(),
        miner_pub_key,
        db_addr,
        &contact,
    )
    .await;

    assert!(res.is_err());

    // Request the correct user
    let res =
        get_registered_client_using_wgkey(user_1.wg_public_key, miner_pub_key, db_addr, &contact)
            .await
            .unwrap();
    assert_eq!(user_1, res);

    // Request a list of all reg users (should be an array of one entry)
    let res = get_all_regsitered_clients(&contact, miner_pub_key, db_addr)
        .await
        .unwrap();

    assert_eq!(vec![user_1], res);

    let nonce = contact
        .eth_get_transaction_count(miner_pub_key)
        .await
        .unwrap();

    // Add the second user
    let res1 = add_users_to_registered_list(
        &contact,
        vec![user_2],
        db_addr,
        miner_private_key,
        None,
        vec![
            SendTxOption::Nonce(nonce),
            SendTxOption::GasLimitMultiplier(5.0),
        ],
    )
    .await
    .unwrap();

    // Add the third user
    let res2 = add_users_to_registered_list(
        &contact,
        vec![user_3],
        db_addr,
        miner_private_key,
        None,
        vec![
            SendTxOption::Nonce(nonce + 1u8.into()),
            SendTxOption::GasLimitMultiplier(5.0),
        ],
    )
    .await
    .unwrap();

    let res3 = add_users_to_registered_list(
        &contact,
        vec![user_4],
        db_addr,
        miner_private_key,
        None,
        vec![
            SendTxOption::Nonce(nonce + 2u8.into()),
            SendTxOption::GasLimitMultiplier(5.0),
        ],
    )
    .await
    .unwrap();

    let res4 = add_users_to_registered_list(
        &contact,
        vec![user_5],
        db_addr,
        miner_private_key,
        None,
        vec![
            SendTxOption::Nonce(nonce + 3u8.into()),
            SendTxOption::GasLimitMultiplier(5.0),
        ],
    )
    .await
    .unwrap();

    let res5 = add_users_to_registered_list(
        &contact,
        vec![user_6],
        db_addr,
        miner_private_key,
        None,
        vec![
            SendTxOption::Nonce(nonce + 4u8.into()),
            SendTxOption::GasLimitMultiplier(5.0),
        ],
    )
    .await
    .unwrap();

    wait_for_txids(
        vec![Ok(res1), Ok(res2), Ok(res3), Ok(res4), Ok(res5)],
        &contact,
    )
    .await;

    let res = get_all_regsitered_clients(&contact, miner_pub_key, db_addr)
        .await
        .unwrap();

    info!("All users are : {:?}", res);

    assert_eq!(vec![user_1, user_2, user_3, user_4, user_5, user_6], res);

    info!("Trying to retrive user 1");
    let res =
        get_registered_client_using_wgkey(user_1.wg_public_key, miner_pub_key, db_addr, &contact)
            .await
            .unwrap();
    assert_eq!(res, user_1);

    info!("Trying to retrive user 2");
    let res =
        get_registered_client_using_wgkey(user_2.wg_public_key, miner_pub_key, db_addr, &contact)
            .await
            .unwrap();
    assert_eq!(res, user_2);

    info!("Trying to retrive user 3");
    let res =
        get_registered_client_using_wgkey(user_3.wg_public_key, miner_pub_key, db_addr, &contact)
            .await
            .unwrap();
    assert_eq!(res, user_3);
}
