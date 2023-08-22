use std::net::IpAddr;

use althea_types::{Identity, WgKey};
use clarity::Address;

pub fn get_all_regsitered_clients() -> Vec<Identity> {
    unimplemented!()
}

pub fn get_registered_client_using_wgkey(_key: WgKey) -> Option<Identity> {
    unimplemented!()
}

pub fn get_registered_client_using_ethkey(_key: Address) -> Option<Identity> {
    unimplemented!()
}

pub fn get_registered_client_using_meship(_ip: IpAddr) -> Option<Identity> {
    unimplemented!()
}

pub fn get_clients_exit_cluster_list(_key: WgKey) -> Vec<Identity> {
    unimplemented!()
}

pub fn add_client_to_registered_list(_c: Identity) {
    unimplemented!()
}
