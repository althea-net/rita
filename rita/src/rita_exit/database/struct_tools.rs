use althea_kernel_interface::ExitClient;
use althea_types::Identity;
use arrayvec::ArrayString;
use exit_db::models;
use exit_db::models::Client;
use failure::Error;
use std::collections::HashSet;

pub fn to_identity(client: &Client) -> Result<Identity, Error> {
    trace!("Converting client {:?}", client);
    Ok(Identity {
        mesh_ip: client.mesh_ip.clone().parse()?,
        eth_address: client.eth_address.clone().parse()?,
        wg_public_key: client.wg_pubkey.clone().parse()?,
        nickname: Some(ArrayString::<[u8; 32]>::from(&client.nickname).unwrap_or_default()),
    })
}

pub fn to_exit_client(client: Client) -> Result<ExitClient, Error> {
    Ok(ExitClient {
        mesh_ip: client.mesh_ip.parse()?,
        internal_ip: client.internal_ip.parse()?,
        port: client.wg_port as u16,
        public_key: client.wg_pubkey.parse()?,
    })
}

pub fn clients_to_ids(clients: Vec<Client>) -> Vec<Identity> {
    let mut ids: Vec<Identity> = Vec::new();
    for client in clients.iter() {
        match (client.verified, to_identity(client)) {
            (true, Ok(id)) => ids.push(id),
            (true, Err(e)) => warn!("Corrupt database entry {:?}", e),
            (false, _) => trace!("{:?} is not registered", client),
        }
    }
    ids
}

/// returns true if client is verified
pub fn verif_done(client: &models::Client) -> bool {
    client.verified
}

/// returns true if text message has been sent
pub fn text_done(client: &models::Client) -> bool {
    client.text_sent
}

/// quick display function for a neat error
pub fn display_hashset(input: &HashSet<String>) -> String {
    let mut out = String::new();
    for item in input.iter() {
        out += &format!("{}, ", item);
    }
    out
}
