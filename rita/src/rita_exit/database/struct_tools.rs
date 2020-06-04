use althea_kernel_interface::ExitClient;
use althea_types::ExitClientIdentity;
use althea_types::Identity;
use arrayvec::ArrayString;
use exit_db::models;
use exit_db::models::Client;
use failure::Error;
use rand::Rng;
use std::collections::HashSet;
use std::net::IpAddr;

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

/// returns the number of text messages this entry has requested
/// and recieved so far
pub fn texts_sent(client: &models::Client) -> i32 {
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

pub fn client_to_new_db_client(
    client: &ExitClientIdentity,
    new_ip: IpAddr,
    country: String,
) -> models::Client {
    let mut rng = rand::thread_rng();
    let rand_code: u64 = rng.gen_range(0, 999_999);
    models::Client {
        wg_port: i32::from(client.wg_port),
        mesh_ip: client.global.mesh_ip.to_string(),
        wg_pubkey: client.global.wg_public_key.to_string(),
        eth_address: client.global.eth_address.to_string().to_lowercase(),
        nickname: client.global.nickname.unwrap_or_default().to_string(),
        internal_ip: new_ip.to_string(),
        email: client.reg_details.email.clone().unwrap_or_default(),
        phone: client.reg_details.phone.clone().unwrap_or_default(),
        country,
        email_code: format!("{:06}", rand_code),
        text_sent: 0,
        verified: false,
        email_sent_time: 0,
        last_seen: 0,
        last_balance_warning_time: 0,
    }
}
