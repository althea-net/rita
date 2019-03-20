use crate::schema::clients;

#[derive(Queryable, Serialize, Deserialize, Debug, Insertable, Clone, AsChangeset, Default)]
#[table_name = "clients"]
pub struct Client {
    pub mesh_ip: String,
    pub wg_pubkey: String,
    pub wg_port: i32,
    pub eth_address: String,
    pub internal_ip: String,
    pub nickname: String,
    pub email: String,
    pub phone: String,
    pub country: String,
    pub email_code: String,
    pub verified: bool,
    pub email_sent_time: i64,
    pub text_sent: i32,
    pub last_seen: i64,
    pub last_balance_warning_time: i64,
}
