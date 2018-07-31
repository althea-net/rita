use schema::clients;

#[derive(Queryable, Serialize, Deserialize, Debug, Insertable, Clone, AsChangeset, Default)]
#[table_name = "clients"]
pub struct Client {
    pub mesh_ip: String,
    pub wg_pubkey: String,
    pub wg_port: String,
    pub internal_ip: String,
    pub email: String,
    pub country: String,
    pub email_code: String,
    pub verified: bool,
    // TODO change before 2038
    pub email_sent_time: i32,
}
