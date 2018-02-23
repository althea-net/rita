use super::schema::status;

#[derive(Queryable, Serialize, Deserialize, Debug, Insertable)]
#[table_name = "status"]
pub struct Status {
    pub ip: String,
    pub mac: String,
    pub balance: String,
}
