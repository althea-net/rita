use diesel;
use actix_web::*;
use actix::prelude::*;
use diesel::prelude::*;
use diesel::dsl::*;
use diesel::select;

use std::net::IpAddr;

use exit_db::{models, schema};

use SETTING;

use failure::Error;

use althea_types::ExitClientIdentity;

#[derive(Default)]
pub struct DbClient;

impl Actor for DbClient {
    type Context = Context<Self>;
}

impl Supervised for DbClient {}
impl SystemService for DbClient {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("DB Client started");
    }
}

pub struct ListClients;
impl Message for ListClients {
    type Result = Result<Vec<models::Client>, Error>;
}

impl Handler<ListClients> for DbClient {
    type Result = Result<Vec<models::Client>, Error>;

    fn handle(&mut self, _: ListClients, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::*;
        trace!("Opening {:?}", &SETTING.read().unwrap().db_file);
        let connection = SqliteConnection::establish(&SETTING.read().unwrap().db_file).unwrap();

        let res = clients.load::<models::Client>(&connection)?;
        trace!("Got clients list {:?}", res);
        Ok(res)
    }
}

fn increment(address: IpAddr) -> Option<IpAddr> {
    if let IpAddr::V4(address) = address {
        let mut oct = address.octets();
        oct[3] += 1;
        return Some(oct.into());
    }
    None
}

pub struct SetupClient(pub ExitClientIdentity);

impl Message for SetupClient {
    type Result = Result<IpAddr, Error>;
}

impl Handler<SetupClient> for DbClient {
    type Result = Result<IpAddr, Error>;

    fn handle(&mut self, msg: SetupClient, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::*;
        let conn = SqliteConnection::establish(&SETTING.read().unwrap().db_file).unwrap();

        let client = msg.0;

        conn.transaction::<_, Error, _>(|| {
            let dummy = models::Client {
                mesh_ip: "0.0.0.0".to_string(),
                wg_pubkey: "".to_string(),
                wg_port: "".to_string(),
                luci_pass: "".to_string(),
                internal_ip: "172.168.1.100".to_string(),
            };

            diesel::insert_into(clients).values(&dummy).execute(&conn); // this will fail most of the time, ignoring error

            trace!("Checking if record exists for {:?}", client.global.mesh_ip);

            let exists = select(exists(
                clients.filter(mesh_ip.eq(&client.global.mesh_ip.to_string())),
            )).get_result(&conn)
                .expect("Error loading statuses");

            if exists {
                trace!("record exists, updating");
                // updating
                diesel::update(clients.find(&client.global.mesh_ip.to_string()))
                    .set(wg_port.eq(&client.wg_port.to_string()))
                    .execute(&conn)
                    .expect("Error saving");

                diesel::update(clients.find(&client.global.mesh_ip.to_string()))
                    .set(wg_pubkey.eq(&client.global.wg_public_key.clone()))
                    .execute(&conn)
                    .expect("Error saving");

                let their_record: models::Client = clients
                    .filter(mesh_ip.eq(&client.global.mesh_ip.to_string()))
                    .load::<models::Client>(&conn)
                    .expect("failed loading record")[0]
                    .clone();

                Ok(their_record.internal_ip.parse()?)
            } else {
                trace!("record does not exist, creating");
                // first time seeing

                let dummy: models::Client = clients
                    .filter(mesh_ip.eq("0.0.0.0"))
                    .load::<models::Client>(&conn)
                    .expect("failed loading dummy")[0]
                    .clone();

                trace!("dummy: {:?}", dummy);

                let new_ip = increment(dummy.internal_ip.parse().unwrap()).unwrap();

                diesel::update(clients.filter(mesh_ip.eq("0.0.0.0")))
                    .set(internal_ip.eq(&new_ip.to_string()))
                    .execute(&conn)
                    .expect("Error saving dummy");

                let c = models::Client {
                    luci_pass: "".into(),
                    wg_port: client.wg_port.to_string(),
                    mesh_ip: client.global.mesh_ip.to_string(),
                    wg_pubkey: client.global.wg_public_key.clone(),
                    internal_ip: new_ip.to_string(),
                };

                diesel::insert_into(clients)
                    .values(&c)
                    .execute(&conn)
                    .expect("Error saving");
                Ok(new_ip)
            }
        })
    }
}
