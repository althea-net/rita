use actix::prelude::*;
use actix_web::*;
use diesel;
use diesel::dsl::*;
use diesel::prelude::*;
use diesel::select;

use reqwest;

use std::net::IpAddr;

use exit_db::{models, schema};

use settings::RitaExitSettings;
use SETTING;

use failure::Error;

use althea_types::{
    ExitClientDetails, ExitClientIdentity, ExitDetails, ExitRegistrationDetails, ExitState,
};

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
        info!("Opening {:?}", &SETTING.get_db_file());
        let connection = SqliteConnection::establish(&SETTING.get_db_file()).unwrap();

        let res = clients.load::<models::Client>(&connection)?;
        trace!("Got clients list {:?}", res);
        Ok(res)
    }
}

fn increment(address: IpAddr) -> Result<IpAddr, Error> {
    if let IpAddr::V4(address) = address {
        let mut oct = address.octets();
        oct[3] += 1;
        return Ok(oct.into());
    }
    bail!("Not ipv4 addr")
}

#[derive(Deserialize)]
struct GeoIPRet {
    country: GeoIPRetCountry,
}

#[derive(Deserialize)]
struct GeoIPRetCountry {
    code: String,
}

// get ISO country code from ip
fn get_country(ip: &IpAddr) -> Result<String, Error> {
    let client = reqwest::Client::new();

    let geo_ip_url = format!("http://geoip.nekudo.com/api/{}", ip);
    trace!("making geoip request to {}", geo_ip_url);

    let res: GeoIPRet = client.get(&geo_ip_url).send()?.json()?;

    return Ok(res.country.code);
}

#[test]
#[ignore]
fn test_get_country() {
    get_country(&"8.8.8.8".parse().unwrap()).unwrap();
}

fn verify_identity(details: &ExitRegistrationDetails, request_ip: &IpAddr) -> Result<(), Error> {
    if details.email.is_none() || details.zip_code.is_none() {
        bail!("email and zip must be set");
    }

    if SETTING.get_allowed_countries().is_empty() {
        Ok(())
    } else {
        let country = get_country(request_ip)?;

        if !SETTING.get_allowed_countries().is_empty()
            && !SETTING.get_allowed_countries().contains(&country)
        {
            bail!("country not allowed")
        }

        Ok(())
    }
}

pub fn get_exit_info() -> ExitDetails {
    ExitDetails {
        server_internal_ip: SETTING.get_exit_network().own_internal_ip,
        wg_exit_port: SETTING.get_exit_network().wg_tunnel_port,
        exit_price: SETTING.get_exit_network().exit_price,
        netmask: SETTING.get_exit_network().netmask,
        description: SETTING.get_description(),
    }
}

pub struct SetupClient(pub ExitClientIdentity, pub IpAddr);

impl Message for SetupClient {
    type Result = Result<ExitState, Error>;
}

fn add_dummy(conn: &SqliteConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::*;

    let dummy = models::Client {
        mesh_ip: "0.0.0.0".to_string(),
        wg_pubkey: "".to_string(),
        wg_port: "".to_string(),
        luci_pass: "".to_string(),
        internal_ip: SETTING.get_exit_network().exit_start_ip.to_string(),
        email: "".to_string(),
        zip: "".to_string(),
        country: "".to_string(),
    };

    match diesel::insert_into(clients).values(&dummy).execute(&*conn) {
        Err(e) => warn!("got error inserting dummy: {}", e),
        _ => {}
    }
    Ok(())
}

fn incr_dummy(conn: &SqliteConnection) -> Result<IpAddr, Error> {
    use self::schema::clients::dsl::*;

    add_dummy(&conn)?;
    let dummy: models::Client = clients
        .filter(mesh_ip.eq("0.0.0.0"))
        .load::<models::Client>(&*conn)
        .expect("failed loading dummy")[0]
        .clone();

    trace!("dummy: {:?}", dummy);

    let new_ip = increment(dummy.internal_ip.parse()?)?;

    diesel::update(clients.filter(mesh_ip.eq("0.0.0.0")))
        .set(internal_ip.eq(&new_ip.to_string()))
        .execute(&*conn)?;

    Ok(new_ip)
}

fn client_to_db_client(
    client: ExitClientIdentity,
    new_ip: IpAddr,
    country: String,
) -> models::Client {
    models::Client {
        luci_pass: "".into(),
        wg_port: client.wg_port.to_string(),
        mesh_ip: client.global.mesh_ip.to_string(),
        wg_pubkey: client.global.wg_public_key.clone(),
        internal_ip: new_ip.to_string(),
        email: client.reg_details.email.clone().unwrap_or("".to_string()),
        zip: client
            .reg_details
            .zip_code
            .clone()
            .unwrap_or("".to_string()),
        country,
    }
}

impl Handler<SetupClient> for DbClient {
    type Result = Result<ExitState, Error>;

    fn handle(&mut self, msg: SetupClient, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::*;
        let conn = SqliteConnection::establish(&SETTING.get_db_file()).unwrap();

        match verify_identity(&msg.0.reg_details, &msg.1) {
            Ok(_) => {
                let client = msg.0.clone();

                conn.transaction::<_, Error, _>(|| {
                    add_dummy(&conn)?;

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

                        diesel::update(clients.find(&client.global.mesh_ip.to_string()))
                            .set(email.eq(&client.reg_details.email.clone().unwrap()))
                            .execute(&conn)
                            .expect("Error saving");

                        diesel::update(clients.find(&client.global.mesh_ip.to_string()))
                            .set(zip.eq(&client.reg_details.zip_code.clone().unwrap()))
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

                        let new_ip = incr_dummy(&conn)?;

                        let c = client_to_db_client(
                            client,
                            new_ip,
                            if SETTING.get_allowed_countries().is_empty() {
                                String::new()
                            } else {
                                get_country(&msg.1)?
                            },
                        );

                        diesel::insert_into(clients)
                            .values(&c)
                            .execute(&conn)
                            .expect("Error saving");
                        Ok(new_ip)
                    }
                })
            }
            Err(e) => return Err(e),
        }.and_then(|ip| {
            Ok(ExitState::Registered {
                our_details: ExitClientDetails {
                    client_internal_ip: ip,
                },
                general_details: get_exit_info(),
                message: "Registration OK".to_string(),
            })
        })
    }
}
