//! DB client is essentially a layer over Diesel which is itself a layer over a sqllite database
//! at some point we will need to add multi-database support such that we can scale exits
//! horizontally.
//!
//! This 'abstraction' layer is pretty closely tied to the signup process for exits and contains
//! too much sign up logic.

use actix::prelude::*;
use actix_web::*;
use diesel;
use diesel::dsl::*;
use diesel::prelude::*;
use diesel::select;

use reqwest;

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use lettre::{
    file::FileTransport,
    smtp::{
        authentication::{Credentials, Mechanism},
        extension::ClientId,
        ConnectionReuseParameters,
    },
    SmtpClient, Transport,
};
use lettre_email::EmailBuilder;

use handlebars::Handlebars;

use rand;
use rand::Rng;

use exit_db::{models, schema};

use settings::RitaExitSettings;
use SETTING;

use ipnetwork::IpNetwork;

use failure::Error;

use althea_types::{ExitClientDetails, ExitClientIdentity, ExitDetails, ExitState};

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
        let connection = match SqliteConnection::establish(&SETTING.get_db_file()) {
            Ok(connection) => connection,
            Err(e) => {
                error!("We could not connect to the database file! {:?}", e);
                bail!("Could not connect to database file!")
            }
        };

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

#[derive(Deserialize, Debug)]
struct GeoIPRet {
    country: GeoIPRetCountry,
}

#[derive(Deserialize, Debug)]
struct GeoIPRetCountry {
    code: String,
}

// get ISO country code from ip
fn get_country(ip: &IpAddr) -> Result<String, Error> {
    let client = reqwest::Client::new();

    let geo_ip_url = format!("http://geoip.nekudo.com/api/{}", ip);
    trace!("making geoip request to {}", geo_ip_url);

    let res: GeoIPRet = client.get(&geo_ip_url).send()?.json()?;
    info!("Got {:?} from GeoIP request", res);

    return Ok(res.country.code);
}

#[test]
#[ignore]
fn test_get_country() {
    get_country(&"8.8.8.8".parse().unwrap()).unwrap();
}

fn verify_ip(request_ip: &IpAddr) -> Result<(), Error> {
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

fn add_dummy(conn: &SqliteConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::*;

    let mut dummy = models::Client::default();

    dummy.internal_ip = SETTING.get_exit_network().exit_start_ip.to_string();
    dummy.mesh_ip = "0.0.0.0".to_string();

    match diesel::insert_into(clients).values(&dummy).execute(&*conn) {
        Err(e) => trace!("Not inserting dummy: {:?}", e),
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

fn update_client(client: &ExitClientIdentity, conn: &SqliteConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::{clients, email, wg_port, wg_pubkey};
    let mail_addr = match client.clone().reg_details.email {
        Some(mail) => mail.clone(),
        None => bail!("Cloud not find email for {:?}", client.clone()),
    };

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(wg_port.eq(&client.wg_port.to_string()))
        .execute(&*conn)?;

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(wg_pubkey.eq(&client.global.wg_public_key.clone()))
        .execute(&*conn)?;

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(email.eq(&mail_addr))
        .execute(&*conn)?;

    Ok(())
}

fn verify_client(
    client: &ExitClientIdentity,
    client_verified: bool,
    conn: &SqliteConnection,
) -> Result<(), Error> {
    use self::schema::clients::dsl::*;

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(verified.eq(client_verified))
        .execute(&*conn)?;

    Ok(())
}

fn secs_since_unix_epoch() -> i32 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() as i32
}

fn update_mail_sent_time(
    client: &ExitClientIdentity,
    conn: &SqliteConnection,
) -> Result<(), Error> {
    use self::schema::clients::dsl::{clients, email, email_sent_time};
    let mail_addr = match client.clone().reg_details.email {
        Some(mail) => mail.clone(),
        None => bail!("Cloud not find email for {:?}", client.clone()),
    };

    diesel::update(clients.filter(email.eq(mail_addr)))
        .set(email_sent_time.eq(secs_since_unix_epoch() as i32))
        .execute(&*conn)?;

    Ok(())
}

fn client_exists(ip: &IpAddr, conn: &SqliteConnection) -> Result<bool, Error> {
    use self::schema::clients::dsl::*;
    Ok(select(exists(clients.filter(mesh_ip.eq(ip.to_string())))).get_result(&*conn)?)
}

fn client_to_new_db_client(
    client: ExitClientIdentity,
    new_ip: IpAddr,
    country: String,
) -> models::Client {
    let mut rng = rand::thread_rng();
    let rand_code: u64 = rng.gen_range(0, 999999);
    models::Client {
        wg_port: client.wg_port.to_string(),
        mesh_ip: client.global.mesh_ip.to_string(),
        wg_pubkey: client.global.wg_public_key.clone(),
        internal_ip: new_ip.to_string(),
        email: client.reg_details.email.clone().unwrap_or("".to_string()),
        country,
        email_code: format!("{:06}", rand_code),
        verified: false,
        email_sent_time: 0,
    }
}

fn email_ver_done(client: &models::Client) -> Result<bool, Error> {
    Ok(client.verified || SETTING.get_mailer().is_none())
}

fn send_mail(client: &models::Client) -> Result<(), Error> {
    if SETTING.get_mailer().is_none() {
        return Ok(());
    };
    let mailer = SETTING.get_mailer().unwrap().clone();

    info!("Sending exit signup email for client");

    let reg = Handlebars::new();

    let email = EmailBuilder::new()
        .to(client.email.clone())
        .from(mailer.from_address)
        .subject(mailer.subject)
        // TODO: maybe have a proper templating engine
        .text(reg.render_template(
            &mailer.body,
            &json!({"email_code": client.email_code.to_string()}),
        )?).build()?;

    if mailer.test {
        let mut mailer = FileTransport::new(&mailer.test_dir);
        mailer.send(email.into())?;
    } else {
        // TODO add serde to lettre
        let mut mailer = SmtpClient::new_simple(&mailer.smtp_url)?
            .hello_name(ClientId::Domain(mailer.smtp_domain))
            .credentials(Credentials::new(mailer.smtp_username, mailer.smtp_password))
            .smtp_utf8(true)
            .authentication_mechanism(Mechanism::Plain)
            .connection_reuse(ConnectionReuseParameters::ReuseUnlimited)
            .transport();
        mailer.send(email.into())?;
    }

    Ok(())
}

pub struct SetupClient(pub ExitClientIdentity, pub IpAddr);

impl Message for SetupClient {
    type Result = Result<ExitState, Error>;
}

impl Handler<SetupClient> for DbClient {
    type Result = Result<ExitState, Error>;

    fn handle(&mut self, msg: SetupClient, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::{clients, mesh_ip};
        let conn = match SqliteConnection::establish(&SETTING.get_db_file()) {
            Ok(connection) => connection,
            Err(e) => {
                error!("We could not connect to the database file! {:?}", e);
                bail!("Could not connect to database file!")
            }
        };
        let client = msg.0.clone();

        trace!("got setup request {:?}", client);

        match verify_ip(&msg.1) {
            Ok(_) => {
                conn.transaction::<_, Error, _>(|| {
                    add_dummy(&conn)?;

                    trace!("Checking if record exists for {:?}", client.global.mesh_ip);

                    if client_exists(&client.global.mesh_ip, &conn)? {
                        update_client(&msg.0, &conn)?;
                        let mut their_record: models::Client = match clients
                            .filter(mesh_ip.eq(&client.global.mesh_ip.to_string()))
                            .load::<models::Client>(&conn)
                        {
                            Ok(entry) => entry[0].clone(),
                            Err(e) => {
                                error!("We failed to lookup the client {:?} with{:?}", mesh_ip, e);
                                bail!("We failed to lookup the client!")
                            }
                        };

                        info!(
                            "expected code {}, got code {:?}",
                            their_record.email_code, client.reg_details.email_code
                        );

                        if client.reg_details.email_code == Some(their_record.email_code.clone()) {
                            info!("email verification complete for {:?}", client);
                            verify_client(&client, true, &conn)?;
                            their_record.verified = true;
                        }

                        if email_ver_done(&their_record)? {
                            info!("{:?} is now registered", client);
                            Ok(ExitState::Registered {
                                our_details: ExitClientDetails {
                                    client_internal_ip: their_record.internal_ip.parse()?,
                                },
                                general_details: get_exit_info(),
                                message: "Registration OK".to_string(),
                            })
                        } else {
                            let cooldown = match SETTING.get_mailer() {
                                Some(mailer) => mailer.email_cooldown as i32,
                                None => bail!("There is no mailer configured!"),
                            };
                            let time_since_last_email =
                                secs_since_unix_epoch() - their_record.email_sent_time;

                            if time_since_last_email < cooldown {
                                Ok(ExitState::GotInfo {
                                    general_details: get_exit_info(),
                                    message: format!(
                                        "Wait {} more seconds for email verification cooldown",
                                        cooldown - time_since_last_email
                                    ),
                                    auto_register: true,
                                })
                            } else {
                                update_mail_sent_time(&client, &conn)?;
                                send_mail(&their_record)?;
                                Ok(ExitState::Pending {
                                    general_details: get_exit_info(),
                                    message: "awaiting email verification".to_string(),
                                    email_code: None,
                                })
                            }
                        }
                    } else {
                        trace!("record does not exist, creating");
                        // first time seeing

                        let new_ip = incr_dummy(&conn)?;

                        let user_country = if SETTING.get_allowed_countries().is_empty() {
                            String::new()
                        } else {
                            get_country(&msg.1)?
                        };

                        let c = client_to_new_db_client(client, new_ip, user_country);

                        diesel::insert_into(clients).values(&c).execute(&conn)?;

                        send_mail(&c)?;

                        Ok(ExitState::Pending {
                            general_details: get_exit_info(),
                            message: "awaiting email verification".to_string(),
                            email_code: None,
                        })
                    }
                })
            }
            Err(e) => Ok(ExitState::Denied {
                message: format!(
                    "This exit only accepts connections from {:?}\n verbose error: {}",
                    SETTING.get_allowed_countries().clone(),
                    e
                ),
            }),
        }
    }
}

pub struct ClientStatus(pub ExitClientIdentity);

impl Message for ClientStatus {
    type Result = Result<ExitState, Error>;
}

impl Handler<ClientStatus> for DbClient {
    type Result = Result<ExitState, Error>;

    fn handle(&mut self, msg: ClientStatus, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::{clients, mesh_ip};
        let conn = match SqliteConnection::establish(&SETTING.get_db_file()) {
            Ok(connection) => connection,
            Err(e) => {
                error!("We could not connect to the database file! {:?}", e);
                bail!("Could not connect to database file!")
            }
        };
        conn.transaction::<_, Error, _>(|| {
            let client = msg.0;

            add_dummy(&conn)?;

            trace!("Checking if record exists for {:?}", client.global.mesh_ip);

            if client_exists(&client.global.mesh_ip, &conn)? {
                trace!("record exists, updating");

                let their_record: models::Client = match clients
                    .filter(mesh_ip.eq(&client.global.mesh_ip.to_string()))
                    .load::<models::Client>(&conn)
                {
                    Ok(entry) => entry[0].clone(),
                    Err(e) => {
                        error!("We failed to lookup the client {:?} with{:?}", mesh_ip, e);
                        bail!("We failed to lookup the client!")
                    }
                };

                if !email_ver_done(&their_record)? {
                    return Ok(ExitState::Pending {
                        general_details: get_exit_info(),
                        message: "awaiting email verification".to_string(),
                        email_code: None,
                    });
                }

                let current_ip = their_record.internal_ip.parse()?;

                let current_subnet = IpNetwork::new(
                    SETTING.get_exit_network().own_internal_ip,
                    SETTING.get_exit_network().netmask,
                )?;

                if !current_subnet.contains(current_ip) {
                    return Ok(ExitState::Registering {
                        general_details: get_exit_info(),
                        message: "Registration reset because of IP range change".to_string(),
                    });
                }

                update_client(&client, &conn)?;

                Ok(ExitState::Registered {
                    our_details: ExitClientDetails {
                        client_internal_ip: current_ip,
                    },
                    general_details: get_exit_info(),
                    message: "Registration OK".to_string(),
                })
            } else {
                Ok(ExitState::New)
            }
        })
    }
}

pub struct TruncateTables;
impl Message for TruncateTables {
    type Result = Result<(), Error>;
}

impl Handler<TruncateTables> for DbClient {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: TruncateTables, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::*;
        info!("Deleting all clients in {:?}", &SETTING.get_db_file());
        let connection = match SqliteConnection::establish(&SETTING.get_db_file()) {
            Ok(connection) => connection,
            Err(e) => {
                error!("We could not connect to the database file! {:?}", e);
                bail!("Could not connect to database file!")
            }
        };
        try!(delete(clients).execute(&connection));
        Ok(())
    }
}
