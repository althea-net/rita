//! DB client is essentially a layer over Diesel which is itself a layer over a sqllite database
//! at some point we will need to add multi-database support such that we can scale exits
//! horizontally.
//!
//! This 'abstraction' layer is pretty closely tied to the signup process for exits and contains
//! too much sign up logic.

use ::actix::prelude::*;
use ::actix_web::*;
use diesel;
use diesel::dsl::*;
use diesel::prelude::*;
use diesel::select;
use std::collections::HashMap;

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

use althea_kernel_interface::ExitClient;

use crate::SETTING;
use settings::exit::ExitVerifSettings;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;

use ipnetwork::IpNetwork;

use failure::Error;

use althea_types::{ExitClientDetails, ExitClientIdentity, ExitDetails, ExitState, ExitVerifMode};

#[derive(Default)]
pub struct DbClient {
    geoip_cache: HashMap<IpAddr, String>,
}

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

/// adds one to whole netmask ip addresses
fn increment(address: IpAddr, netmask: u8) -> Result<IpAddr, Error> {
    assert_eq!(netmask % 8, 0);
    // same algorithm for either path, couldn't converge the codepaths
    // without having to play with slices for oct
    match address {
        IpAddr::V4(address) => {
            // the number of bytes we can cover using this netmask
            let bytes_to_modify = ((32 - netmask) + 7) / 8;
            assert!(netmask <= 32);
            assert!(bytes_to_modify <= 4);
            assert!(bytes_to_modify > 0);

            let mut carry = false;
            let mut oct = address.octets();
            for i in (3 - (bytes_to_modify)..4).rev() {
                let index = i as usize;
                if i == (4 - bytes_to_modify) && oct[index] == 255 && carry {
                    bail!("Ip space in the netmask has been exhausted!");
                }

                if oct[index] == 255 {
                    oct[index] = 0;
                    carry = true;
                    continue;
                }

                if carry {
                    oct[index] += 1;
                    return Ok(oct.into());
                }

                oct[index] += 1;
                return Ok(oct.into());
            }
            bail!("No more ip address space!")
        }
        IpAddr::V6(address) => {
            // the number of bytes we can cover using this netmask
            let bytes_to_modify = ((128 - netmask) + 7) / 8;
            assert!(netmask <= 128);
            assert!(bytes_to_modify <= 16);
            assert!(bytes_to_modify > 0);

            let mut carry = false;
            let mut oct = address.octets();
            for i in ((16 - bytes_to_modify)..16).rev() {
                let index = i as usize;
                if i == (15 - bytes_to_modify) && oct[index] == 255 && carry {
                    bail!("Ip space in the netmask has been exhausted!");
                }

                if oct[index] == 255 {
                    oct[index] = 0;
                    carry = true;
                    continue;
                }

                if carry {
                    oct[index] += 1;
                    return Ok(oct.into());
                }

                oct[index] += 1;
                return Ok(oct.into());
            }
            bail!("No more ip address space!")
        }
    }
}

#[derive(Deserialize, Debug)]
struct GeoIPRet {
    country_code: String,
}

/// get ISO country code from ip, consults a in memory cache
fn get_country(ip: &IpAddr, cache: &mut HashMap<IpAddr, String>) -> Result<String, Error> {
    info!("get country for {}", ip.to_string());
    let client = reqwest::Client::new();
    let api_key = SETTING
        .get_exit_network()
        .api_key
        .clone()
        .expect("No api key configured!");

    match cache.get(ip) {
        Some(code) => Ok(code.clone()),
        None => {
            let geo_ip_url = format!("http://api.ipapi.com/{}?access_key={}", ip, api_key);
            info!(
                "making geoip request to {} for {}",
                geo_ip_url,
                ip.to_string()
            );

            let res: GeoIPRet = match client.get(&geo_ip_url).send() {
                Ok(mut r) => match r.json() {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to Jsonize geoip response {:?}", e);
                        bail!("Failed to jsonize GeoIP response {:?}", e)
                    }
                },
                Err(e) => {
                    warn!("Get request for GeoIP failed! {:?}", e);
                    bail!("Get request for GeoIP failed {:?}", e)
                }
            };
            info!("Got {:?} from GeoIP request", res);
            cache.insert(*ip, res.country_code.clone());

            Ok(res.country_code)
        }
    }
}

#[test]
#[ignore]
fn test_get_country() {
    get_country(&"8.8.8.8".parse().unwrap(), &mut HashMap::new()).unwrap();
}

fn verify_ip(request_ip: &IpAddr, cache: &mut HashMap<IpAddr, String>) -> Result<(), Error> {
    if SETTING.get_allowed_countries().is_empty() {
        Ok(())
    } else {
        let country = get_country(request_ip, cache)?;

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
        exit_currency: SETTING.get_payment().system_chain,
        netmask: SETTING.get_exit_network().netmask,
        description: SETTING.get_description(),
        verif_mode: match SETTING.get_verif_settings() {
            Some(ExitVerifSettings::Email(_mailer_settings)) => ExitVerifMode::Email,
            None => ExitVerifMode::Off,
        },
    }
}

fn add_dummy(conn: &SqliteConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::*;

    let mut dummy = models::Client::default();

    dummy.internal_ip = SETTING.get_exit_network().exit_start_ip.to_string();
    dummy.mesh_ip = "0.0.0.0".to_string();

    match diesel::insert_into(clients).values(&dummy).execute(&*conn) {
        Err(_e) => {}
        _ => warn!("Inserted dummy, this should only happen once"),
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

    trace!("incrementing dummy: {:?}", dummy);
    let netmask = SETTING.get_exit_network().netmask as u8;

    let new_ip = increment(dummy.internal_ip.parse()?, netmask)?;

    diesel::update(clients.filter(mesh_ip.eq("0.0.0.0")))
        .set(internal_ip.eq(&new_ip.to_string()))
        .execute(&*conn)?;

    Ok(new_ip)
}

fn update_client(client: &ExitClientIdentity, conn: &SqliteConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::{clients, email, last_seen, wg_port, wg_pubkey};
    let mail_addr = match client.clone().reg_details.email {
        Some(mail) => mail.clone(),
        None => bail!("Cloud not find email for {:?}", client.clone()),
    };

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(wg_port.eq(&client.wg_port.to_string()))
        .execute(&*conn)?;

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(wg_pubkey.eq(&client.global.wg_public_key.to_string()))
        .execute(&*conn)?;

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(email.eq(&mail_addr))
        .execute(&*conn)?;

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(last_seen.eq(secs_since_unix_epoch() as i32))
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

pub fn secs_since_unix_epoch() -> i32 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() as i32
}

// we match on email not key? that has interesting implications for
// shared emails
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
    let rand_code: u64 = rng.gen_range(0, 999_999);
    models::Client {
        wg_port: client.wg_port.to_string(),
        mesh_ip: client.global.mesh_ip.to_string(),
        wg_pubkey: client.global.wg_public_key.to_string(),
        eth_address: client.global.eth_address.to_string(),
        nickname: client.global.nickname.unwrap_or_default().to_string(),
        internal_ip: new_ip.to_string(),
        email: client.reg_details.email.clone().unwrap_or_default(),
        country,
        email_code: format!("{:06}", rand_code),
        verified: false,
        email_sent_time: 0,
        last_seen: 0,
    }
}

fn verif_done(client: &models::Client) -> Result<bool, Error> {
    Ok(client.verified || SETTING.get_verif_settings().is_none())
}

fn send_mail(client: &models::Client) -> Result<(), Error> {
    if SETTING.get_verif_settings().is_none() {
        return Ok(());
    };
    let ExitVerifSettings::Email(mailer) = SETTING.get_verif_settings().unwrap();

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
        )?)
        .build()?;

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

        match verify_ip(&msg.1, &mut self.geoip_cache) {
            Ok(_) => conn.transaction::<_, Error, _>(|| {
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

                    if verif_done(&their_record)? {
                        info!("{:?} is now registered", client);
                        Ok(ExitState::Registered {
                            our_details: ExitClientDetails {
                                client_internal_ip: their_record.internal_ip.parse()?,
                            },
                            general_details: get_exit_info(),
                            message: "Registration OK".to_string(),
                        })
                    } else {
                        let cooldown = match SETTING.get_verif_settings() {
                            Some(ExitVerifSettings::Email(mailer)) => mailer.email_cooldown as i32,
                            None => bail!("There is no verification configured!"),
                        };
                        let time_since_last_email =
                            secs_since_unix_epoch() - their_record.email_sent_time;

                        if time_since_last_email < cooldown {
                            Ok(ExitState::GotInfo {
                                general_details: get_exit_info(),
                                message: format!(
                                    "Wait {} more seconds for verification cooldown",
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

                    let new_ip = incr_dummy(&conn)?;

                    let user_country = if SETTING.get_allowed_countries().is_empty() {
                        String::new()
                    } else {
                        get_country(&msg.1, &mut self.geoip_cache)?
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
            }),
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

                if !verif_done(&their_record)? {
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

pub struct DeleteClient(pub ExitClient);
impl Message for DeleteClient {
    type Result = Result<(), Error>;
}

impl Handler<DeleteClient> for DbClient {
    type Result = Result<(), Error>;

    fn handle(&mut self, client: DeleteClient, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::*;
        let client = client.0;
        info!("Deleting all clients in {:?}", &SETTING.get_db_file());
        let connection = match SqliteConnection::establish(&SETTING.get_db_file()) {
            Ok(connection) => connection,
            Err(e) => {
                error!("We could not connect to the database file! {:?}", e);
                bail!("Could not connect to database file!")
            }
        };
        let mesh_ip_string = client.mesh_ip.to_string();
        let statement = clients.find(&mesh_ip_string);
        r#try!(delete(statement).execute(&connection));
        Ok(())
    }
}

// for backwards compatibility with entires that do not have a timestamp
// new entires will be initialized and updated as part of the normal flow
pub struct SetClientTimestamp(pub ExitClient);
impl Message for SetClientTimestamp {
    type Result = Result<(), Error>;
}

impl Handler<SetClientTimestamp> for DbClient {
    type Result = Result<(), Error>;

    fn handle(&mut self, client: SetClientTimestamp, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::*;
        let client = client.0;
        info!("Deleting all clients in {:?}", &SETTING.get_db_file());
        let connection = match SqliteConnection::establish(&SETTING.get_db_file()) {
            Ok(connection) => connection,
            Err(e) => {
                error!("We could not connect to the database file! {:?}", e);
                bail!("Could not connect to database file!")
            }
        };
        diesel::update(clients.find(&client.mesh_ip.to_string()))
            .set(last_seen.eq(secs_since_unix_epoch() as i32))
            .execute(&connection)?;
        Ok(())
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
        r#try!(delete(clients).execute(&connection));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn increment_basic_v4() {
        let addr1: IpAddr = [0, 0, 0, 0].into();
        let addr2: IpAddr = [0, 0, 0, 1].into();
        assert_eq!(increment(addr1, 16).unwrap(), addr2);
    }

    #[test]
    fn increment_overflow_v4() {
        let addr1: IpAddr = [0, 0, 0, 255].into();
        let addr2: IpAddr = [0, 0, 1, 0].into();
        assert_eq!(increment(addr1, 16).unwrap(), addr2);
    }
    #[test]
    fn increment_out_of_bounds_simple_v4() {
        let addr1: IpAddr = [0, 0, 255, 255].into();
        assert!(increment(addr1, 16).is_err());
    }

    #[test]
    fn increment_basic_v6() {
        let addr1: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into();
        let addr2: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].into();
        assert_eq!(increment(addr1, 112).unwrap(), addr2);
    }

    #[test]
    fn increment_overflow_v6() {
        let addr1: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255].into();
        let addr2: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0].into();
        assert_eq!(increment(addr1, 112).unwrap(), addr2);
    }
    #[test]
    fn increment_out_of_bounds_simple_v6() {
        let addr1: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255].into();
        assert!(increment(addr1, 112).is_err());
    }
}
