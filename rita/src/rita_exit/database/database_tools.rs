use crate::rita_exit::database::ip_increment::increment;
use crate::rita_exit::database::secs_since_unix_epoch;
use crate::SETTING;
use ::actix_web::Result;
use althea_kernel_interface::ExitClient;
use althea_types::ExitClientIdentity;
use diesel;
use diesel::dsl::{delete, exists};
use diesel::prelude::{ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl};
use diesel::select;
use exit_db::{models, schema};
use failure::Error;
use settings::exit::RitaExitSettings;
use std::net::IpAddr;

pub fn add_dummy(conn: &PgConnection) -> Result<(), Error> {
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

pub fn incr_dummy(conn: &PgConnection) -> Result<IpAddr, Error> {
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

/// updates the last seen time
pub fn update_client(client: &ExitClientIdentity, conn: &PgConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::{clients, email, last_seen, phone};

    if let Some(mail) = client.reg_details.email.clone() {
        diesel::update(clients.find(&client.global.mesh_ip.to_string()))
            .set(email.eq(mail))
            .execute(&*conn)?;
    }

    if let Some(number) = client.reg_details.phone.clone() {
        diesel::update(clients.find(&client.global.mesh_ip.to_string()))
            .set(phone.eq(number))
            .execute(&*conn)?;
    }

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(last_seen.eq(secs_since_unix_epoch() as i64))
        .execute(&*conn)?;

    Ok(())
}

pub fn get_client(ip: IpAddr, conn: &PgConnection) -> Result<models::Client, Error> {
    use self::schema::clients::dsl::{clients, mesh_ip};
    match clients
        .filter(mesh_ip.eq(&ip.to_string()))
        .load::<models::Client>(conn)
    {
        Ok(entry) => Ok(entry[0].clone()),
        Err(e) => {
            error!("We failed to lookup the client {:?} with{:?}", mesh_ip, e);
            bail!("We failed to lookup the client!")
        }
    }
}

/// changes a clients verified value in the database
pub fn verify_client(
    client: &ExitClientIdentity,
    client_verified: bool,
    conn: &PgConnection,
) -> Result<(), Error> {
    use self::schema::clients::dsl::*;

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(verified.eq(client_verified))
        .execute(&*conn)?;

    Ok(())
}

/// Marks a client as verified in the database
pub fn verify_db_client(
    client: &models::Client,
    client_verified: bool,
    conn: &PgConnection,
) -> Result<(), Error> {
    use self::schema::clients::dsl::*;

    diesel::update(clients.find(&client.mesh_ip))
        .set(verified.eq(client_verified))
        .execute(&*conn)?;

    Ok(())
}

/// Marks a registration text as sent in the database
pub fn text_sent(client: &ExitClientIdentity, conn: &PgConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::*;

    diesel::update(clients.find(&client.global.mesh_ip.to_string()))
        .set(text_sent.eq(true))
        .execute(&*conn)?;

    Ok(())
}

pub fn client_exists(ip: &IpAddr, conn: &PgConnection) -> Result<bool, Error> {
    use self::schema::clients::dsl::*;
    trace!("Checking if client exists");
    Ok(select(exists(clients.filter(mesh_ip.eq(ip.to_string())))).get_result(&*conn)?)
}

pub fn delete_client(client: ExitClient, connection: &PgConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::*;
    info!("Deleting clients {:?} in database", client);

    let mesh_ip_string = client.mesh_ip.to_string();
    let statement = clients.find(&mesh_ip_string);
    r#try!(delete(statement).execute(connection));
    Ok(())
}

// for backwards compatibility with entires that do not have a timestamp
// new entires will be initialized and updated as part of the normal flow
pub fn set_client_timestamp(client: ExitClient, connection: &PgConnection) -> Result<(), Error> {
    use self::schema::clients::dsl::*;
    info!("Setting timestamp for client {:?}", client);

    diesel::update(clients.find(&client.mesh_ip.to_string()))
        .set(last_seen.eq(secs_since_unix_epoch()))
        .execute(connection)?;
    Ok(())
}

// we match on email not key? that has interesting implications for
// shared emails
pub fn update_mail_sent_time(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<(), Error> {
    use self::schema::clients::dsl::{clients, email, email_sent_time};
    let mail_addr = match client.clone().reg_details.email {
        Some(mail) => mail.clone(),
        None => bail!("Cloud not find email for {:?}", client.clone()),
    };

    diesel::update(clients.filter(email.eq(mail_addr)))
        .set(email_sent_time.eq(secs_since_unix_epoch()))
        .execute(&*conn)?;

    Ok(())
}

pub fn update_low_balance_notification_time(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<(), Error> {
    use self::schema::clients::dsl::{clients, last_balance_warning_time, wg_pubkey};

    diesel::update(clients.filter(wg_pubkey.eq(client.global.wg_public_key.to_string())))
        .set(last_balance_warning_time.eq(secs_since_unix_epoch()))
        .execute(&*conn)?;

    Ok(())
}
