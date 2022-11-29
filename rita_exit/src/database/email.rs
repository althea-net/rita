use crate::database::database_tools::update_mail_sent_time;
use crate::database::database_tools::verify_client;
use crate::database::get_exit_info;
use crate::database::secs_since_unix_epoch;
use crate::database::struct_tools::verif_done;
use crate::get_client_ipv6;
use crate::RitaExitError;

use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState};
use diesel::prelude::PgConnection;
use exit_db::models;
use handlebars::Handlebars;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::authentication::Mechanism;
use lettre::transport::smtp::extension::ClientId;
use lettre::transport::smtp::PoolConfig;
use lettre::FileTransport;
use lettre::{Message, SmtpTransport, Transport};
use serde_json::json;
use settings::exit::ExitVerifSettings;

pub fn send_mail(client: &models::Client) -> Result<(), Box<RitaExitError>> {
    let mailer = match settings::get_rita_exit().verif_settings {
        Some(ExitVerifSettings::Email(mailer)) => mailer,
        Some(_) => {
            return Err(Box::new(RitaExitError::MiscStringError(
                "Verification mode is not email!".to_string(),
            )))
        }
        None => {
            return Err(Box::new(RitaExitError::MiscStringError(
                "No verification mode configured!".to_string(),
            )))
        }
    };

    info!("Sending exit signup email for client");

    let reg = Handlebars::new();

    let email = match Message::builder()
        .to(client.email.clone().parse().unwrap())
        .from(mailer.from_address.parse().unwrap())
        .subject(mailer.signup_subject)
        // TODO: maybe have a proper templating engine
        .body(
            match reg.render_template(
                &mailer.signup_body,
                &json!({"email_code": client.email_code.to_string()}),
            ) {
                Ok(a) => a,
                Err(e) => return Err(Box::new(e.into())),
            },
        ) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };

    if mailer.test {
        let mailer = FileTransport::new(&mailer.test_dir);
        if let Err(e) = mailer.send(&email) {
            return Err(Box::new(e.into()));
        };
    } else {
        let mailer = match SmtpTransport::relay(&mailer.smtp_url) {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        }
        .hello_name(ClientId::Domain(mailer.smtp_domain))
        .credentials(Credentials::new(mailer.smtp_username, mailer.smtp_password))
        .authentication(vec![Mechanism::Plain])
        .pool_config(PoolConfig::new().max_size(20))
        .build();
        if let Err(e) = mailer.send(&email) {
            return Err(Box::new(e.into()));
        };
    }

    Ok(())
}

/// handles the minutia of emails and cooldowns
pub fn handle_email_registration(
    client: &ExitClientIdentity,
    their_record: &exit_db::models::Client,
    conn: &PgConnection,
    cooldown: i64,
) -> Result<ExitState, Box<RitaExitError>> {
    let mut their_record = their_record.clone();
    if client.reg_details.email_code == Some(their_record.email_code.clone()) {
        info!("email verification complete for {:?}", client);

        verify_client(client, true, conn)?;
        their_record.verified = true;
    }

    if verif_done(&their_record) {
        info!("{:?} is now registered", client);

        let client_internal_ip = match their_record.internal_ip.parse() {
            Ok(ip) => ip,
            Err(e) => return Err(Box::new(RitaExitError::AddrParseError(e))),
        };
        let client_internet_ipv6_subnet = get_client_ipv6(&their_record)?;
        Ok(ExitState::Registered {
            our_details: ExitClientDetails {
                client_internal_ip,
                internet_ipv6_subnet: client_internet_ipv6_subnet,
            },
            general_details: get_exit_info(),
            message: "Registration OK".to_string(),
        })
    } else {
        let time_since_last_email = secs_since_unix_epoch() - their_record.email_sent_time;

        if time_since_last_email < cooldown {
            Ok(ExitState::GotInfo {
                general_details: get_exit_info(),
                message: format!(
                    "Wait {} more seconds for verification cooldown",
                    cooldown - time_since_last_email
                ),
            })
        } else {
            update_mail_sent_time(client, conn)?;

            send_mail(&their_record)?;

            Ok(ExitState::Pending {
                general_details: get_exit_info(),
                message: "awaiting email verification".to_string(),
                email_code: None,
                phone_code: None,
            })
        }
    }
}
