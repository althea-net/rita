use crate::rita_exit::database::database_tools::update_mail_sent_time;
use crate::rita_exit::database::database_tools::verify_client;
use crate::rita_exit::database::get_exit_info;
use crate::rita_exit::database::secs_since_unix_epoch;
use crate::rita_exit::database::struct_tools::verif_done;
use crate::SETTING;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState};
use diesel;
use diesel::prelude::PgConnection;
use exit_db::models;
use failure::Error;
use futures01::future;
use futures01::future::Future;
use handlebars::Handlebars;
use lettre::file::FileTransport;
use lettre::smtp::authentication::{Credentials, Mechanism};
use lettre::smtp::extension::ClientId;
use lettre::smtp::ConnectionReuseParameters;
use lettre::{SmtpClient, Transport};
use lettre_email::EmailBuilder;
use settings::exit::EmailVerifSettings;
use settings::exit::ExitVerifSettings;
use settings::exit::RitaExitSettings;

pub fn send_mail(client: &models::Client) -> Result<(), Error> {
    let mailer = match SETTING.get_verif_settings() {
        Some(ExitVerifSettings::Email(mailer)) => mailer,
        Some(_) => bail!("Verification mode is not email!"),
        None => bail!("No verification mode configured!"),
    };

    info!("Sending exit signup email for client");

    let reg = Handlebars::new();

    let email = EmailBuilder::new()
        .to(client.email.clone())
        .from(mailer.from_address)
        .subject(mailer.signup_subject)
        // TODO: maybe have a proper templating engine
        .text(reg.render_template(
            &mailer.signup_body,
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

/// handles the minutia of emails and cooldowns
pub fn handle_email_registration(
    client: &ExitClientIdentity,
    their_record: &exit_db::models::Client,
    conn: &PgConnection,
    cooldown: i64,
) -> impl Future<Item = ExitState, Error = Error> {
    let mut their_record = their_record.clone();
    if client.reg_details.email_code == Some(their_record.email_code.clone()) {
        info!("email verification complete for {:?}", client);

        match verify_client(&client, true, &conn) {
            Ok(_) => (),
            Err(e) => return future::err(e),
        }
        their_record.verified = true;
    }

    if verif_done(&their_record) {
        info!("{:?} is now registered", client);

        let client_internal_ip = match their_record.internal_ip.parse() {
            Ok(ip) => ip,
            Err(e) => return future::err(format_err!("{:?}", e)),
        };
        let client_internal_ipv6 = match their_record.internal_ipv6.parse() {
            // the option can be removed once all clients have upgraded, right
            // now we need it to handle old clients checking in and getting new ipv6 assignments
            Ok(ip) => Some(ip),
            Err(e) => return future::err(format_err!("{:?}", e)),
        };
        future::ok(ExitState::Registered {
            our_details: ExitClientDetails {
                client_internal_ip,
                client_internal_ipv6,
            },
            general_details: get_exit_info(),
            message: "Registration OK".to_string(),
        })
    } else {
        let time_since_last_email = secs_since_unix_epoch() - their_record.email_sent_time;

        if time_since_last_email < cooldown {
            future::ok(ExitState::GotInfo {
                general_details: get_exit_info(),
                message: format!(
                    "Wait {} more seconds for verification cooldown",
                    cooldown - time_since_last_email
                ),
                auto_register: true,
            })
        } else {
            match update_mail_sent_time(&client, &conn) {
                Ok(_) => (),
                Err(e) => return future::err(e),
            }
            match send_mail(&their_record) {
                Ok(_) => (),
                Err(e) => return future::err(e),
            }
            future::ok(ExitState::Pending {
                general_details: get_exit_info(),
                message: "awaiting email verification".to_string(),
                email_code: None,
                phone_code: None,
            })
        }
    }
}

pub fn send_low_balance_email(email: &str, mailer: EmailVerifSettings) -> Result<(), Error> {
    info!("Sending low balance email to {}", email);

    let email = EmailBuilder::new()
        .to(email)
        .from(mailer.from_address)
        .subject(mailer.balance_notification_subject)
        .text(mailer.balance_notification_body)
        .build()?;

    if mailer.test {
        let mut mailer = FileTransport::new(&mailer.test_dir);
        mailer.send(email.into())?;
    } else {
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
