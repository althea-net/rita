use crate::SETTING;
use actix_web::HttpResponse;
use actix_web::{HttpRequest, Json};
use althea_types::ContactType;
use althea_types::InstallationDetails;
use settings::client::RitaClientSettings;
use std::net::Ipv4Addr;
use std::time::SystemTime;

/// This is a utility type that is used by the front end when sending us
/// installation details. This lets us do the validation and parsing here
/// rather than relying on serde to get it right.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct InstallationDetailsPost {
    pub phone: Option<String>,
    pub email: Option<String>,
    pub client_antenna_ip: Option<Ipv4Addr>,
    pub relay_antennas: Vec<Ipv4Addr>,
    pub phone_client_antennas: Vec<Ipv4Addr>,
    pub mailing_address: Option<String>,
    pub physical_address: String,
    pub equipment_details: String,
}

pub fn set_installation_details(req: Json<InstallationDetailsPost>) -> HttpResponse {
    let input = req.into_inner();
    let mut exit_client = SETTING.get_exit_client_mut();
    let contact_details = match (input.phone, input.email) {
        (None, None) => return HttpResponse::BadRequest().finish(),
        (Some(phone), Some(email)) => match (phone.parse(), email.parse()) {
            (Ok(p), Ok(e)) => ContactType::Both {
                number: p,
                email: e,
            },
            (_, _) => return HttpResponse::BadRequest().finish(),
        },
        (None, Some(email)) => match email.parse() {
            Ok(e) => ContactType::Email { email: e },
            Err(_e) => return HttpResponse::BadRequest().finish(),
        },
        (Some(phone), None) => match phone.parse() {
            Ok(p) => ContactType::Phone { number: p },
            Err(_e) => return HttpResponse::BadRequest().finish(),
        },
    };
    // update the contact info, we display this as part of the forum but it's
    // stored separately since it's used elsewhere and sent to the operator tools
    // on it's own.
    exit_client.contact_info = Some(contact_details);
    drop(exit_client);

    let new_installation_details = InstallationDetails {
        client_antenna_ip: input.client_antenna_ip,
        relay_antennas: input.relay_antennas,
        phone_client_antennas: input.phone_client_antennas,
        mailing_address: input.mailing_address,
        physical_address: input.physical_address,
        equipment_details: input.equipment_details,
        install_date: SystemTime::now(),
    };

    let mut operator_settings = SETTING.get_operator_mut();
    operator_settings.installation_details = Some(new_installation_details);
    HttpResponse::Ok().finish()
}

pub fn get_installation_details(_req: HttpRequest) -> HttpResponse {
    let operator_settings = SETTING.get_operator();
    HttpResponse::Ok().json(operator_settings.installation_details.clone())
}
