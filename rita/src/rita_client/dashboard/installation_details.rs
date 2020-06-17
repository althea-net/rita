use crate::ARGS;
use crate::SETTING;
use actix_web::HttpResponse;
use actix_web::{HttpRequest, Json, Path};
use althea_types::ContactType;
use althea_types::InstallationDetails;
use althea_types::{BillingDetails, MailingAddress};
use settings::{client::RitaClientSettings, FileWrite};

/// This is a utility type that is used by the front end when sending us
/// installation details. This lets us do the validation and parsing here
/// rather than relying on serde to get it right.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct InstallationDetailsPost {
    pub first_name: String,
    pub last_name: String,
    pub country: String,
    pub postal_code: String,
    pub state: Option<String>,
    pub city: String,
    pub street: String,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub client_antenna_ip: Option<String>,
    pub relay_antennas: Option<String>,
    pub phone_client_antennas: Option<String>,
    pub mailing_address: Option<String>,
    pub physical_address: String,
    pub equipment_details: String,
}

pub fn set_installation_details(req: Json<InstallationDetailsPost>) -> HttpResponse {
    let input = req.into_inner();
    trace!("Setting install details with {:?}", input);

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
    // this lets us do less formatting on the frontend and simply
    // take a common separated string and parse it into the correct
    // values
    let mut parsed_relay_antenna_ips = Vec::new();
    let mut parsed_phone_client_anntenna_ips = Vec::new();
    if let Some(val) = input.relay_antennas {
        for ip_str in val.split(',') {
            if let Ok(ip) = ip_str.parse() {
                parsed_relay_antenna_ips.push(ip);
            } else {
                trace!("false to parse {}", ip_str);
                // it's permissible to have nothing but it's not permissable to have improperly
                // formatted data
                return HttpResponse::BadRequest().finish();
            }
        }
    }
    if let Some(val) = input.phone_client_antennas {
        for ip_str in val.split(',') {
            if let Ok(ip) = ip_str.parse() {
                parsed_phone_client_anntenna_ips.push(ip);
            } else {
                trace!("false to parse {}", ip_str);
                return HttpResponse::BadRequest().finish();
            }
        }
    }
    let parsed_client_antenna_ip = match input.client_antenna_ip {
        Some(ip_str) => match ip_str.parse() {
            Ok(ip) => Some(ip),
            Err(_e) => return HttpResponse::BadRequest().finish(),
        },
        None => None,
    };

    // update the contact info, we display this as part of the forum but it's
    // stored separately since it's used elsewhere and sent to the operator tools
    // on it's own.
    exit_client.contact_info = Some(contact_details.into());
    drop(exit_client);

    let new_installation_details = InstallationDetails {
        client_antenna_ip: parsed_client_antenna_ip,
        relay_antennas: parsed_relay_antenna_ips,
        phone_client_antennas: parsed_phone_client_anntenna_ips,
        physical_address: input.physical_address,
        equipment_details: input.equipment_details,
        install_date: None,
    };
    let new_billing_details = BillingDetails {
        user_first_name: input.first_name,
        user_last_name: input.last_name,
        mailing_address: MailingAddress {
            country: input.country,
            postal_code: input.postal_code,
            state: input.state,
            city: input.city,
            street: input.street,
        },
    };

    let mut operator_settings = SETTING.get_operator_mut();
    operator_settings.installation_details = Some(new_installation_details);
    operator_settings.billing_details = Some(new_billing_details);
    operator_settings.display_operator_setup = false;

    drop(operator_settings);

    // try and save the config and fail if we can't
    if let Err(_e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().finish()
}

pub fn get_installation_details(_req: HttpRequest) -> HttpResponse {
    let operator_settings = SETTING.get_operator();
    HttpResponse::Ok().json(operator_settings.installation_details.clone())
}

pub fn display_operator_setup(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(SETTING.get_operator().display_operator_setup)
}

pub fn set_display_operator_setup(val: Path<bool>) -> HttpResponse {
    // scoped so that this value gets dropped before we get to save, preventing
    // deadlock
    {
        SETTING.get_operator_mut().display_operator_setup = val.into_inner();
    }

    // try and save the config and fail if we can't
    if let Err(_e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().finish()
}
