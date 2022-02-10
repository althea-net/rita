use actix_web_async::http::StatusCode;
use actix_web_async::{web::Json, HttpRequest, HttpResponse};
use althea_types::{WyreReservationRequestCarrier, WyreReservationResponse};
use phonenumber::Mode;
use settings::localization::LocalizationSettings;

use std::time::Duration;

/// A version of the localization struct that serializes into a more easily
/// consumable form
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LocalizationReturn {
    pub wyre_enabled: bool,
    pub display_currency_symbol: bool,
    pub support_number: String,
}

impl From<LocalizationSettings> for LocalizationReturn {
    fn from(input: LocalizationSettings) -> Self {
        LocalizationReturn {
            wyre_enabled: input.wyre_enabled,
            display_currency_symbol: input.display_currency_symbol,
            support_number: input
                .support_number
                .format()
                .mode(Mode::National)
                .to_string(),
        }
    }
}

pub fn get_localization(_req: HttpRequest) -> HttpResponse {
    debug!("/localization GET hit");
    let localization = settings::get_rita_client().localization;
    HttpResponse::Ok().json(localization)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AmountRequest {
    amount: f32,
}

/// This retrieves the reservation url from the operator tools server, which
/// has to go through the process of getting a link using the bearer auth token
/// wyre provides. In theory this is actually a general 'redirect user to payment
/// processor' endpoint that we could integrate with Moonpay or another provider
/// TODO generalize naming of this endpoint
pub async fn get_wyre_reservation(amount: Json<AmountRequest>) -> HttpResponse {
    info!("Getting wyre reservation");

    let mut rita_client = settings::get_rita_client();
    let exit_client = rita_client.exit_client;
    let operator = rita_client.operator;
    let id = settings::get_rita_client().get_identity();
    let payload = WyreReservationRequestCarrier {
        amount: amount.amount,
        address: None,
        id,
        contact_info: exit_client.contact_info.clone().unwrap().into(),
        billing_details: operator.billing_details.clone().unwrap(),
    };
    rita_client.exit_client = exit_client;
    rita_client.operator = operator;
    settings::set_rita_client(rita_client);

    let api_url: &str;
    if cfg!(feature = "dev_env") {
        api_url = "0.0.0.0:8080/wyre_reservation";
    } else if cfg!(feature = "operator_debug") {
        api_url = "http://192.168.10.2:8080/wyre_reservation";
    } else {
        api_url = "https://operator.althea.net:8080/wyre_reservation";
    }

    let client = awc::Client::default();
    let response = client
        .post(api_url)
        .timeout(Duration::from_secs(10))
        .send_json(&payload)
        .await;
    let mut response = match response {
        Ok(a) => a,
        Err(e) => {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{}", e));
        }
    };

    let value: WyreReservationResponse = match response.json().await {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to deserialize wyre response  {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    HttpResponse::Ok().json(value)
}
