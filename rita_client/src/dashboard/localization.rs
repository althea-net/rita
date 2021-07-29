use actix_web::error::JsonPayloadError;
use actix_web::{client, HttpMessage, HttpRequest, HttpResponse, Json};
use althea_types::WyreReservationRequestCarrier;
use althea_types::WyreReservationResponse;
use failure::Error;
use futures01::future;
use futures01::future::Either;
use futures01::Future;
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

pub fn get_localization(_req: HttpRequest) -> Json<LocalizationReturn> {
    debug!("/localization GET hit");
    let localization = settings::get_rita_client().localization;
    Json(localization.into())
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
pub fn get_wyre_reservation(
    amount: Json<AmountRequest>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
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
    #[cfg(not(feature = "operator_debug"))]
    let api_url = "https://operator.althea.net:8080/wyre_reservation";
    #[cfg(feature = "operator_debug")]
    let api_url = "http://192.168.10.2:8080/wyre_reservation";
    Box::new(
        client::post(&api_url)
            .timeout(Duration::from_secs(10))
            .json(&payload)
            .unwrap()
            .send()
            .then(move |response| match response {
                Ok(response) => Either::A(response.json().then(
                    move |value: Result<WyreReservationResponse, JsonPayloadError>| match value {
                        Ok(value) => Ok(HttpResponse::Ok().json(value)),
                        Err(e) => {
                            error!("Failed to deserialize wyre response  {:?}", e);
                            Ok(HttpResponse::InternalServerError().finish())
                        }
                    },
                )),
                Err(e) => {
                    error!("Failed to send wyre request {:?}", e);
                    Either::B(future::ok(HttpResponse::InternalServerError().finish()))
                }
            }),
    )
}
