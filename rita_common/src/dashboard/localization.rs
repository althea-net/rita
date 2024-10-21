use actix_web::{HttpRequest, HttpResponse};
use phonenumber::Mode;
use settings::localization::LocalizationSettings;

/// A version of the localization struct that serializes into a more easily
/// consumable form
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LocalizationReturn {
    pub display_currency_symbol: bool,
    pub support_number: String,
}

impl From<LocalizationSettings> for LocalizationReturn {
    fn from(input: LocalizationSettings) -> Self {
        LocalizationReturn {
            display_currency_symbol: input.display_currency_symbol,
            support_number: input
                .support_number
                .format()
                .mode(Mode::National)
                .to_string(),
        }
    }
}

pub async fn get_localization(_req: HttpRequest) -> HttpResponse {
    debug!("/localization GET hit");
    let localization = settings::get_rita_common().payment.localization;
    HttpResponse::Ok().json(localization)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AmountRequest {
    amount: f32,
}
