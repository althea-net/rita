use crate::SETTING;
use actix_web::{HttpRequest, Json};
use settings::{localization::LocalizationSettings, RitaCommonSettings};

/// A version of the localization struct that serializes into a more easily
/// consumable form
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LocalizationReturn {
    pub wyre_enabled: bool,
    pub wyre_account_id: String,
    pub display_currency_symbol: bool,
    pub support_number: String,
}

impl From<LocalizationSettings> for LocalizationReturn {
    fn from(input: LocalizationSettings) -> Self {
        LocalizationReturn {
            wyre_enabled: input.wyre_enabled,
            wyre_account_id: input.wyre_account_id,
            display_currency_symbol: input.display_currency_symbol,
            support_number: input.support_number.to_string(),
        }
    }
}

pub fn get_localization(_req: HttpRequest) -> Json<LocalizationReturn> {
    debug!("/localization GET hit");
    let localization = SETTING.get_localization().clone();
    Json(localization.into())
}
