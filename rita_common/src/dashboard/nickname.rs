use actix_web::{HttpRequest, HttpResponse, Json, Result};
use arrayvec::ArrayString;

use crate::RitaCommonError;

pub fn get_nickname(_req: HttpRequest) -> Result<HttpResponse, RitaCommonError> {
    let nick = settings::get_rita_common().network.nickname;

    if let Some(nick) = nick {
        Ok(HttpResponse::Ok().json(nick.to_string()))
    } else {
        Err(RitaCommonError::NicknameError("Nickname not set!".to_string()))
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Nickname {
    nickname: String,
}

pub fn set_nickname(nickname: Json<Nickname>) -> Result<HttpResponse, RitaCommonError> {
    let new_nick = &nickname.nickname;
    match ArrayString::<32>::from(new_nick) {
        Ok(new) => {
            let mut common = settings::get_rita_common();
            common.network.nickname = Some(new);
            settings::set_rita_common(common);

            // try and save the config and fail if we can't
            if let Err(e) = settings::write_config() {
                return Err(RitaCommonError::SettingsError(e))
            }

            Ok(HttpResponse::Ok().json(()))
        }
        Err(_e) => Err(RitaCommonError::CapacityError("Insufficient capacity for string!".to_string()))
    }
}

/// sets a nickname if there is not one already set
#[allow(dead_code)]
pub fn maybe_set_nickname(new_nick: String) -> Result<(), RitaCommonError> {
    let mut common = settings::get_rita_common();

    if common.network.nickname.is_none()
        && (new_nick != "AltheaHome-2.4" || new_nick != "AltheaHome-5")
    {
        match ArrayString::<32>::from(&new_nick) {
            Ok(new) => {
                common.network.nickname = Some(new);
                settings::set_rita_common(common);
                // try and save the config and fail if we can't
                if let Err(e) = settings::write_config() {
                    return Err(RitaCommonError::SettingsError(e))
                }

                Ok(())
            }
            Err(_e) => Err(RitaCommonError::CapacityError("Insufficient capacity for string!".to_string()))
        }
    } else {
        Ok(())
    }
}
