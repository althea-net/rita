use crate::ARGS;
use crate::SETTING;
use ::actix_web::{HttpRequest, HttpResponse, Json, Result};
use ::settings::FileWrite;
use ::settings::RitaCommonSettings;
use arrayvec::ArrayString;
use failure::Error;

pub fn get_nickname(_req: HttpRequest) -> Result<HttpResponse, Error> {
    let nick = SETTING.get_network().nickname;

    if let Some(nick) = nick {
        Ok(HttpResponse::Ok().json(nick.to_string()))
    } else {
        bail!("Nickname not set!")
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Nickname {
    nickname: String,
}

pub fn set_nickname(nickname: Json<Nickname>) -> Result<HttpResponse, Error> {
    let new_nick = &nickname.nickname;
    match ArrayString::<[u8; 32]>::from(new_nick) {
        Ok(new) => {
            SETTING.get_network_mut().nickname = Some(new);

            // try and save the config and fail if we can't
            if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
                return Err(e);
            }
            Ok(HttpResponse::Ok().json(()))
        }
        Err(_e) => bail!("Insufficient capacity for string!"),
    }
}
