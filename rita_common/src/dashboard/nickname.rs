use actix_web::{HttpRequest, HttpResponse, Json, Result};
use arrayvec::ArrayString;
use failure::bail;
use failure::Error;

pub fn get_nickname(_req: HttpRequest) -> Result<HttpResponse, Error> {
    let nick = settings::get_rita_common().get_network().nickname;

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
    match ArrayString::<32>::from(new_nick) {
        Ok(new) => {
            let mut common = settings::get_rita_common();
            let mut network = settings::get_rita_common().get_network();
            network.nickname = Some(new);
            common.set_network(network);
            settings::set_rita_common(common);

            // try and save the config and fail if we can't
            if let Err(e) = settings::write_config() {
                return Err(e);
            }

            Ok(HttpResponse::Ok().json(()))
        }
        Err(_e) => bail!("Insufficient capacity for string!"),
    }
}

/// sets a nickname if there is not one already set
#[allow(dead_code)]
pub fn maybe_set_nickname(new_nick: String) -> Result<(), Error> {
    let mut common = settings::get_rita_common();
    let mut network = settings::get_rita_common().get_network();

    if network.nickname.is_none() && (new_nick != "AltheaHome-2.4" || new_nick != "AltheaHome-5") {
        match ArrayString::<32>::from(&new_nick) {
            Ok(new) => {
                network.nickname = Some(new);
                common.set_network(network);
                settings::set_rita_common(common);
                // try and save the config and fail if we can't
                if let Err(e) = settings::write_config() {
                    return Err(e);
                }

                Ok(())
            }
            Err(_e) => bail!("Insufficient capacity for string!"),
        }
    } else {
        Ok(())
    }
}
