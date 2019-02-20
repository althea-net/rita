use super::*;

pub fn get_nickname(_req: HttpRequest) -> Result<HttpResponse, Error> {
    let nick = SETTING.get_network().nickname;

    if nick.is_none() {
        bail!("Nickname not set!")
    } else {
        Ok(HttpResponse::Ok().json(nick.unwrap().to_string()))
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
