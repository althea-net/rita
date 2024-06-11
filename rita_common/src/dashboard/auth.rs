use actix_web_async::{http::StatusCode, web::Json, HttpResponse};
use clarity::utils::bytes_to_hex_str;
use crate::{RitaCommonError, KI};
use settings::set_rita_common;
use sha3::{Digest, Sha3_512};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct RouterPassword {
    pub password: String,
}

pub async fn set_pass(router_pass: Json<RouterPassword>) -> HttpResponse {
    debug!("/router/password hit with {:?}", router_pass);
    let router_pass = router_pass.into_inner();
    let input_string = router_pass.password.clone() + "RitaSalt";

    debug!("Using {} as sha3 512 input", input_string);
    let mut hasher = Sha3_512::new();
    hasher.update(input_string.as_bytes());
    let hashed_pass = bytes_to_hex_str(&hasher.finalize());

    let mut settings = settings::get_rita_common();
    settings.network.rita_dashboard_password = Some(hashed_pass);
    set_rita_common(settings);

    if let Err(e) = settings::write_config() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("{}", RitaCommonError::SettingsError(e)));
    }

    if KI.is_openwrt() {
        if let Err(e) = KI.set_system_password(router_pass.password) {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e}"));
        }

        // We edited disk contents, force global sync
        if let Err(e) = KI.fs_sync() {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e}"));
        }
    }

    HttpResponse::Ok().json(())
}

#[cfg(test)]
mod tests {
    use clarity::utils::bytes_to_hex_str;
    use hex_literal::hex;
    use sha3::{Digest, Sha3_512};

    #[test]
    fn test_hash() {
        let sha3_output = hex!("881c7d6ba98678bcd96e253086c4048c3ea15306d0d13ff48341c6285ee71102a47b6f16e20e4d65c0c3d677be689dfda6d326695609cbadfafa1800e9eb7fc1");

        let mut hasher = Sha3_512::new();
        hasher.update(b"testing");
        let result = hasher.finalize().to_vec();

        assert_eq!(result.len(), sha3_output.len());
        assert_eq!(result, sha3_output.to_vec());
    }

    #[test]
    fn test_hash_to_string() {
        let sha3sum_output = "881c7d6ba98678bcd96e253086c4048c3ea15306d0d13ff48341c6285ee71102a47b6f16e20e4d65c0c3d677be689dfda6d326695609cbadfafa1800e9eb7fc1";

        let mut hasher = Sha3_512::new();
        hasher.update(b"testing");
        let result = hasher.finalize().to_vec();

        assert_eq!(bytes_to_hex_str(&result), sha3sum_output);
    }
}
