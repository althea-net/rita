use crate::rita_client::dashboard::get_lines;
use crate::rita_client::dashboard::write_out;
use crate::KI;
use crate::SETTING;
use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Path;
use failure::Error;
use settings::RitaCommonSettings;

static DROPBEAR_CONFIG: &str = "/etc/config/dropbear";

pub fn get_remote_access_status(_req: HttpRequest) -> Result<HttpResponse, Error> {
    if !KI.is_openwrt() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST));
    }
    let lines = get_lines(DROPBEAR_CONFIG)?;
    for line in lines.iter() {
        if line.contains("option Interface") {
            return Ok(HttpResponse::Ok().json(false));
        }
    }
    Ok(HttpResponse::Ok().json(true))
}

pub fn set_remote_access_status(path: Path<bool>) -> Result<HttpResponse, Error> {
    let remote_access = path.into_inner();
    let mut lines: Vec<String> = Vec::new();
    lines.push("config dropbear".to_string());
    // the wonky spacing is actually important, keep it
    if !remote_access || SETTING.get_network().rita_dashboard_password.is_some() {
        lines.push("        option PasswordAuth 'yes'".to_string());
    }
    lines.push("        option Port         '22'".to_string());
    if !remote_access {
        lines.push("        option Interface    'lan'".to_string());
    }

    write_out(DROPBEAR_CONFIG, lines)?;
    KI.run_command("/etc/init.d/dropbear", &["restart"])?;

    Ok(HttpResponse::Ok().json(()))
}
