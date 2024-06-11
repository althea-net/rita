use actix_web_async::http::StatusCode;
use actix_web_async::web::Path;
use actix_web_async::HttpRequest;
use actix_web_async::HttpResponse;
use althea_kernel_interface::file_io::get_lines;
use althea_kernel_interface::file_io::write_out;
use crate::RitaCommonError;
use crate::KI;
use crate::DROPBEAR_CONFIG;
static FIREWALL_CONFIG: &str = "/etc/config/firewall";

pub async fn get_remote_access_status(_req: HttpRequest) -> HttpResponse {
    if !KI.is_openwrt() {
        return HttpResponse::new(StatusCode::BAD_REQUEST);
    }
    HttpResponse::Ok().json(match check_dropbear_config() {
        Ok(a) => a,
        Err(e) => {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e}"));
        }
    })
}

// todo try and combine the above function with this one and maintain
// the http responses at some point
#[allow(dead_code)]
pub fn get_remote_access_internal() -> Result<bool, RitaCommonError> {
    if !KI.is_openwrt() {
        return Err(RitaCommonError::ConversionError("Not Openwrt!".to_string()).into());
    }
    check_dropbear_config()
}

fn check_dropbear_config() -> Result<bool, RitaCommonError> {
    let lines = get_lines(DROPBEAR_CONFIG)?;
    // the old style config has one server, the new style config has two
    // the old style has 'option interface' which indicates LAN only listening
    // and is fine as an indicator. The new style has two blocks, the top on
    // port 2200 and the bottom with 'option interface' to keep it constrained
    // to lan.
    for line in lines.iter() {
        if line.contains("2200") && line.contains("option Port") {
            // we have found our new port listening, we're good
            return Ok(true);
        } else if line.contains("option Interface") {
            // since the new config has port 2200 above option interface
            // in the second server directive this means we are not enabled
            // in the new config. Likewise the old config doesn't have the
            // interface directive at all. Either way if we hit this remote
            // access is not enabled
            return Ok(false);
        }
    }
    // we have found neither the new configs listening directive, nor the old configs
    // not listening line, this means we're in the old config and have remote access
    // enabled
    Ok(true)
}

pub async fn set_remote_access_status(path: Path<bool>) -> HttpResponse {
    let remote_access = path.into_inner();
    if let Err(e) = set_remote_access_internal(remote_access) {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e}"));
    }
    HttpResponse::Ok().json(())
}

pub fn set_remote_access_internal(remote_access: bool) -> Result<(), RitaCommonError> {
    let mut lines: Vec<String> = Vec::new();
    // the wonky spacing is actually important, keep it around.
    // dropbear server one is ours for remote access, it never allows password
    // auth and listens on the higher port 2200
    if remote_access {
        lines.push("config dropbear".to_string());
        lines.push("        option PasswordAuth 'no'".to_string());
        lines.push("        option Port         '2200'".to_string());
    }
    // password auth is enabled by default
    lines.push("config dropbear".to_string());
    lines.push("        option Port         '22'".to_string());
    lines.push("        option Interface    'lan'".to_string());

    write_out(DROPBEAR_CONFIG, lines)?;
    KI.run_command("/etc/init.d/dropbear", &["restart"])?;

    // this adds the updated rules to the firewall config, notice the versioning on the
    // firewall rules. The old ones will be left in place.
    let mut firewall_lines = get_lines(FIREWALL_CONFIG)?;
    let mut needs_mesh_ssh = true;
    let mut needs_wan_ssh = true;
    for line in firewall_lines.iter() {
        if line.contains("Allow-Mesh-SSH-2") {
            needs_mesh_ssh = false;
        }
        if line.contains("Allow-WAN-SSH") {
            needs_wan_ssh = false;
        }
    }
    if needs_mesh_ssh {
        firewall_lines.push("".to_string());
        firewall_lines.push("config rule".to_string());
        firewall_lines.push("        option name             Allow-Mesh-SSH-2".to_string());
        firewall_lines.push("        option src              mesh".to_string());
        firewall_lines.push("        option dest_port        2200".to_string());
        firewall_lines.push("        option target           ACCEPT".to_string());
    }
    if needs_wan_ssh {
        firewall_lines.push("".to_string());
        firewall_lines.push("config rule".to_string());
        firewall_lines.push("        option name             Allow-WAN-SSH".to_string());
        firewall_lines.push("        option src              backhaul".to_string());
        firewall_lines.push("        option dest_port        2200".to_string());
        firewall_lines.push("        option target           ACCEPT".to_string());
    }
    if needs_mesh_ssh || needs_wan_ssh {
        write_out(FIREWALL_CONFIG, firewall_lines)?;
        KI.run_command("reboot", &[])?;
        Ok(())
    } else {
        Ok(())
    }
}
