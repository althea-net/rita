use std::net::Ipv4Addr;

use actix_web::{web::Json, HttpRequest, HttpResponse};
use althea_kernel_interface::run_command;
use althea_types::Identity;
use ipnetwork::Ipv4Network;
use settings::exit::ExitIpv4RoutingSettings;

pub async fn get_exit_network_settings(_req: HttpRequest) -> HttpResponse {
    let settings = settings::get_rita_exit().exit_network;
    HttpResponse::Ok().json(settings)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExitModeRequest {
    mode: String,
    subnet: Ipv4Network,
    gateway: Ipv4Addr,
    external_ip: Ipv4Addr,
    broadcast_ip: Ipv4Addr,
    static_assignments: Vec<Identity>,
}

/// setter for exit mode: Default(masquerade), SNAT, CGNAT. we must take in subnet, gateway, external_ip, broadcast_ip
/// and static_assignments
pub async fn set_exit_mode(req: Json<ExitModeRequest>) -> HttpResponse {
    // breakaway case: if we are being turned to default, simply set the settings and return
    if req.mode == "MASQUERADENAT" {
        let mut settings = settings::get_rita_exit();
        settings.exit_network.ipv4_routing = ExitIpv4RoutingSettings::MASQUERADENAT;
        let _ = run_command("reboot", &[]);
        return HttpResponse::Ok().finish();
    }
    // update the settings
    let mut ipv4_routing_settings = match req.mode.as_str() {
        "SNAT" => ExitIpv4RoutingSettings::SNAT {
            subnet: req.subnet,
            gateway_ipv4: req.gateway,
            external_ipv4: req.external_ip,
            broadcast_ipv4: req.broadcast_ip,
            static_assignments: Vec::new(),
        },
        "CGNAT" => ExitIpv4RoutingSettings::CGNAT {
            subnet: req.subnet,
            gateway_ipv4: req.gateway,
            external_ipv4: req.external_ip,
            broadcast_ipv4: req.broadcast_ip,
            static_assignments: Vec::new(),
        },
        _ => {
            return HttpResponse::BadRequest().finish();
        }
    };
    match ipv4_routing_settings.validate() {
        Ok(_) => {
            // add in the static assignments
            for id in req.static_assignments.iter() {
                match ipv4_routing_settings.maybe_add_static_assignment(*id) {
                    Ok(_) => (),
                    Err(_e) => {
                        return HttpResponse::InternalServerError().finish();
                    }
                }
            }
            let mut settings = settings::get_rita_exit();
            settings.exit_network.ipv4_routing = ipv4_routing_settings;
            //save the settings
            settings::set_rita_exit(settings);
        }
        Err(_e) => {
            return HttpResponse::BadRequest().finish();
        }
    }
    let _ = run_command("reboot", &[]);
    HttpResponse::Ok().finish()
}

/// Returns the next static ipv4 that can be assigned to a client
pub async fn get_next_static_ip(req: Json<ExitModeRequest>) -> HttpResponse {
    // first validate the settings
    let mut settings = match req.mode.as_str() {
        "SNAT" => {
            let settings = ExitIpv4RoutingSettings::SNAT {
                subnet: req.subnet,
                gateway_ipv4: req.gateway,
                external_ipv4: req.external_ip,
                broadcast_ipv4: req.broadcast_ip,
                static_assignments: Vec::new(),
            };
            match settings.validate() {
                Ok(_) => settings,
                Err(_e) => {
                    return HttpResponse::BadRequest().finish();
                }
            }
        }
        "CGNAT" => {
            let settings = ExitIpv4RoutingSettings::CGNAT {
                subnet: req.subnet,
                gateway_ipv4: req.gateway,
                external_ipv4: req.external_ip,
                broadcast_ipv4: req.broadcast_ip,
                static_assignments: Vec::new(),
            };
            match settings.validate() {
                Ok(_) => settings,
                Err(_e) => {
                    return HttpResponse::BadRequest().finish();
                }
            }
        }
        _ => {
            error!("Invalid mode: {}", req.mode);
            return HttpResponse::BadRequest().finish();
        }
    };
    // add in the static assignments to increment correctly
    for id in req.static_assignments.iter() {
        match settings.maybe_add_static_assignment(*id) {
            Ok(_) => (),
            Err(_e) => {
                return HttpResponse::InternalServerError().finish();
            }
        }
    }
    // get the next static ip
    match settings.get_next_static_ip() {
        Some(ip) => HttpResponse::Ok().json(ip),
        None => HttpResponse::InternalServerError().finish(),
    }
}

#[cfg(test)]
mod test {}
