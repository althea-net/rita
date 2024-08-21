//! The Exit info endpoint gathers infromation about exit status and presents it to the dashbaord.

use crate::exit_manager::exit_setup_request;
use crate::heartbeat::get_selected_exit_server;
use crate::RitaClientError;
use actix_web_async::http::StatusCode;
use actix_web_async::{web::Path, HttpRequest, HttpResponse};
use althea_types::ExitState;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::parsing::do_we_have_route;
use rita_common::KI;
use settings::client::ExitServer;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Serialize)]
pub struct ExitInfo {
    nickname: String,
    exit_settings: ExitServer,
    is_selected: bool,
    have_route: bool,
    is_reachable: bool,
    is_tunnel_working: bool,
}

pub struct GetExitInfo;

const EXIT_PING_TIMEOUT: Duration = Duration::from_millis(200);

/// Checks if the provided exit is selected
fn is_selected(exit: &ExitServer, current_exit: Option<ExitServer>) -> bool {
    match current_exit {
        None => false,
        Some(i) => i == *exit,
    }
}

/// Determines if the provided exit is currently selected, if it's setup, and then if it can be reached over
/// the exit tunnel via a ping
fn is_tunnel_working(
    exit: &ExitServer,
    current_exit: Option<ExitServer>,
    exit_status: ExitState,
) -> bool {
    match (current_exit.clone(), is_selected(exit, current_exit)) {
        (Some(_exit), true) => match exit_status.general_details() {
            Some(details) => KI
                .ping_check(
                    &details.server_internal_ip,
                    EXIT_PING_TIMEOUT,
                    Some("wg_exit"),
                )
                .unwrap_or(false),
            None => false,
        },
        (_, _) => false,
    }
}

pub fn dashboard_get_exit_info() -> Result<Vec<ExitInfo>, RitaClientError> {
    let babel_port = settings::get_rita_client().network.babel_port;
    match open_babel_stream(babel_port, Duration::from_secs(5)) {
        Ok(mut stream) => {
            match parse_routes(&mut stream) {
                Ok(routes) => {
                    let route_table_sample = routes;
                    let mut output = Vec::new();
                    let rita_client = settings::get_rita_client();
                    let exit_client = rita_client.exit_client;
                    let reg_state = exit_client.registration_state;
                    let current_exit = get_selected_exit_server();

                    for exit in exit_client.bootstrapping_exits.clone().into_iter() {
                        let selected = is_selected(&exit.1, current_exit.clone());
                        info!("Trying to get exit: {}", exit.0.clone());
                        let route_ip = exit.0;
                        let have_route = do_we_have_route(&route_ip, &route_table_sample)?;

                        // failed pings block for one second, so we should be sure it's at least reasonable
                        // to expect the pings to work before issuing them.
                        let reachable = if have_route {
                            KI.ping_check(&route_ip, EXIT_PING_TIMEOUT, None)?
                        } else {
                            false
                        };
                        let tunnel_working = match (have_route, selected) {
                            (true, true) => {
                                is_tunnel_working(&exit.1, current_exit.clone(), reg_state.clone())
                            }
                            _ => false,
                        };

                        output.push(ExitInfo {
                            nickname: exit.0.to_string(),
                            exit_settings: exit.1.clone(),
                            is_selected: selected,
                            have_route,
                            is_reachable: reachable,
                            is_tunnel_working: tunnel_working,
                        })
                    }

                    Ok(output)
                }

                Err(e) => Err(RitaClientError::MiscStringError(format!("{e}"))),
            }
        }
        Err(e) => Err(RitaClientError::MiscStringError(format!("{e}"))),
    }
}

pub async fn get_exit_info(_req: HttpRequest) -> HttpResponse {
    debug!("Exit endpoint hit!");
    match dashboard_get_exit_info() {
        Ok(a) => HttpResponse::Ok().json(a),
        Err(e) => HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e:?}")),
    }
}

pub async fn register_to_exit() -> HttpResponse {
    info!("/exit/register hit");

    let mut ret = HashMap::new();
    if let Err(e) = exit_setup_request(None).await {
        error!("exit_setup_request() failed with: {:?}", e);
        ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
        ret.insert("rust_error".to_owned(), format!("{e:?}"));
        return HttpResponse::build(StatusCode::BAD_REQUEST).json(ret);
    }
    HttpResponse::Ok().json(ret)
}

pub async fn verify_on_exit_with_code(path: Path<String>) -> HttpResponse {
    let code = path.into_inner();
    debug!("/exit/verify/{} hit", code);

    let mut ret = HashMap::new();
    if let Err(e) = exit_setup_request(Some(code)).await {
        error!("exit_setup_request() failed with: {:?}", e);
        ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
        ret.insert("rust_error".to_owned(), format!("{e:?}"));
        return HttpResponse::build(StatusCode::BAD_REQUEST).json(ret);
    }
    HttpResponse::Ok().json(ret)
}
