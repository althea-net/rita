//! The Exit info endpoint gathers infromation about exit status and presents it to the dashbaord.

use crate::exit_manager::exit_setup_request;
use crate::RitaClientError;
use actix_web_async::http::StatusCode;
use actix_web_async::{web::Json, web::Path, HttpRequest, HttpResponse};
use althea_types::ExitState;
use babel_monitor::do_we_have_route;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;

use rita_common::RitaCommonError;
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
fn is_selected(exit: &ExitServer, current_exit: Option<&ExitServer>) -> bool {
    match current_exit {
        None => false,
        Some(i) => i == exit,
    }
}

/// Determines if the provided exit is currently selected, if it's setup, and then if it can be reached over
/// the exit tunnel via a ping
fn is_tunnel_working(exit: &ExitServer, current_exit: Option<&ExitServer>) -> bool {
    match (current_exit, is_selected(exit, current_exit)) {
        (Some(exit), true) => match exit.info.general_details() {
            Some(details) => KI
                .ping_check(&details.server_internal_ip, EXIT_PING_TIMEOUT)
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
                    let current_exit = exit_client.get_current_exit();

                    for exit in exit_client.exits.clone().into_iter() {
                        let selected = is_selected(&exit.1, current_exit);
                        let have_route = do_we_have_route(
                            &exit
                                .1
                                .selected_exit
                                .selected_id
                                .expect("Expected exit ip here, but none present"),
                            &route_table_sample,
                        )?;

                        // failed pings block for one second, so we should be sure it's at least reasonable
                        // to expect the pings to work before issuing them.
                        let reachable = if have_route {
                            KI.ping_check(
                                &exit
                                    .1
                                    .selected_exit
                                    .selected_id
                                    .expect("Expected exit ip here, but none present"),
                                EXIT_PING_TIMEOUT,
                            )?
                        } else {
                            false
                        };
                        let tunnel_working = match (have_route, selected) {
                            (true, true) => is_tunnel_working(&exit.1, current_exit),
                            _ => false,
                        };

                        output.push(ExitInfo {
                            nickname: exit.0,
                            exit_settings: exit.1.clone(),
                            is_selected: selected,
                            have_route,
                            is_reachable: reachable,
                            is_tunnel_working: tunnel_working,
                        })
                    }

                    Ok(output)
                }

                Err(e) => Err(RitaClientError::MiscStringError(format!("{}", e))),
            }
        }
        Err(e) => Err(RitaClientError::MiscStringError(format!("{}", e))),
    }
}

pub async fn add_exits(new_exits: Json<HashMap<String, ExitServer>>) -> HttpResponse {
    debug!("/exits POST hit with {:?}", new_exits);
    let mut rita_client = settings::get_rita_client();
    let mut exits = rita_client.exit_client.exits;
    exits.extend(new_exits.into_inner());

    let copy = exits.clone();

    rita_client.exit_client.exits = exits;
    settings::set_rita_client(rita_client);

    HttpResponse::Ok().json(copy)
}

pub async fn get_exit_info(_req: HttpRequest) -> HttpResponse {
    debug!("Exit endpoint hit!");
    match dashboard_get_exit_info() {
        Ok(a) => HttpResponse::Ok().json(a),
        Err(e) => HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{:?}", e)),
    }
}

pub async fn reset_exit(path: Path<String>) -> HttpResponse {
    let exit_name = path.into_inner();
    debug!("/exits/{}/reset hit", exit_name);
    let mut rita_client = settings::get_rita_client();

    let mut exits = rita_client.exit_client.exits;
    let mut ret = HashMap::new();

    if let Some(exit) = exits.get_mut(&exit_name) {
        info!(
            "Changing exit {:?} state to New, and deleting wg_exit tunnel",
            exit_name
        );
        exit.info = ExitState::New;

        if let Err(e) = KI.del_interface("wg_exit") {
            error!("Failed to delete wg_exit {:?}", e)
        };
        rita_client.exit_client.exits = exits;
        settings::set_rita_client(rita_client);
        HttpResponse::Ok().json(ret)
    } else {
        error!("Requested a reset on unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested reset on unknown exit {:?}", exit_name),
        );

        HttpResponse::build(StatusCode::BAD_REQUEST).json(ret)
    }
}

pub async fn select_exit(path: Path<String>) -> HttpResponse {
    let exit_name = path.into_inner();
    debug!("/exits/{}/select hit", exit_name);

    let mut rita_client = settings::get_rita_client();
    let mut exit_client = rita_client.exit_client;
    let mut ret = HashMap::new();

    if exit_client.exits.contains_key(&exit_name) {
        info!("Selecting exit {:?}", exit_name);
        exit_client.current_exit = Some(exit_name);
        rita_client.exit_client = exit_client;
        settings::set_rita_client(rita_client);

        // try and save the config and fail if we can't
        if let Err(e) = settings::write_config() {
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .json(format!("{:?}", RitaCommonError::SettingsError(e)));
        }

        HttpResponse::Ok().json(ret)
    } else {
        error!("Requested selection of an unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested selection of an unknown exit {:?}", exit_name),
        );
        HttpResponse::build(StatusCode::BAD_REQUEST).json(ret)
    }
}

pub async fn register_to_exit(path: Path<String>) -> HttpResponse {
    let exit_name = path.into_inner();
    info!("/exits/{}/register hit", exit_name);

    info!("Attempting to register on exit {:?}", exit_name);

    let mut ret = HashMap::new();
    if let Err(e) = exit_setup_request(exit_name, None).await {
        error!("exit_setup_request() failed with: {:?}", e);
        ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
        ret.insert("rust_error".to_owned(), format!("{:?}", e));
        return HttpResponse::build(StatusCode::BAD_REQUEST).json(ret);
    }
    HttpResponse::Ok().json(ret)
}

pub async fn verify_on_exit_with_code(path: Path<(String, String)>) -> HttpResponse {
    let (exit_name, code) = path.into_inner();
    debug!("/exits/{}/verify/{} hit", exit_name, code);

    let mut ret = HashMap::new();
    if let Err(e) = exit_setup_request(exit_name, Some(code)).await {
        error!("exit_setup_request() failed with: {:?}", e);
        ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
        ret.insert("rust_error".to_owned(), format!("{:?}", e));
        return HttpResponse::build(StatusCode::BAD_REQUEST).json(ret);
    }
    HttpResponse::Ok().json(ret)
}
