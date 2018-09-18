/*
The Exit info endpoint gathers infromation about exit status and presents it to the dashbaord.
*/

use actix::prelude::*;
use failure::Error;
use std::net::{SocketAddr, TcpStream};

use babel_monitor::Babel;
use rita_common::dashboard::Dashboard;
use settings::ExitServer;
use settings::RitaClientSettings;
use settings::RitaCommonSettings;
use KI;
use SETTING;

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

impl Message for GetExitInfo {
    type Result = Result<Vec<ExitInfo>, Error>;
}

/// Checks if the provided exit is selected
fn is_selected(exit: &ExitServer, current_exit: Option<&ExitServer>) -> Result<bool, Error> {
    match current_exit {
        None => Ok(false),
        Some(i) => Ok(i == exit),
    }
}

/// Determines if the provide exit is currently selected, if it's setup, and then if it can be reached over
/// the exit tunnel via a ping
fn is_tunnel_working(exit: &ExitServer, current_exit: Option<&ExitServer>) -> Result<bool, Error> {
    if current_exit.is_some() && is_selected(exit, current_exit)? {
        if current_exit.unwrap().info.general_details().is_some() {
            let internal_ip = current_exit
                .unwrap()
                .clone()
                .info
                .general_details()
                .unwrap()
                .server_internal_ip;
            KI.ping_check_v4(&internal_ip)
        } else {
            return Ok(false);
        }
    } else {
        return Ok(false);
    }
}

impl Handler<GetExitInfo> for Dashboard {
    type Result = Result<Vec<ExitInfo>, Error>;

    fn handle(&mut self, _msg: GetExitInfo, _ctx: &mut Self::Context) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;
        let mut babel = Babel::new(stream);
        babel.start_connection()?;
        let route_table_sample = babel.parse_routes()?;

        let mut output = Vec::new();

        let exit_client = SETTING.get_exit_client();
        let current_exit = exit_client.get_current_exit();

        for exit in exit_client.exits.clone().into_iter() {
            let selected = is_selected(&exit.1, current_exit)?;
            let have_route = babel.do_we_have_route(&exit.1.id.mesh_ip, &route_table_sample)?;

            // failed pings block for one second, so we should be sure it's at least reasonable
            // to expect the pings to work before issuing them.
            let reachable = match have_route {
                true => KI.ping_check_v6(&exit.1.id.mesh_ip)?,
                false => false,
            };
            let tunnel_working = match (have_route, selected) {
                (true, true) => is_tunnel_working(&exit.1, current_exit)?,
                _ => false,
            };

            output.push(ExitInfo {
                nickname: exit.0,
                exit_settings: exit.1.clone(),
                is_selected: selected,
                have_route: have_route,
                is_reachable: reachable,
                is_tunnel_working: tunnel_working,
            })
        }

        Ok(output)
    }
}
