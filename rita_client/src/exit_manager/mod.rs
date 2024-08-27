//! This module contains utility functions for dealing with the exit signup and connection procedure
//! the procedure goes as follows.
//!
//! Exit is preconfigured with wireguard, mesh ip, and eth address info, this removes the possibility
//! of an effective MITM attack.
//!
//! The exit is queried for info about it that might change, such as it's subnet settings and default
//! route.
//!
//! Once the 'general' settings are acquire we contact the exit with our email, after getting an email
//! we input the confirmation code.
//!
//! The exit then serves up our user specific settings (our own exit internal ip) which we configure
//! and open the wg_exit tunnel. The exit performs the other side of this operation after querying
//! the database and finding a new entry.
//!
//! Signup is complete and the user may use the connection

pub mod encryption;
pub mod exit_loop;
pub mod exit_switcher;
pub mod requests;
pub mod time_sync;
pub mod utils;

use althea_types::ExitListV2;
use althea_types::ExitState;
use exit_switcher::ExitTracker;
use settings::client::SelectedExit;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

/// TODO replace with a component in the exit config struct
const DEFAULT_WG_LISTEN_PORT: u16 = 59998;

lazy_static! {
    pub static ref SELECTED_EXIT_DETAILS: Arc<RwLock<SelectedExitDetails>> =
        Arc::new(RwLock::new(SelectedExitDetails::default()));
}

#[derive(Default)]
pub struct SelectedExitDetails {
    /// information of current exit we are connected to and tracking exit, if connected to one
    /// It also holds information about metrics and degradation values. Look at doc comment on 'set_best_exit' for more
    /// information on what these mean
    pub selected_exit: SelectedExit,
}

/// Data to use identity whether a clients wg exit tunnel needs to be setup up again across ticks
#[derive(Default, Clone)]
pub struct LastExitStates {
    last_exit: Option<IpAddr>,
    last_exit_details: Option<ExitState>,
}

/// An actor which pays the exit
#[derive(Clone, Default)]
pub struct ExitManager {
    pub nat_setup: bool,
    /// Every tick we query an exit endpoint to get a list of exits in that cluster. We use this list for exit switching
    pub exit_list: ExitListV2,
    /// Store last exit here, when we see an exit change, we reset wg tunnels
    pub last_exit_state: LastExitStates,
    pub last_status_request: Option<Instant>,
    /// This tracks metric values of the exit that we potentially consider switching to during every tick.
    /// To switch, this vector needs to be full of values from a single exit.
    pub metric_values: Vec<u16>,
    pub exit_tracker: HashMap<IpAddr, ExitTracker>,
}

/// This functions sets the exit list ONLY IF the list arguments provived is not empty. This is need for the following edge case:
/// When an exit goes down, the endpoint wont repsond, so we have no exits to switch to. By setting only when we have a length > 1
/// we assure that we switch when an exit goes down
pub fn set_exit_list(list: ExitListV2, em_state: &mut ExitManager) -> bool {
    if !list.exit_list.is_empty() {
        em_state.exit_list = list;
        return true;
    }
    false
}

/// Gets the currently selected exit, if none is selected returns the first exit from the bootstrapping list
pub fn get_current_exit() -> IpAddr {
    let selected_exit = SELECTED_EXIT_DETAILS.read().unwrap();
    let ip = selected_exit.selected_exit.selected_id;
    drop(selected_exit);
    if let Some(ip) = ip {
        ip
    } else {
        let client_settings = settings::get_rita_client();
        let exit = client_settings
            .exit_client
            .bootstrapping_exits
            .iter()
            .next()
            .expect("No exits in bootstrapping list")
            .1;
        set_selected_exit(SelectedExit {
            selected_id: Some(exit.exit_id.mesh_ip),
            selected_id_metric: None,
            selected_id_degradation: None,
            tracking_exit: None,
        });
        exit.exit_id.mesh_ip
    }
}

pub fn get_full_selected_exit() -> SelectedExit {
    SELECTED_EXIT_DETAILS.read().unwrap().selected_exit.clone()
}

pub fn set_selected_exit(exit_info: SelectedExit) {
    SELECTED_EXIT_DETAILS.write().unwrap().selected_exit = exit_info;
}

#[cfg(test)]
mod tests {
    use super::*;
    use althea_types::{ExitClientDetails, ExitDetails, ExitVerifMode, Identity, SystemChain};
    use settings::client::ExitServer;
    use utils::has_exit_changed;

    #[test]
    fn test_exit_has_changed() {
        let _exit_server = ExitServer {
            exit_id: Identity {
                mesh_ip: "fd00::1337".parse().unwrap(),
                eth_address: "0xd2C5b6dd6ca641BE4c90565b5d3DA34C14949A53"
                    .parse()
                    .unwrap(),
                wg_public_key: "V9I9yrxAqFqLV+9GeT5pnXPwk4Cxgfvl30Fv8khVGsM="
                    .parse()
                    .unwrap(),
                nickname: None,
            },

            registration_port: 3452,
            wg_exit_listen_port: 59998,
        };
        let mut exit_state = ExitState::New;
        let dummy_exit_details = ExitDetails {
            server_internal_ip: "172.0.0.1".parse().unwrap(),
            netmask: 0,
            wg_exit_port: 123,
            exit_price: 123,
            exit_currency: SystemChain::Xdai,
            description: "".to_string(),
            verif_mode: ExitVerifMode::Off,
        };
        let mut last_states = LastExitStates::default();

        // An ip is selected and setup in last_states
        let selected_exit = "fd00::2602".parse().unwrap();

        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit,
            exit_state.clone()
        ));

        // Last states get updated next tick
        last_states.last_exit = Some("fd00::2602".parse().unwrap());
        last_states.last_exit_details = Some(exit_state.clone());
        assert!(!has_exit_changed(
            last_states.clone(),
            selected_exit,
            exit_state.clone()
        ));

        // Registration Details change
        exit_state = ExitState::Registered {
            general_details: dummy_exit_details.clone(),
            our_details: ExitClientDetails {
                client_internal_ip: "172.1.1.1".parse().unwrap(),
                internet_ipv6_subnet: None,
            },
            message: "".to_string(),
        };
        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit,
            exit_state.clone()
        ));

        // next tick last stats get updated accordingly
        last_states.last_exit_details = Some(exit_state.clone());

        // Registration detail for client change
        exit_state = ExitState::Registered {
            general_details: dummy_exit_details,
            our_details: ExitClientDetails {
                client_internal_ip: "172.1.1.14".parse().unwrap(),
                internet_ipv6_subnet: None,
            },
            message: "".to_string(),
        };
        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit,
            exit_state.clone()
        ));

        // next tick its updated accordingly
        last_states.last_exit_details = Some(exit_state.clone());
        assert!(!has_exit_changed(last_states, selected_exit, exit_state));
    }
}
