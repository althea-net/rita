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

pub mod exit_loop;
pub mod exit_selector;
pub mod requests;
pub mod time_sync;
pub mod utils;

use althea_types::ExitIdentity;
use althea_types::ExitState;
use exit_selector::ExitSwitcherState;
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

/// Data to use identity whether a clients wg exit tunnel needs to be setup up again across ticks
#[derive(Clone)]
pub struct LastExitStates {
    last_exit: ExitIdentity,
    last_exit_details: ExitState,
}

/// An actor which pays the exit
#[derive(Clone)]
pub struct ExitManager {
    nat_setup: bool,
    /// Store last exit here, when we see an exit change, we reset wg tunnels
    last_exit_state: Option<LastExitStates>,
    last_status_request: Option<Instant>,
    exit_switcher_state: ExitSwitcherState,
    // mapping from exit identity to exit state, the registration state itself
    // should always be the same, but the exit specific info can and will change
    // it may also be possible for us to be registered on one exit but not on another
    // due to a query issue or other failure on the exit side, so we have to handle that
    registration_state: HashMap<ExitIdentity, ExitState>,
}

impl Default for ExitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitManager {
    pub fn new() -> ExitManager {
        ExitManager {
            nat_setup: false,
            last_exit_state: None,
            last_status_request: None,
            exit_switcher_state: ExitSwitcherState {
                last_switch: None,
                backoff: Duration::from_secs(1),
                currently_selected: None,
                quality_history: HashMap::new(),
            },
            registration_state: HashMap::new(),
        }
    }

    /// Gets the currently selected exit, if none is selected returns the first exit from the verified list or None if none exist
    pub fn get_current_exit(&self) -> Option<ExitIdentity> {
        self.exit_switcher_state.currently_selected.clone()
    }

    /// Gets the exit registration state for the current exit
    pub fn get_exit_registration_state(&self) -> ExitState {
        match self.get_current_exit() {
            Some(exit) => match self.registration_state.get(&exit) {
                Some(state) => state.clone(),
                None => ExitState::New,
            },
            None => ExitState::New,
        }
    }

    pub fn set_exit_registration_state(&mut self, exit_id: ExitIdentity, state: ExitState) {
        self.registration_state.insert(exit_id, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use althea_types::ExitIdentity;
    use althea_types::{ExitClientDetails, ExitDetails, ExitVerifMode, SystemChain};
    use std::collections::HashSet;
    use utils::has_exit_changed;

    /// generates a random identity, never use in production, your money will be stolen
    pub fn random_exit_identity() -> ExitIdentity {
        use clarity::PrivateKey;

        let secret: [u8; 32] = rand::random();
        let mut ip: [u8; 16] = [0; 16];
        ip.copy_from_slice(&secret[0..16]);

        // the starting location of the funds
        let eth_key = PrivateKey::from_bytes(secret).unwrap();
        let eth_address = eth_key.to_address();

        let payment_types = HashSet::new();
        let allowed_regions = HashSet::new();

        ExitIdentity {
            mesh_ip: ip.into(),
            eth_addr: eth_address,
            wg_key: secret.into(),
            registration_port: 0,
            wg_exit_listen_port: 0,
            allowed_regions,
            payment_types,
        }
    }

    #[test]
    fn test_exit_has_changed() {
        let id = random_exit_identity();
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
        let mut last_states = None;

        // An ip is selected and setup in last_states
        let selected_exit = random_exit_identity();

        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit.clone(),
            exit_state.clone()
        ));

        // Last states get updated next tick
        last_states = Some(LastExitStates {
            last_exit: selected_exit.clone(),
            last_exit_details: exit_state.clone(),
        });
        assert!(!has_exit_changed(
            last_states.clone(),
            selected_exit.clone(),
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
            identity: Box::new(id.clone()),
        };
        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit.clone(),
            exit_state.clone()
        ));

        // next tick last stats get updated accordingly
        last_states = Some(LastExitStates {
            last_exit: selected_exit.clone(),
            last_exit_details: exit_state.clone(),
        });

        // Registration detail for client change
        exit_state = ExitState::Registered {
            general_details: dummy_exit_details,
            our_details: ExitClientDetails {
                client_internal_ip: "172.1.1.14".parse().unwrap(),
                internet_ipv6_subnet: None,
            },
            message: "".to_string(),
            identity: Box::new(id),
        };
        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit.clone(),
            exit_state.clone()
        ));

        // next tick its updated accordingly
        last_states = Some(LastExitStates {
            last_exit: selected_exit.clone(),
            last_exit_details: exit_state.clone(),
        });
        assert!(!has_exit_changed(last_states, selected_exit, exit_state));
    }
}
