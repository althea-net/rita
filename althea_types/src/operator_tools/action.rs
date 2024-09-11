use crate::openwrt_updates::{UpdateType, UpdateTypeLegacy};
use crate::wifi_info::WifiToken;
use clarity::Address;
use num256::Uint256;
use serde::Deserialize;
use serde::Serialize;
use std::hash::Hash;

/// Something the operator may want to do to a router under their control
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum OperatorAction {
    /// Resets the Rita dashboard password. This is the password users use to login
    /// to the router dashboard, which is distinct from the WiFi password. This
    /// password is also used for ssh login on the LAN. This reset operation does
    /// not change that password but it will be changed when the dashboard password
    /// is set again by the user.
    ResetRouterPassword,
    /// This resets the WiFi password to the default 'ChangeMe' and restarts the wifi
    /// subsystem (without restarting the router).
    ResetWiFiPassword,
    // Given a vector of wifitoken, apply these changes to the router
    SetWifi {
        token: Vec<WifiToken>,
    },
    /// This resets the traffic shaper to 'unlimited' speed for all connections. It can
    /// be useful when the shaper is showing obviously incorrect values for some peer
    /// usually caused by bad network transients. While the shaper will eventually recover
    /// this allows a human to do it right away
    ResetShaper,
    /// Fully reboots the router, this includes a power cycle not just a restart of the
    /// routing processes. For x86 machines this action comes with some risk as devices may
    /// get stuck in the BIOS if not configured properly.
    Reboot,
    /// Restart babeld and rita on the router
    SoftReboot,
    /// Sends instructions from op tools about the type of update to perform, either a sysupgrade
    /// or an opkg update
    UpdateV2 {
        instruction: UpdateType,
    },
    /// Sends instructions from op tools about the type of update to perform, either a sysupgrade
    /// or an opkg update, to be removed after all routers >= beta 19 rc9
    Update {
        instruction: UpdateTypeLegacy,
    },
    /// Changes the operator address of a given router in order to support Beta 15 and below
    /// this has it's own logic in the operator tools that will later be removed for the logic
    /// you see in Althea_rs
    ChangeOperatorAddress {
        new_address: Option<Address>,
    },
    /// Sets the min gas value to the provided value, primarily intended for use on xDai where
    /// the validators set a minimum gas price as a group without warning
    SetMinGas {
        new_min_gas: Uint256,
    },
    /// Modifies the authorized keys used for access to routers
    UpdateAuthorizedKeys {
        add_list: Vec<String>,
        drop_list: Vec<String>,
    },
}
