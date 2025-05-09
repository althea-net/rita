#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use std::str;
use std::str::Utf8Error;
use std::{env, fmt};
use std::{
    error::Error,
    time::{Instant, SystemTimeError},
};
use std::{io::ErrorKind, num::ParseIntError};
use std::{
    num::ParseFloatError,
    process::{Command, Output},
};

pub mod babel;
pub mod bridge_tools;
pub mod check_cron;
pub mod counter;
pub mod create_wg_key;
pub mod dns;
pub mod exit_client_tunnel;
pub mod exit_server_tunnel;
pub mod file_io;
pub mod fs_sync;
mod get_neighbors;
pub mod hardware_info;
pub mod interface_tools;
pub mod ip_addr;
pub mod ip_neigh;
pub mod ip_route;
pub mod iptables;
pub mod is_openwrt;
pub mod link_local_tools;
pub mod manipulate_uci;
pub mod netfilter;
pub mod netns;
pub mod open_tunnel;
pub mod openwrt_ubus;
pub mod opkg_feeds;
pub mod ping_check;
pub mod set_system_password;
pub mod setup_wg_if;
pub mod time;
pub mod traffic_control;
pub mod udp_socket_table;
pub mod upgrade;
pub mod wg_iface_counter;

use althea_types::error::AltheaTypesError;
use oping::PingError;

pub use crate::counter::FilterTarget;
pub use crate::create_wg_key::WgKeypair;
pub use crate::exit_server_tunnel::ExitClient;
pub use crate::ip_route::DefaultRoute;
pub use crate::ip_route::IpRoute;
pub use crate::ip_route::ToSubnet;

use std::fmt::Result as FormatResult;
use std::io::Error as IoError;
use std::net::AddrParseError;
use std::string::FromUtf8Error;

#[derive(Clone, Debug)]
pub enum KernelInterfaceError {
    RuntimeError(String),
    NoInterfaceError(String),
    AddressNotReadyError(String),
    WgExistsError,
    FailedToGetMemoryUsage,
    FailedToGetMemoryInfo,
    FailedToGetLoadAverage,
    NoAltheaReleaseFeedFound,
    EmptyRouteString,
    InvalidRouteString(String),
    TrafficControlError(String),
    InvalidArchString(String),
    FailedToGetSystemTime,
    FailedToGetSystemKernelVersion,
    ParseError(String),
    FromUtf8Error,
    WgSetupFailed(String),
}

impl fmt::Display for KernelInterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> FormatResult {
        match self {
            KernelInterfaceError::RuntimeError(val) => write!(f, "Runtime Error: {val}"),
            KernelInterfaceError::NoInterfaceError(val) => {
                write!(f, "No interface by the name: {val}")
            }
            KernelInterfaceError::AddressNotReadyError(val) => {
                write!(f, "Address isn't ready yet: {val}")
            }
            KernelInterfaceError::WgExistsError => write!(f, "Wireguard Interface Already exists"),
            KernelInterfaceError::FailedToGetMemoryUsage => {
                write!(f, "Failed to get accurate memory usage!")
            }
            KernelInterfaceError::FailedToGetLoadAverage => {
                write!(f, "Failed to get load average!")
            }
            KernelInterfaceError::FailedToGetMemoryInfo => write!(f, "Failed to get memory info!"),
            KernelInterfaceError::ParseError(val) => write!(f, "Unable to parse: {val}!"),
            KernelInterfaceError::NoAltheaReleaseFeedFound => {
                write!(f, "Could not pares /etc/opkg/customfeeds.conf")
            }
            KernelInterfaceError::TrafficControlError(val) => {
                write!(f, "TrafficControl error {val}")
            }
            KernelInterfaceError::EmptyRouteString => {
                write!(f, "Can't parse an empty string into a route!")
            }
            KernelInterfaceError::InvalidRouteString(val) => {
                write!(f, "InvalidRouteString {val}")
            }
            KernelInterfaceError::InvalidArchString(val) => {
                write!(f, "InvalidArchString {val}")
            }
            KernelInterfaceError::FailedToGetSystemTime => {
                write!(f, "Failed to get system time!")
            }
            KernelInterfaceError::FailedToGetSystemKernelVersion => {
                write!(f, "Failed to get system kernel version!")
            }
            KernelInterfaceError::FromUtf8Error => write!(f, "Could not parse from utf8 output"),
            KernelInterfaceError::WgSetupFailed(val) => write!(f, "Wireguard setup failed: {val}"),
        }
    }
}

impl Error for KernelInterfaceError {}

impl From<FromUtf8Error> for KernelInterfaceError {
    fn from(e: FromUtf8Error) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

impl From<IoError> for KernelInterfaceError {
    fn from(e: IoError) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

impl From<AddrParseError> for KernelInterfaceError {
    fn from(e: AddrParseError) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

impl From<ParseIntError> for KernelInterfaceError {
    fn from(e: ParseIntError) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

impl From<ParseFloatError> for KernelInterfaceError {
    fn from(e: ParseFloatError) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

impl From<AltheaTypesError> for KernelInterfaceError {
    fn from(e: AltheaTypesError) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

impl From<Utf8Error> for KernelInterfaceError {
    fn from(e: Utf8Error) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

impl From<SystemTimeError> for KernelInterfaceError {
    fn from(e: SystemTimeError) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

impl From<PingError> for KernelInterfaceError {
    fn from(e: PingError) -> Self {
        KernelInterfaceError::RuntimeError(format!("{e}"))
    }
}

// a quick throwaway function to print arguments arrays so that they can be copy/pasted from logs
fn print_str_array(input: &[&str]) -> String {
    let mut output = String::new();
    for item in input {
        output = output + " " + item;
    }
    output
}

pub fn run_command(program: &str, args: &[&str]) -> Result<Output, KernelInterfaceError> {
    let start = Instant::now();
    let output = match Command::new(program).args(args).output() {
        Ok(o) => o,
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                error!("The {:?} binary was not found. Please install a package that provides it. PATH={:?}", program, env::var("PATH"));
            }
            return Err(e.into());
        }
    };

    trace!(
        "Command {} {} returned: {:?}",
        program,
        print_str_array(args),
        output
    );
    if !output.status.success() {
        trace!(
            "Command {} {} returned: an error {:?}",
            program,
            print_str_array(args),
            output
        );
    }
    trace!(
        "command completed in {}s {}ms",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis()
    );

    if start.elapsed().as_secs() > 5 {
        error!(
            "Command {} {} took more than five seconds to complete!",
            program,
            print_str_array(args)
        );
    } else if start.elapsed().as_secs() > 1 {
        warn!(
            "Command {} {} took more than one second to complete!",
            program,
            print_str_array(args)
        );
    }

    Ok(output)
}
