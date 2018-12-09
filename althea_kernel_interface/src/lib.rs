#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;







use std::env;
use std::io::ErrorKind;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use std::str;

mod counter;
mod create_wg_key;
mod delete_tunnel;
mod dns;
mod exit_client_tunnel;
mod exit_server_tunnel;
mod fs_sync;
mod get_neighbors;
mod interface_tools;
mod ip_addr;
mod ip_route;
mod iptables;
mod link_local_tools;
mod manipulate_uci;
mod open_tunnel;
mod openwrt_ubus;
mod ping_check;
mod setup_wg_if;
mod udp_socket_table;
pub mod wg_iface_counter;

pub use crate::counter::FilterTarget;
pub use crate::create_wg_key::WgKeypair;
pub use crate::exit_server_tunnel::ExitClient;

use failure::Error;

#[derive(Debug, Fail)]
pub enum KernelInterfaceError {
    #[fail(display = "Runtime Error: {:?}", _0)]
    RuntimeError(String),
}

#[cfg(test)]
lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|_program, _args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(not(test))]
lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
}

pub trait CommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error>;
    fn set_mock(&self, mock: Box<dyn FnMut(String, Vec<String>) -> Result<Output, Error> + Send>);
}

pub struct LinuxCommandRunner;

impl CommandRunner for LinuxCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error> {
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

        trace!("Command {:?} {:?} returned: {:?}", program, args, output);
        if !output.status.success() {
            trace!(
                "Command {:?} {:?} returned: an error {:?}",
                program,
                args,
                output
            );
        }
        trace!(
            "command completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_nanos() / 1000000
        );
        return Ok(output);
    }

    fn set_mock(&self, _mock: Box<dyn FnMut(String, Vec<String>) -> Result<Output, Error> + Send>) {
        unimplemented!()
    }
}

pub struct TestCommandRunner {
    pub run_command: Arc<Mutex<Box<dyn FnMut(String, Vec<String>) -> Result<Output, Error> + Send>>>,
}

impl CommandRunner for TestCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error> {
        let mut args_owned = Vec::new();
        for a in args {
            args_owned.push(a.to_string())
        }

        (&mut *self.run_command.lock().unwrap())(program.to_string(), args_owned)
    }

    fn set_mock(&self, mock: Box<dyn FnMut(String, Vec<String>) -> Result<Output, Error> + Send>) {
        *self.run_command.lock().unwrap() = mock
    }
}

pub trait KernelInterface: CommandRunner + Sync {}

impl KernelInterface for LinuxCommandRunner {}
impl KernelInterface for TestCommandRunner {}
