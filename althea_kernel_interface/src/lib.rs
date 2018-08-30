#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

extern crate eui48;
extern crate itertools;
extern crate regex;

use std::env;
use std::io::ErrorKind;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Output};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use std::str;

mod counter;
mod create_wg_key;
mod delete_tunnel;
mod dns;
mod exit_client_tunnel;
mod exit_server_counter;
mod exit_server_tunnel;
mod fs_sync;
mod get_neighbors;
mod iface_counter;
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
mod stats;
mod wireless;

pub use counter::FilterTarget;
pub use exit_server_counter::ExitFilterTarget;
pub use exit_server_tunnel::ExitClient;

use failure::Error;

#[derive(Debug, Fail)]
pub enum KernelInterfaceError {
    #[fail(display = "Runtime Error: {:?}", _0)]
    RuntimeError(String),
}

#[derive(Debug, Fail)]
pub enum KernelInterfaceTestError {
    #[fail(display = "Too many commands run")]
    TooManyCommandsRun,
}

#[cfg(test)]
lazy_static! {
    pub static ref KI: Box<KernelInterface> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|_program, _args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(not(test))]
lazy_static! {
    pub static ref KI: Box<KernelInterface> = Box::new(LinuxCommandRunner {});
}

pub trait CommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error>;
    fn set_mock(&self, mock: Box<FnMut(String, Vec<String>) -> Result<Output, Error> + Send>);
    fn test_commands(&self, test_name: &str, test_commands: &[(&str, &str)]);
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
            info!(
                "Command {:?} {:?} returned: an error {:?}",
                program, args, output
            );
        }
        trace!(
            "command completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_nanos() / 1000000
        );
        return Ok(output);
    }

    fn test_commands(&self, _test_name: &str, _test_commands: &[(&str, &str)]) {
        unimplemented!()
    }

    fn set_mock(&self, _mock: Box<FnMut(String, Vec<String>) -> Result<Output, Error> + Send>) {
        unimplemented!()
    }
}

pub struct TestCommandRunner {
    pub run_command: Arc<Mutex<Box<FnMut(String, Vec<String>) -> Result<Output, Error> + Send>>>,
}

impl TestCommandRunner {}

impl CommandRunner for TestCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error> {
        let mut args_owned = Vec::new();
        for a in args {
            args_owned.push(a.to_string())
        }

        (&mut *self.run_command.lock().unwrap())(program.to_string(), args_owned)
    }
    fn test_commands(&self, _test_name: &str, test_commands: &[(&str, &str)]) {
        let mut commands_owned = Vec::new();
        for (command, result) in test_commands {
            commands_owned.push((command.to_string(), result.to_string()))
        }
        let mut command_index = 0;
        let closure = move |command: String, arg: Vec<String>| {
            let args_string = arg.join(" ");
            let command_string = vec![command, args_string].join(" ");
            if command_index >= commands_owned.len() {
                panic!(
                    "too many commands run in current test, got {}, index {}",
                    command_string, command_index
                );
            }
            let (expected_command, result) = commands_owned[command_index].clone();
            if expected_command == command_string {
                command_index += 1;
                return Ok(Output {
                    stdout: result.as_bytes().to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                });
            } else {
                panic!(
                    "unexpected command! got {}, expected {}, index {}",
                    command_string, expected_command, command_index
                );
            }
        };
        *self.run_command.lock().unwrap() = Box::new(closure);
    }

    fn set_mock(&self, mock: Box<FnMut(String, Vec<String>) -> Result<Output, Error> + Send>) {
        *self.run_command.lock().unwrap() = mock
    }
}

pub trait KernelInterface: CommandRunner + Sync {}

impl KernelInterface for LinuxCommandRunner {}
impl KernelInterface for TestCommandRunner {}

pub fn test_kernel_interface() -> Box<TestCommandRunner> {
    Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|_program, _args| {
            Err(KernelInterfaceTestError::TooManyCommandsRun)?
        }))),
    })
}

pub fn new_kernel_interface() -> Box<LinuxCommandRunner> {
    Box::new(LinuxCommandRunner {})
}
