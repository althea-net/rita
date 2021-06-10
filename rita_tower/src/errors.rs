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
use std::{
    str::Utf8Error,
    sync::{Arc, Mutex},
};

use std::str;

use althea_types::error::AltheaTypesError;

use std::fmt::Result as FormatResult;
use std::io::Error as IoError;
use std::net::AddrParseError;
use std::string::FromUtf8Error;

type CommandFunction = Box<dyn FnMut(String, Vec<String>) -> Result<Output, TowerError> + Send>;

#[derive(Clone, Debug)]
pub enum TowerError {
    RuntimeError(String),
    FailedToGetEnbsError,
    FailedToGetConnectedUesError,
    FailedToGetAttachedUesError,
    FailedToGetUptime,
}

impl fmt::Display for TowerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> FormatResult {
        match self {
            TowerError::RuntimeError(val) => write!(f, "Runtime Error: {}", val),

            TowerError::FailedToGetEnbsError => write!(f, "Unable to handle or obtain enbs file"),
            TowerError::FailedToGetConnectedUesError => {
                write!(f, "Unable to handle or obtain connected ues file")
            }
            TowerError::FailedToGetAttachedUesError => {
                write!(f, "Unable to handle or obtain attached ues file")
            }
            TowerError::FailedToGetUptime => {
                write!(f, "Unable to parse string for uptime")
            }
        }
    }
}

impl Error for TowerError {}

impl From<FromUtf8Error> for TowerError {
    fn from(e: FromUtf8Error) -> Self {
        TowerError::RuntimeError(format!("{}", e))
    }
}

impl From<IoError> for TowerError {
    fn from(e: IoError) -> Self {
        TowerError::RuntimeError(format!("{}", e))
    }
}

impl From<AddrParseError> for TowerError {
    fn from(e: AddrParseError) -> Self {
        TowerError::RuntimeError(format!("{}", e))
    }
}

impl From<ParseIntError> for TowerError {
    fn from(e: ParseIntError) -> Self {
        TowerError::RuntimeError(format!("{}", e))
    }
}

impl From<ParseFloatError> for TowerError {
    fn from(e: ParseFloatError) -> Self {
        TowerError::RuntimeError(format!("{}", e))
    }
}

impl From<AltheaTypesError> for TowerError {
    fn from(e: AltheaTypesError) -> Self {
        TowerError::RuntimeError(format!("{}", e))
    }
}

impl From<Utf8Error> for TowerError {
    fn from(e: Utf8Error) -> Self {
        TowerError::RuntimeError(format!("{}", e))
    }
}

impl From<SystemTimeError> for TowerError {
    fn from(e: SystemTimeError) -> Self {
        TowerError::RuntimeError(format!("{}", e))
    }
}

#[cfg(test)]
lazy_static! {
    pub static ref KI: Box<dyn Tower> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|_program, _args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(not(test))]
lazy_static! {
    pub static ref KI: Box<dyn Tower> = Box::new(LinuxCommandRunner {});
}

pub trait CommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, TowerError>;
    fn set_mock(&self, mock: CommandFunction);
}

// a quick throwaway function to print arguments arrays so that they can be copy/pasted from logs
fn print_str_array(input: &[&str]) -> String {
    let mut output = String::new();
    for item in input {
        output = output + " " + item;
    }
    output
}

pub struct LinuxCommandRunner;

impl CommandRunner for LinuxCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, TowerError> {
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

    fn set_mock(
        &self,
        _mock: Box<dyn FnMut(String, Vec<String>) -> Result<Output, TowerError> + Send>,
    ) {
        unimplemented!()
    }
}

pub struct TestCommandRunner {
    pub run_command: Arc<Mutex<CommandFunction>>,
}

impl CommandRunner for TestCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, TowerError> {
        let mut args_owned = Vec::new();
        for a in args {
            args_owned.push((*a).to_string())
        }

        (&mut *self.run_command.lock().unwrap())(program.to_string(), args_owned)
    }

    fn set_mock(&self, mock: CommandFunction) {
        *self.run_command.lock().unwrap() = mock
    }
}

pub trait Tower: CommandRunner + Sync + Send {}

impl Tower for LinuxCommandRunner {}
impl Tower for TestCommandRunner {}
