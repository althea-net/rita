//! Simple helper functions for brctl

use crate::run_command;
use crate::KernelInterfaceError as Error;
use std::process::Output;

pub fn add_if_to_bridge(br: &str, iface: &str) -> Result<Output, Error> {
    run_command("brctl", &["addif", br, iface])
}

pub fn del_if_from_bridge(br: &str, iface: &str) -> Result<Output, Error> {
    run_command("brctl", &["delif", br, iface])
}
