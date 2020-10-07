//! Simple helper functions for brctl

use super::KernelInterface;
use crate::KernelInterfaceError as Error;
use std::process::Output;

impl dyn KernelInterface {
    pub fn add_if_to_bridge(&self, br: &str, iface: &str) -> Result<Output, Error> {
        self.run_command("brctl", &["addif", br, iface])
    }

    pub fn del_if_from_bridge(&self, br: &str, iface: &str) -> Result<Output, Error> {
        self.run_command("brctl", &["delif", br, iface])
    }
}
