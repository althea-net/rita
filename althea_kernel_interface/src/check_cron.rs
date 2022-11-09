use super::KernelInterface;
use crate::KernelInterfaceError as Error;
use std::process::{Command, Stdio};

impl dyn KernelInterface {
    /// Checks if the cron service is running and starts it if it's not
    pub fn check_cron(&self) -> Result<(), Error> {
        Command::new("/etc/init.d/cron")
            .args(["enable"])
            .stdout(Stdio::piped())
            .output()?;
        Command::new("/etc/init.d/cron")
            .args(["start"])
            .stdout(Stdio::piped())
            .output()?;

        Ok(())
    }
}
