use super::KernelInterface;

use failure::Error;
use std::io::Write;
use std::process::{Command, Stdio};

impl dyn KernelInterface {
    /// Sets the system password on openwrt
    pub fn set_system_password(&self, password: String) -> Result<(), Error> {
        trace!("Trying to set the system password to {}", password);
        let mut passwd = Command::new("passwd")
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();

        passwd
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&password.as_bytes())?;
        passwd
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&password.as_bytes())?;
        let output = passwd.wait_with_output()?;
        trace!("Got {} from passwd", String::from_utf8(output.stdout)?);

        Ok(())
    }
}
