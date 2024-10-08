use crate::KernelInterfaceError;
use std::io::Write;
use std::process::{Command, Stdio};

/// Sets the system password on openwrt
pub fn set_system_password(password: String) -> Result<(), KernelInterfaceError> {
    trace!("Trying to set the system password to {}", password);
    let mut password_with_newline = password.as_bytes().to_vec();
    password_with_newline.push(b'\n');

    let mut passwd = Command::new("passwd")
        .args(["-a sha512"])
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    passwd
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&password_with_newline)?;
    passwd
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&password_with_newline)?;

    let output = passwd.wait_with_output()?;
    trace!("Got {} from passwd", String::from_utf8(output.stdout)?);

    Ok(())
}
