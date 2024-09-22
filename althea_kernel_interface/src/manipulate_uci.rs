use crate::{run_command, KernelInterfaceError};
use regex::Regex;
use std::collections::HashMap;

fn run_uci(command: &str, args: &[&str]) -> Result<(), KernelInterfaceError> {
    let output = run_command(command, args)?;
    if !output.stderr.is_empty() {
        return Err(KernelInterfaceError::RuntimeError(format!(
            "received error while setting UCI: {}",
            String::from_utf8(output.stderr)?
        )));
    }
    Ok(())
}

/// Sets an arbitrary UCI variable on OpenWRT
pub fn set_uci_var(key: &str, value: &str) -> Result<(), KernelInterfaceError> {
    run_uci("uci", &["set", &format!("{key}={value}")])?;
    Ok(())
}

/// Adds an arbitrary UCI variable on OpenWRT
pub fn add_uci_var(key: &str, value: &str) -> Result<(), KernelInterfaceError> {
    run_uci("uci", &["add", key, value])?;
    Ok(())
}

/// Sets an arbitrary UCI list on OpenWRT
pub fn set_uci_list(key: &str, value: &[&str]) -> Result<(), KernelInterfaceError> {
    if let Err(e) = del_uci_var(key) {
        trace!("Delete uci var failed! {:?}", e);
    }

    for v in value {
        run_uci("uci", &["add_list", &format!("{}={}", &key, &v)])?;
    }
    Ok(())
}

/// Deletes an arbitrary UCI variable on OpenWRT
pub fn del_uci_var(key: &str) -> Result<(), KernelInterfaceError> {
    run_uci("uci", &["delete", key])?;
    Ok(())
}

/// Retrieves the value of a given UCI path, could be one or multiple values
pub fn get_uci_var(key: &str) -> Result<String, KernelInterfaceError> {
    let output = run_command("uci", &["get", key])?;
    if !output.stderr.is_empty() {
        return Err(KernelInterfaceError::RuntimeError(format!(
            "received error while getting UCI: {}",
            String::from_utf8(output.stderr)?
        )));
    }
    let clean_string = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(clean_string)
}

/// Commits changes to UCI, returns true if successful
pub fn uci_commit(subsection: &str) -> Result<(), KernelInterfaceError> {
    let output = run_command("uci", &["commit", subsection])?;
    if !output.status.success() {
        return Err(KernelInterfaceError::RuntimeError(format!(
            "received error while commiting UCI: {}",
            String::from_utf8(output.stderr)?
        )));
    }
    Ok(())
}

/// Resets unsaved changes to UCI
pub fn uci_revert(section: &str) -> Result<(), KernelInterfaceError> {
    let output = run_command("uci", &["revert", section])?;
    if !output.status.success() {
        return Err(KernelInterfaceError::RuntimeError(format!(
            "received error while reverting UCI: {}",
            String::from_utf8(output.stderr)?
        )));
    }
    Ok(())
}

pub fn refresh_initd(program: &str) -> Result<(), KernelInterfaceError> {
    let output = run_command(&format!("/etc/init.d/{program}"), &["reload"])?;
    if !output.status.success() {
        return Err(KernelInterfaceError::RuntimeError(format!(
            "received error while refreshing {}: {}",
            program,
            String::from_utf8(output.stderr)?
        )));
    }
    Ok(())
}

/// Obtain a HashMap of a UCI section's entries and their values. Whenever `section` is None
/// the function will shell out for just `uci show` which fetches all available config entries.
pub fn uci_show(section: Option<&str>) -> Result<HashMap<String, String>, KernelInterfaceError> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(.+)=(.+)").unwrap();
    }

    let output = match section {
        Some(s) => run_command("uci", &["show", s])?,
        None => run_command("uci", &["show"])?,
    };

    if !output.status.success() {
        return Err(KernelInterfaceError::RuntimeError(format!(
            "`uci show` experienced a problem:\nstdout:\n{:?}\nstderr:\n{:?}",
            String::from_utf8(output.stdout)?,
            String::from_utf8(output.stderr)?
        )));
    }

    let stdout = String::from_utf8(output.stdout)?;

    let mut retval: HashMap<String, String> = HashMap::new();

    for line in stdout.lines() {
        let caps = match RE.captures(line) {
            Some(c) => c,
            None => {
                return Err(KernelInterfaceError::RuntimeError(format!(
                    "uci_show: Could not match regex {:?} on line {:?}",
                    *RE, line
                )))
            }
        };
        retval.insert(
            caps[1].to_owned(),
            caps[2].to_owned().trim_matches('\'').to_string(),
        );
    }

    Ok(retval)
}

pub fn openwrt_reset_wireless() -> Result<(), KernelInterfaceError> {
    run_command("wifi", &[])?;
    Ok(())
}

pub fn openwrt_reset_network() -> Result<(), KernelInterfaceError> {
    run_command("/etc/init.d/network", &["restart"])?;
    Ok(())
}

pub fn openwrt_reset_dnsmasq() -> Result<(), KernelInterfaceError> {
    run_command("/etc/init.d/dnsmasq", &["restart"])?;
    Ok(())
}
