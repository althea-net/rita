use super::KernelInterface;
use std::process::{Command, Stdio};

impl dyn KernelInterface {
    /// Checks if the local system is openwrt
    pub fn is_openwrt(&self) -> bool {
        let uname = Command::new("uname")
            .args(&["-a"])
            .stdout(Stdio::piped())
            .output()
            .unwrap();
        let uname_results = String::from_utf8(uname.stdout).unwrap();
        uname_results.contains("OpenWrt")
    }
}
