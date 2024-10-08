use std::process::{Command, Stdio};

/// Checks if the local system is openwrt
pub fn is_openwrt() -> bool {
    let uname = Command::new("cat")
        .args(["/etc/openwrt_release"])
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    let uname_results = String::from_utf8(uname.stdout).unwrap();
    uname_results.contains("OpenWrt")
}
