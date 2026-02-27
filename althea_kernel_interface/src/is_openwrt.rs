use super::KernelInterface;
use std::process::{Command, Stdio};

impl dyn KernelInterface {
    /// Checks if the local system is openwrt
    pub fn is_openwrt(&self) -> bool {
        let uname = Command::new("cat")
            .args(["/etc/openwrt_release"])
            .stdout(Stdio::piped())
            .output()
            .unwrap();
        let uname_results = String::from_utf8(uname.stdout).unwrap();
        uname_results.contains("OpenWrt")
    }
}

/// checks the openwrt version to return whether it is openwrt 24.10 or later
/// (done for handling interface list changes)
pub fn is_openwrt_2410_plus() -> bool {
    let uname = Command::new("cat")
        .args(["/etc/openwrt_release"])
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    let uname_results = String::from_utf8(uname.stdout).unwrap();
    is_openwrt_2410_plus_str(&uname_results)
}

fn is_openwrt_2410_plus_str(uname_results: &str) -> bool {
    uname_results
        .find("DISTRIB_RELEASE='")
        .and_then(|index| {
            let version_str = &uname_results[index + 17..];
            // Extract version number up to first non-version character
            let version: String = version_str
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();

            // Split into parts and parse major.minor
            let mut parts = version.split('.');
            let major = parts.next()?.parse::<u32>().ok()?;
            let minor = parts.next()?.parse::<u32>().ok()?;

            Some((major, minor))
        })
        .map(|(major, minor)| major > 24 || (major == 24 && minor >= 10))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_is_openwrt_2410_plus() {
        let test_content = r#"DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='24.10-SNAPSHOT'
DISTRIB_REVISION='r28948+1-a790196993'
DISTRIB_TARGET='ipq40xx/generic'
DISTRIB_ARCH='arm_cortex-a7_neon-vfpv4'
DISTRIB_DESCRIPTION='OpenWrt 24.10-SNAPSHOT r28948+1-a790196993'
DISTRIB_TAINTS='no-all'
"#;
        assert!(super::is_openwrt_2410_plus_str(test_content));

        let test_content = r#"DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='23.90-SNAPSHOT'
DISTRIB_REVISION='r28948+1-a790196993'
DISTRIB_TARGET='ipq40xx/generic'
DISTRIB_ARCH='arm_cortex-a7_neon-vfpv4'
DISTRIB_DESCRIPTION='OpenWrt 24.10-SNAPSHOT r28948+1-a790196993'
DISTRIB_TAINTS='no-all'
"#;
        assert!(!super::is_openwrt_2410_plus_str(test_content));

        let test_content = r#"DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='25.0-SNAPSHOT'
DISTRIB_REVISION='r28948+1-a790196993'
DISTRIB_TARGET='ipq40xx/generic'
DISTRIB_ARCH='arm_cortex-a7_neon-vfpv4'
DISTRIB_DESCRIPTION='OpenWrt 24.10-SNAPSHOT r28948+1-a790196993'
DISTRIB_TAINTS='no-all'
"#;
        assert!(super::is_openwrt_2410_plus_str(test_content));

        let test_content = r#"DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='24.10.5'
DISTRIB_REVISION='r29087-d9c5716d1d'
DISTRIB_TARGET='x86/64'
DISTRIB_ARCH='x86_64'
DISTRIB_DESCRIPTION='OpenWrt 24.10.5 r29087-d9c5716d1d'
DISTRIB_TAINTS='no-all'
"#;
        assert!(super::is_openwrt_2410_plus_str(test_content));

        let test_content = r#"DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='23.05.5'
DISTRIB_REVISION='r24106-10cc5fcd00'
DISTRIB_TARGET='x86/64'
DISTRIB_ARCH='x86_64'
DISTRIB_DESCRIPTION='OpenWrt 23.05.5 r24106-10cc5fcd00'
DISTRIB_TAINTS='no-all'
"#;
        assert!(!super::is_openwrt_2410_plus_str(test_content));
    }
}
