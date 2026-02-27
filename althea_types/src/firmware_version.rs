/// Firmware version types for structured version reporting
///
/// These types allow routers to report their firmware version in a structured
/// format rather than just a string, enabling the operator server to make
/// better decisions about upgrades and compatibility.
use std::cmp::Ordering;
use std::fmt::Display;

/// Default value for major version field (currently always 0)
fn default_major() -> u16 {
    0
}

fn default_variant() -> FirmwareVariant {
    FirmwareVariant::Public
}

/// Default value for firmware_type field (Router for backwards compatibility)
fn default_firmware_type() -> RitaType {
    RitaType::Router
}

/// Enum representing the type of device for update logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RitaType {
    /// Standard router/client device
    Router,
    /// Exit server device
    Exit,
}

impl RitaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RitaType::Router => "rita",
            RitaType::Exit => "exit",
        }
    }
}

impl Display for RitaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// What firmware variant we are dealing with. This can be used to represent various
/// forks or alternate implementations of the Althea protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FirmwareVariant {
    Public,
}

impl Display for FirmwareVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirmwareVariant::Public => write!(f, "Public"),
        }
    }
}

/// Firmware version following semantic versioning (major.minor.patch)
///
/// Historical Note: Due to legacy naming, what we call "minor" was previously called "major" (beta number),
/// and what we call "patch" was previously called "minor" (rc number). The actual major version has always
/// been 0 for all current releases.
///
/// Current semantics:
/// - major: Always 0 for current releases
/// - minor: Beta number (e.g., 20 in beta20rc19)
/// - patch: RC number (e.g., 19 in beta20rc19)
/// - variant: Public only for now
/// - firmware_type: Rita (client) or Exit
///
/// Display format: "v0.MINOR.PATCH" (e.g., "v0.20.19")
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FirmwareVersion {
    #[serde(default = "default_major")]
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    #[serde(default = "default_variant")]
    pub variant: FirmwareVariant,
    #[serde(default = "default_firmware_type")]
    pub firmware_type: RitaType,
}

impl FirmwareVersion {
    /// Create a new firmware version with proper semantic versioning.
    ///
    /// Parameters:
    /// - minor: Beta number (e.g., 20 for beta20)
    /// - patch: RC number (e.g., 19 for rc19)
    /// - variant: Public only for now
    /// - firmware_type: Rita (client) or Exit
    pub fn new(minor: u16, patch: u16, variant: FirmwareVariant, firmware_type: RitaType) -> Self {
        FirmwareVersion {
            major: 0,
            minor,
            patch,
            variant,
            firmware_type,
        }
    }

    /// Check if upgrading from `current` to `self` is a valid forward update
    ///
    /// Rules:
    /// - Cannot cross major version boundaries
    /// - Can upgrade at most 1 minor version forward (within same major)
    /// - Can upgrade unlimited patch versions forward (within same minor)
    /// - Cannot downgrade
    pub fn is_valid_forward_update(&self, current: FirmwareVersion) -> bool {
        if self.major != current.major {
            return false;
        }
        if self.firmware_type != current.firmware_type {
            return false;
        }
        match self.minor.cmp(&current.minor) {
            Ordering::Greater => self.minor == current.minor + 1,
            Ordering::Equal => self.patch >= current.patch,
            Ordering::Less => false,
        }
    }

    /// Parse a firmware version string with an explicit variant and type.
    pub fn from_str_with_variant_and_type(
        s: &str,
        variant: FirmwareVariant,
        firmware_type: RitaType,
    ) -> Result<Self, String> {
        let mut version = s.parse::<FirmwareVersion>()?;
        version.variant = variant;
        version.firmware_type = firmware_type;
        Ok(version)
    }

    /// Convert to a complete version string including variant and type.
    pub fn to_complete_version_string(&self) -> String {
        format!(
            "v{}.{}.{}-{}-{}",
            self.major,
            self.minor,
            self.patch,
            self.variant,
            self.firmware_type.as_str()
        )
    }

    /// Returns a simplified version string suitable for user display, like "v0.23.9".
    pub fn get_user_display_string(&self) -> String {
        format!("v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for FirmwareVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FirmwareVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

impl std::str::FromStr for FirmwareVersion {
    type Err = String;

    #[allow(clippy::single_char_pattern)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lat_tag = s.to_lowercase();


        let lat_tag = lat_tag.trim_start_matches('v');
        let lat_tag = lat_tag.replace("beta", "");

        let mut lat_tag_split = lat_tag.split("rc");
        let check_lat_tag = lat_tag_split.clone();

        if check_lat_tag.count() == 1 {
            // no rc in the name - try standard semantic versioning like "0.20.19"
            let mut lat_tag_dash = lat_tag.split("-");
            let version_str = lat_tag_dash.next().unwrap_or("");

            let parts: Vec<&str> = version_str.split('.').collect();
            if parts.len() >= 3 {
                let minor = parts[1]
                    .parse::<u16>()
                    .map_err(|_| format!("Failed to parse minor version from '{}'", s))?;
                let patch = parts[2]
                    .parse::<u16>()
                    .map_err(|_| format!("Failed to parse patch version from '{}'", s))?;
                return Ok(FirmwareVersion {
                    major: 0,
                    minor,
                    patch,
                    variant: FirmwareVariant::Public,
                    firmware_type: RitaType::Router,
                });
            }
        }

        let minor_str = lat_tag_split.next();
        let patch_str = lat_tag_split.next();

        if minor_str.is_none() || patch_str.is_none() {
            return Err(format!("Can't parse string '{}' into firmware version", s));
        }

        let minor: u16 = minor_str
            .unwrap()
            .parse()
            .map_err(|_| format!("Can't parse minor version from '{}'", s))?;
        let patch: u16 = patch_str
            .unwrap()
            .parse()
            .map_err(|_| format!("Can't parse patch version from '{}'", s))?;

        Ok(FirmwareVersion {
            major: 0,
            minor,
            patch,
            variant: FirmwareVariant::Public,
            firmware_type: RitaType::Router,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver() {
        let v: FirmwareVersion = "v0.22.5".parse().unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 22);
        assert_eq!(v.patch, 5);
        assert_eq!(v.firmware_type, RitaType::Router);
    }

    #[test]
    fn test_parse_beta_rc() {
        let v: FirmwareVersion = "beta20rc19".parse().unwrap();
        assert_eq!(v.minor, 20);
        assert_eq!(v.patch, 19);
    }

    #[test]
    fn test_forward_update() {
        let current = FirmwareVersion::new(20, 19, FirmwareVariant::Public, RitaType::Router);
        let same_minor = FirmwareVersion::new(20, 23, FirmwareVariant::Public, RitaType::Router);
        let next_minor = FirmwareVersion::new(21, 12, FirmwareVariant::Public, RitaType::Router);
        let skip_minor = FirmwareVersion::new(22, 1, FirmwareVariant::Public, RitaType::Router);
        let downgrade = FirmwareVersion::new(19, 10, FirmwareVariant::Public, RitaType::Router);

        assert!(same_minor.is_valid_forward_update(current));
        assert!(next_minor.is_valid_forward_update(current));
        assert!(!skip_minor.is_valid_forward_update(current));
        assert!(!downgrade.is_valid_forward_update(current));
    }

    #[test]
    fn test_ordering() {
        let v1 = FirmwareVersion::new(20, 19, FirmwareVariant::Public, RitaType::Router);
        let v2 = FirmwareVersion::new(20, 23, FirmwareVariant::Public, RitaType::Router);
        let v3 = FirmwareVersion::new(21, 1, FirmwareVariant::Public, RitaType::Router);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }
}
