use serde::Deserialize;
use serde::Serialize;
use std::hash::Hash;

/// This enum contains information about what type of update we need to perform on a router initiated from op tools.
/// This can either be a sysupgrade with a url to a firmware image, or an opkg update with a url to a opkg feed
#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
pub enum UpdateType {
    Sysupgrade(SysupgradeCommand),
    Opkg(Vec<OpkgCommand>),
}

static FEED_NAME: &str = "althea";
impl From<UpdateTypeLegacy> for UpdateType {
    fn from(legacy: UpdateTypeLegacy) -> Self {
        match legacy {
            UpdateTypeLegacy::Sysupgrade(command) => UpdateType::Sysupgrade(command),
            UpdateTypeLegacy::Opkg(legacy_opkg) => {
                let mut commands = Vec::new();
                for item in legacy_opkg.command_list {
                    match item.opkg_command {
                        OpkgCommandTypeLegacy::Install => {
                            if item.packages.is_none() {
                                continue;
                            }
                            commands.push(OpkgCommand::Install {
                                packages: item.packages.unwrap(),
                                arguments: item.arguments.unwrap_or_default(),
                            })
                        }
                        OpkgCommandTypeLegacy::Update => commands.push(OpkgCommand::Update {
                            feed: legacy_opkg.feed.clone(),
                            feed_name: FEED_NAME.to_string(),
                            arguments: item.arguments.unwrap_or_default(),
                        }),
                    }
                }
                UpdateType::Opkg(commands)
            }
        }
    }
}

/// This enum defines which opkg command we are performing during a router update
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum OpkgCommand {
    Install {
        packages: Vec<String>,
        arguments: Vec<String>,
    },
    Remove {
        packages: Vec<String>,
        arguments: Vec<String>,
    },
    Update {
        feed: String,
        feed_name: String,
        arguments: Vec<String>,
    },
}

///This enum contains information about what type of update we need to perform on a router initiated from op tools.
/// This can either be a sysupgrade with a url to a firmware image, or an opkg update with a url to a opkg feed
#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
pub enum UpdateTypeLegacy {
    Sysupgrade(SysupgradeCommand),
    Opkg(OpkgCommandListLegacy),
}

#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
///This struct contains info required for a sysupgrade command
pub struct SysupgradeCommand {
    pub url: String,
    pub flags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
/// This struct contains the feed and a vector of opkg commands to run on an update
pub struct OpkgCommandListLegacy {
    pub feed: String,
    pub command_list: Vec<OpkgCommandLegacy>,
}

/// This struct contains alls the information need to perfom an opkg command, i.e, install/update, list of arguments, and flags
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OpkgCommandLegacy {
    pub opkg_command: OpkgCommandTypeLegacy,
    pub packages: Option<Vec<String>>,
    pub arguments: Option<Vec<String>>,
}

/// This enum defines which opkg command we are performing during a router update
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum OpkgCommandTypeLegacy {
    Install,
    Update,
}

#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
pub enum ReleaseStatus {
    Custom(String),
    ReleaseCandidate,
    PreRelease,
    GeneralAvailability,
}
