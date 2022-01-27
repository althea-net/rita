use crate::operator_update::handle_release_feed_update;
use althea_kernel_interface::KernelInterfaceError;
use althea_types::UpdateType;
use rita_common::KI;
use std::process::Output;

/// Updates rita by performing either a sysupgrade or opkg install
pub fn update_rita(instruction: UpdateType) -> Result<Output, KernelInterfaceError> {
    if KI.is_openwrt() {
        match instruction {
            UpdateType::Sysupgrade(command) => KI.perform_sysupgrade(command),
            UpdateType::Opkg(commands) => {
                //update the feed
                handle_release_feed_update(Some(commands.feed));

                //opkg commands
                let res = Err(KernelInterfaceError::RuntimeError(
                    "No commands given for opkg".to_string(),
                ));
                for cmd in commands.command_list {
                    let res = KI.perform_opkg(cmd);
                    res.clone()?;
                }
                res
            }
        }
    } else {
        Err(KernelInterfaceError::RuntimeError(
            "Not an openwrt device, not updating".to_string(),
        ))
    }
}
