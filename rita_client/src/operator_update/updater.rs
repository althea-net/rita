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
                let res = handle_release_feed_update(Some(commands.feed));
                if let Err(e) = res {
                    error!("Unable to update release feed for opkg update {:?}", e);
                    return Err(e);
                }
                info!("Set new release feed for opkg");

                //opkg commands
                let mut res = Err(KernelInterfaceError::RuntimeError(
                    "No commands given for opkg".to_string(),
                ));
                for cmd in commands.command_list {
                    res = KI.perform_opkg(cmd);
                    if res.is_err() {
                        error!("Unable to perform opkg with error: {:?}", res);
                        return res;
                    }
                }

                // Restart rita after opkg
                let args = vec!["restart"];
                if let Err(e) = KI.run_command("/etc/init.d/babeld", &args) {
                    error!("Unable to restart babel after opkg update: {}", e);
                }
                if let Err(e) = KI.run_command("/etc/init.d/rita", &args) {
                    error!("Unable to restart rita after opkg update: {}", e)
                }
                res
            }
        }
    } else {
        error!("Recieved update command for device not openWRT");
        Err(KernelInterfaceError::RuntimeError(
            "Not an openwrt device, not updating".to_string(),
        ))
    }
}
