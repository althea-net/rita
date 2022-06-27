use althea_kernel_interface::KernelInterfaceError;
use althea_types::UpdateType;
use rita_common::KI;

/// Updates the system, including Rita and other packages by performing either a sysupgrade or opkg install
pub fn update_system(instruction: UpdateType) -> Result<(), KernelInterfaceError> {
    if KI.is_openwrt() {
        match instruction {
            UpdateType::Sysupgrade(command) => match KI.perform_sysupgrade(command) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            UpdateType::Opkg(commands) => {
                for cmd in commands {
                    let res = KI.perform_opkg(cmd);
                    if let Err(e) = res {
                        error!("Unable to perform opkg with error: {:?}", e);
                        return Err(e);
                    }
                }

                // Restart rita after opkg
                let args = vec!["restart"];
                if let Err(e) = KI.run_command("/etc/init.d/rita", &args) {
                    error!("Unable to restart rita after opkg update: {}", e)
                }
                Ok(())
            }
        }
    } else {
        error!("Recieved update command for device not openWRT");
        Err(KernelInterfaceError::RuntimeError(
            "Not an openwrt device, not updating".to_string(),
        ))
    }
}
