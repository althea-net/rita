//! There is a bit of naming conflict here, this file is about 'updating the rita software on the router'
//! versus updating operator tools on the status of this router which is the context of 'update' in the rest
//! of this module

use althea_kernel_interface::{
    is_openwrt::is_openwrt,
    run_command,
    upgrade::{perform_opkg, perform_sysupgrade},
    KernelInterfaceError,
};
use althea_types::UpdateType;

/// Updates the system, including Rita and other packages by performing either a sysupgrade or opkg install
pub fn update_system(instruction: UpdateType) -> Result<(), KernelInterfaceError> {
    if is_openwrt() {
        match instruction {
            UpdateType::Sysupgrade(command) => match perform_sysupgrade(command) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            UpdateType::Opkg(commands) => {
                for cmd in commands {
                    let res = perform_opkg(cmd);
                    match res {
                        Ok(o) => match o.status.code() {
                            Some(0) => info!("opkg completed successfully! {:?}", o),
                            Some(_) => {
                                let err = format!("opkg has failed! {o:?}");
                                error!("{}", err);
                            }
                            None => warn!("No return code form opkg update? {:?}", o),
                        },
                        Err(e) => {
                            error!("Unable to perform opkg with error: {:?}", e);
                            return Err(e);
                        }
                    }
                }

                // Restart rita after opkg
                let args = vec!["restart"];
                if let Err(e) = run_command("/etc/init.d/rita", &args) {
                    error!("Unable to restart rita after opkg update: {}", e)
                }
                if let Err(e) = run_command("/etc/init.d/rita_tower", &args) {
                    error!("Unable to restart rita tower after opkg update: {}", e)
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
