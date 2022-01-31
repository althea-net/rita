use super::KernelInterface;
use crate::KernelInterfaceError as Error;
use althea_types::{OpkgCommand, OpkgCommandType, SysupgradeCommand};
use std::process::Output;

impl dyn KernelInterface {
    pub fn perform_sysupgrade(&self, command: SysupgradeCommand) -> Result<Output, Error> {
        //If empty url, return error
        if command.url.is_empty() {
            info!("Empty url given to sysupgrade");
            return Err(Error::RuntimeError(
                "Empty url given to sysupgrade".to_string(),
            ));
        }

        // append path to end of flags
        let mut args = if command.flags.is_some() {
            command.flags.unwrap()
        } else {
            Vec::new()
        };
        args.push(command.url);
        let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
        info!(
            "Running the command /sbin/sysupgrade with args: {:?}",
            args_ref
        );
        self.run_command("/sbin/sysupgrade", &args_ref)
    }

    /// This function checks if the function provided is update or install. In case of install, for each of the packages
    /// present, the arguments given are applied and opkg install is run
    pub fn perform_opkg(&self, command: OpkgCommand) -> Result<Output, Error> {
        match command.opkg_command {
            OpkgCommandType::Update => {
                if command.packages.is_none() {
                    let mut args = command.arguments.unwrap_or_default();
                    args.insert(0, "update".to_string());
                    let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
                    info!("Running command opkg with args: {:?}", args_ref);
                    self.run_command("opkg", &args_ref)
                } else {
                    let mut res = Err(Error::RuntimeError(
                        "No packages given to update".to_string(),
                    ));
                    for packet in command.packages.clone().unwrap() {
                        let mut args = command.arguments.clone().unwrap_or_default();
                        args.insert(0, packet);
                        args.insert(0, "update".to_string());
                        let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
                        info!("Running command opkg with args: {:?}", args_ref);
                        res = self.run_command("opkg", &args_ref);
                        res.clone()?;
                    }
                    res
                }
            }
            OpkgCommandType::Install => {
                let mut res = Err(Error::RuntimeError(
                    "No packages given to install".to_string(),
                ));
                if command.packages.is_none() {
                    error!("No packages given to opkg install");
                    return res;
                }
                for packet in command.packages.clone().unwrap() {
                    let mut args = command.arguments.clone().unwrap_or_default();
                    args.insert(0, packet);
                    args.insert(0, "install".to_string());
                    let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
                    info!("Running command opkg with args: {:?}", args_ref);
                    res = self.run_command("opkg", &args_ref);
                    res.clone()?;
                }
                res
            }
        }
    }
}
