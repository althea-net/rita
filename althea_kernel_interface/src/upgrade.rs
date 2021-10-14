use super::KernelInterface;
use crate::KernelInterfaceError as Error;
use althea_types::{OpkgCommand, OpkgCommandType};
use std::process::Output;

impl dyn KernelInterface {
    pub fn perform_sysupgrade(&self, path: &str) -> Result<Output, Error> {
        self.run_command("/sbin/sysupgrade", &[path])
    }

    /// This function checks if the function provided is update or install. In case of install, for each of the packages
    /// present, the arguments given are applied and opkg install is run
    pub fn perform_opkg(&self, command: OpkgCommand) -> Result<Output, Error> {
        match command.opkg_command {
            OpkgCommandType::Update => {
                if command.packages.is_none() {
                    let mut args = command.arguments.unwrap();
                    args.insert(0, "update".to_string());
                    let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
                    self.run_command("opkg", &args_ref)
                } else {
                    let mut res = Err(Error::RuntimeError(
                        "No packages given to update".to_string(),
                    ));
                    for packet in command.packages.clone().unwrap() {
                        let mut args = command.arguments.clone().unwrap();
                        args.insert(0, packet);
                        args.insert(0, "update".to_string());
                        let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
                        res = self.run_command("opkg", &args_ref);
                        if res.is_err() {
                            return res;
                        }
                    }
                    res
                }
            }
            OpkgCommandType::Install => {
                let mut res = Err(Error::RuntimeError(
                    "No packages given to install".to_string(),
                ));
                if command.packages.is_none() {
                    return res;
                }
                for packet in command.packages.clone().unwrap() {
                    let mut args = command.arguments.clone().unwrap();
                    args.insert(0, packet);
                    args.insert(0, "install".to_string());
                    let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
                    res = self.run_command("opkg", &args_ref);
                    if res.is_err() {
                        return res;
                    }
                }
                res
            }
        }
    }
}
