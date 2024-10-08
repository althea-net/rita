use crate::{
    opkg_feeds::{get_release_feed, set_release_feed, CUSTOMFEEDS},
    run_command, KernelInterfaceError as Error,
};
use althea_types::{OpkgCommand, SysupgradeCommand};
use std::process::Output;

pub fn perform_sysupgrade(command: SysupgradeCommand) -> Result<Output, Error> {
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
    run_command("/sbin/sysupgrade", &args_ref)
}

/// This function checks if the function provided is update or install. In case of install, for each of the packages
/// present, the arguments given are applied and opkg install is run
pub fn perform_opkg(command: OpkgCommand) -> Result<Output, Error> {
    match command {
        OpkgCommand::Install {
            packages,
            arguments,
        } => {
            let mut args = arguments;
            args.insert(0, "install".to_string());
            for package in packages {
                args.push(package);
            }
            info!("Running opkg install with args: {:?}", args);
            let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
            run_command("opkg", &args_ref)
        }
        OpkgCommand::Remove {
            packages,
            arguments,
        } => {
            let mut args = arguments;
            args.insert(0, "remove".to_string());
            for package in packages {
                args.push(package);
            }
            info!("Running opkg remove with args: {:?}", args);
            let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
            run_command("opkg", &args_ref)
        }
        OpkgCommand::Update {
            feed,
            feed_name,
            arguments,
        } => {
            handle_release_feed_update(feed, feed_name)?;
            let mut args = arguments;
            args.insert(0, "update".to_string());
            info!("Running opkg update with args: {:?}", args);
            let args_ref: Vec<&str> = args.iter().map(std::ops::Deref::deref).collect();
            run_command("opkg", &args_ref)
        }
    }
}

// updates the release feed if and only if it actually results in a change, this does
// produce a disk write, so we want to avoid it if possible
fn handle_release_feed_update(new_feed: String, feed_name: String) -> Result<(), Error> {
    match get_release_feed(CUSTOMFEEDS, &feed_name) {
        // if there's an error getting the current release feed, try to set anyways
        Err(_) => match set_release_feed(&new_feed, &feed_name, CUSTOMFEEDS) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to set new release feed! {:?}", e);
                Err(e)
            }
        },
        // if we can successfully get the old release feed, check that we are
        // actually changing it, then apply the change
        Ok(old_feed) => {
            if !old_feed.contains(&new_feed) {
                match set_release_feed(&new_feed, &feed_name, CUSTOMFEEDS) {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        error!("Failed to set new release feed! {:?}", e);
                        Err(e)
                    }
                }
            } else {
                Ok(())
            }
        }
    }
}
