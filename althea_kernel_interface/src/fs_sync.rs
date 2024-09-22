use crate::run_command;
use crate::KernelInterfaceError as Error;

/// Performs a full filesystem sync by running the sync command.
/// If there are any outstanding writes they will be flushed to the disk
/// Currently used because UBIFS devices seem to have issues
pub fn fs_sync() -> Result<(), Error> {
    run_command("sync", &[])?;
    Ok(())
}
