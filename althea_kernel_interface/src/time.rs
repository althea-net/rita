use std::time::{SystemTime, UNIX_EPOCH};

use super::KernelInterface;
use crate::KernelInterfaceError as Error;
use std::process::Output;

impl dyn KernelInterface {
    /// Set the router's time using "date -s @seconds_since_unix_epoch"
    pub fn set_local_time(&self, time: SystemTime) -> Result<Output, Error> {
        let time_secs = time.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let t = format!("@{}", time_secs);
        trace!("setting local time to exit time {}", t);
        match self.run_command("date", &["-s", t.as_str()]) {
            Ok(output) => {
                trace!("time was changed.  new time: {:?}", SystemTime::now());
                trace!("output: {:?}", output);
                Ok(output)
            }
            Err(e) => {
                error!("Failed to set local time: {:?}", e);
                Err(e)
            }
        }
    }
}
