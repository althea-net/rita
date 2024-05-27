use std::env;
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use babel_monitor::open_babel_stream;
use babel_monitor::structs::BabeldConfig;

/// Random utilities that don't go anywhere else, many of these are used only in one or the other of rita_exit or rita_client so one will use it and the other will
/// throw a dead code warning.
pub mod ip_increment;

#[allow(dead_code)]
pub fn option_convert<B: std::convert::From<A>, A>(item: Option<A>) -> Option<B> {
    item.map(|val| val.into())
}

pub fn env_vars_contains(var_name: &str) -> bool {
    for (key, _value) in env::vars_os() {
        if key == var_name {
            return true;
        }
    }
    false
}

// lossy conversion, but it won't matter until 2.9 * 10^8 millenia from now
pub fn secs_since_unix_epoch() -> i64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() as i64
}

/// This function is intended to be called at startup before any other threads are started
/// it takes the babel config and applies the settings to Babel. This must be done before
/// tunnel manager starts operating or tunnels will be setup that don't respect the defaults
/// we are trying to configure. All of these values can be changed at runtime but this function is
/// intended for startup only
pub fn apply_babeld_settings_defaults(babeld_port: u16, config: BabeldConfig) {
    // how long before we give up trying to contact babel, since this is a startup process babeld
    // many not be reachable due to just being started so we want to wait a bit, but not indefinately
    const BABEL_CONTACT_TIMEOUT: Duration = Duration::from_secs(20);
    let start = Instant::now();
    while Instant::now() < start + BABEL_CONTACT_TIMEOUT {
        match open_babel_stream(babeld_port, BABEL_CONTACT_TIMEOUT) {
            Ok(mut stream) => {
                if let Err(e) = babel_monitor::set_local_fee(&mut stream, config.local_fee) {
                    error!("Failed to set babel local fee with {:?}", e);
                }
                if let Err(e) = babel_monitor::set_metric_factor(&mut stream, config.metric_factor)
                {
                    error!("Failed to set babel metric factor with {:?}", e);
                }
                if let Err(e) = babel_monitor::set_kernel_check_interval(
                    &mut stream,
                    config.kernel_check_interval,
                ) {
                    error!("Failed to set babel kernel check interval with {:?}", e);
                }
                info!("Successfully completed babeld setup!");
                return;
            }
            Err(e) => error!("Failed to connect to babel! {:?}", e),
        }
    }
    panic!(
        "Unable to reach babel on {} please check that babel is running and configured correctly",
        babeld_port
    );
}
