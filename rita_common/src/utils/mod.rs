use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

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
