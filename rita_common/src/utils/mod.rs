use std::env;

/// Random utilities that don't go anywhere else, many of these are used only in one or the other of rita_exit or rita_client so one will use it and the other will
/// throw a dead code warning.
pub mod ip_increment;
pub mod wait_timeout;

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
