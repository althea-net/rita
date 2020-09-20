use std::env;

/// Random utilities that don't go anywhere else, many of these are used only in one or the other of rita_exit or rita_client so one will use it and the other will
/// throw a dead code warning.
pub mod ip_increment;
pub mod wait_timeout;

#[allow(dead_code)]
pub fn option_deref<T: Copy>(item: Option<&T>) -> Option<T> {
    match item {
        Some(i) => Some(*i),
        None => None,
    }
}

#[allow(dead_code)]
pub fn option_convert<B: std::convert::From<A>, A>(item: Option<A>) -> Option<B> {
    match item {
        Some(val) => Some(val.into()),
        None => None,
    }
}

pub fn env_vars_contains(var_name: &str) -> bool {
    for (key, _value) in env::vars_os() {
        if key == var_name {
            return true;
        }
    }
    false
}
