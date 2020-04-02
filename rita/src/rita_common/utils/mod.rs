/// Random utilities that don't go anywhere else, many of these are used only in one or the other of rita_exit or rita_client so one will use it and the other will
/// throw a dead code warning.
pub mod ip_increment;

#[allow(dead_code)]
pub fn option_deref<T: Copy>(item: Option<&T>) -> Option<T> {
    match item {
        Some(i) => Some(*i),
        None => None,
    }
}
