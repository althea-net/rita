pub mod ip_increment;

#[allow(dead_code)]
pub fn option_deref<T: Copy>(item: Option<&T>) -> Option<T> {
    match item {
        Some(i) => Some(*i),
        None => None,
    }
}
