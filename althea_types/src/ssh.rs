#[derive(Hash, Eq, PartialEq, Debug)]
pub struct AuthorizedKeys {
    // public ssh key
    pub key: String,
    // if the key is managed by ops-tools or network operator
    pub managed: bool,
    // set flush to remove key from configuratio
    pub flush: bool,
}
