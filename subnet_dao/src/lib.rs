#[macro_use]
extern crate failure;

extern crate web3;

use std::net::IpAddr;

use failure::Error;

// TODO actually meet this description
/// Determines if a mesh ip is on the user configured Subnet DAO
/// Should never return Err() during normal operation so you can
/// safely unwrap. There is also aggressive in-memory caching to
/// allow freqent queries.
pub fn is_on_registry(mesh_ip: IpAddr) -> Result<bool, Error> {
    if !mesh_ip.is_ipv6() {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
