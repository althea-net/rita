use crate::KernelInterface;
use crate::KernelInterfaceError;
use oping::Ping;
use std::net::IpAddr;
use std::time::Duration;

impl dyn KernelInterface {
    //Pings a ipv6 address to determine if it's online
    pub fn ping_check(
        &self,
        ip: &IpAddr,
        timeout: Duration,
        outgoing_device: Option<&str>,
    ) -> Result<bool, KernelInterfaceError> {
        trace!("starting ping");
        let mut ping = Ping::new();
        ping.add_host(&ip.to_string())?;

        // set outgoing device as needed
        if let Some(device) = outgoing_device {
            ping.set_device(device)?;
        }

        ping.set_timeout(timeout.as_millis() as f64 / 1000f64)?;
        trace!("sending ping");
        let mut response = ping.send()?;
        trace!("sent ping");
        if let Some(res) = response.next() {
            trace!("got ping response {:?}", res);
            // we get dropped '1' to mean the packet is dropped
            // because this create offers c bindings and doesn't do
            // much of anything to adapt them
            Ok(res.dropped == 0)
        } else {
            Ok(false)
        }
    }
}
