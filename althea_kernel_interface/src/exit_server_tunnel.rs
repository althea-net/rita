use super::{KernelInterface, KernelManagerError};

use failure::Error;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::collections::HashMap;

#[derive(Debug)]
pub struct ExitClient {
    pub internal_ip: IpAddr,
    pub public_key: String,
    pub mesh_ip: IpAddr,
    pub port: u16,
}

impl KernelInterface {
    pub fn set_exit_wg_config(
        &self,
        clients: Vec<(ExitClient)>,
        listen_port: u16,
    ) -> Result<(), Error> {
        let command = "wg".to_string();

        let mut args = Vec::new();
        args.push("set".into());
        args.push("wg_exit".into());
        args.push("listen-port".into());
        args.push(format!("{}", listen_port));
        args.push("private-key".into());
        args.push("priv".into());

        for c in clients {
            args.push("peer".into());
            args.push(format!("{}", c.public_key));
            args.push("endpoint".into());
            args.push(format!("[{}]:{}", c.mesh_ip, c.port));
            args.push("allowed-ips".into());
            args.push(format!("{}", c.internal_ip));
            args.push("persistent-keepalive".into());
            args.push("5".into());
        }

        let mut args_str = Vec::new();

        let arg_count = args.len();

        for i in 0..arg_count {
            args_str.push(args[i].as_str())
        }

        self.run_command(&command, &args_str[..]);

        Ok(())
    }
}
