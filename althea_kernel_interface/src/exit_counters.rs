use super::{KernelInterface, KernelManagerError};

use std::net::IpAddr;
use std::str::FromStr;
use std::collections::HashMap;

use eui48::MacAddress;
use regex::Regex;

use failure::Error;

#[derive(Debug, Eq, PartialEq)]
pub enum ExitFilterTarget {
    Input,
    Output
}

impl ExitFilterTarget {
    pub fn interface(&self) -> &str {
        match self {
            &ExitFilterTarget::Input  => "-i",
            &ExitFilterTarget::Output => "-o",
        }
    }

    pub fn table(&self) -> &str {
        match self {
            &ExitFilterTarget::Input => "INPUT",
            &ExitFilterTarget::Output => "OUTPUT"
        }
    }

    pub fn regex(&self) -> Regex {
        match self {
            &ExitFilterTarget::Input  => Regex::new(
                r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+([a-zA-Z0-9]+)\s+\*\s+[a-f0-9:/]+\s+([a-f0-9:/]+)",
            ).unwrap(),
            &ExitFilterTarget::Output => Regex::new(
                r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+\*\s+([a-zA-Z0-9]+)\s+[a-f0-9:/]+\s+([a-f0-9:/]+)",
            ).unwrap(),
        }
    }
}