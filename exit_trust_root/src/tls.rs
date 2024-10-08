//! boilerplate for tls support

use clarity::PrivateKey;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::DEVELOPMENT;

pub fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

pub fn load_rustls_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

// the exit root of trust server uses this key to sign exit server lists sent back to clients
pub fn load_clarity_private_key() -> clarity::PrivateKey {
    if DEVELOPMENT {
        return "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1e"
            .parse()
            .unwrap();
    }
    let filename = "/etc/exit_root_privkey";
    let keyfile = File::open(filename).expect("cannot open clarity private key file");
    let reader = BufReader::new(keyfile);
    if let Some(key) = reader.lines().next() {
        let res: PrivateKey = key.unwrap().parse().expect("failed to parse private key");
        return res;
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}
