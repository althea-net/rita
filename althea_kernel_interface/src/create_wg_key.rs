use super::{KernelInterface, KernelManagerError};

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use failure::Error;

impl KernelInterface {
    pub fn create_wg_key(&self, path: &Path, private_key :&String) -> Result<(), Error> {
        if path.exists() {
            warn!("System private key exists in {:?}", path);
        } else {
            trace!("File does not exist, creating");
            let mut priv_key_file = File::create(path)?;
            write!(priv_key_file, "{}", private_key);
            Ok(())
        }
    }

    pub fn create_wg_keypair(&mut self) -> Result<[String; 2], Error> {
        let mut genkey = Command::new("wg")
            .args(&["genkey"])
            .stdout(Stdio::piped())
            .output()
            .unwrap();

        let mut genstdout = genkey.stdout;
        let mut pubkey = Command::new("wg")
            .args(&["pubkey"])
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();

        pubkey.stdin.as_mut().unwrap().write_all(&genstdout);
        let output = pubkey.wait_with_output().unwrap();

        let mut privkey_str = String::from_utf8(genstdout)?;
        let mut pubkey_str = String::from_utf8(output.stdout)?;
        privkey_str.truncate(44);
        pubkey_str.truncate(44);

        Ok([pubkey_str, privkey_str])
    }

}

//TODO some tests
