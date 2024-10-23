use althea_types::SignedExitServerList;
use clarity::Address;
use clarity::PrivateKey;
use crossbeam::queue::SegQueue;
use phonenumber::PhoneNumber;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::Instant;

use crate::register_client_batch_loop::RegistrationRequest;
use crate::RPC_SERVER;

/// Command line arguments
#[derive(clap::Parser, Clone, Debug)]
#[clap(version = env!("CARGO_PKG_VERSION"), author = "Justin Kilpatrick <justin@althea.net>")]
#[command(version, about, long_about = None)]
pub struct Config {
    /// How long to wait for a response from a full node before timing out
    /// in seconds. Set this conservatively to avoid crashing an operation
    /// that has already been running for a long time.
    #[arg(short, long, default_value = "30")]
    pub timeout: u64,
    /// rpc url to use, this should be an ETH node on the same network as the
    /// database smart contract
    #[arg(short, long, default_value = RPC_SERVER)]
    pub rpc: String,
    /// An ethereum private key, used to both sign transactions (root of trust)
    /// and to make requests to the database smart contract, such as registration
    #[arg(short, long)]
    pub private_key: PrivateKey,
    /// SMS API key
    #[arg(short, long)]
    pub telnyx_api_key: String,
    /// SMS verify profile id
    #[arg(short, long)]
    pub verify_profile_id: String,
    /// The Magic number if provided bypasses authentication
    /// and registers the user with the given identity
    #[arg(short, long)]
    pub magic_number: Option<PhoneNumber>,
    /// The Magic number if provided bypasses authentication
    /// and registers the user with the given identity
    /// If set to true use https mode
    #[arg(short, long)]
    pub https: bool,
    /// URL to listen on
    #[arg(short, long)]
    pub url: String,
}

#[derive(Clone, Debug)]
/// Utility struct to hold the config and cache in a single argument
pub struct ConfigAndCache {
    /// The configuration for the server
    pub config: Arc<Config>,
    /// A cache of exit server lists, we try to serve these first before querying the blockchain
    pub cache: Arc<RwLock<HashMap<Address, SignedExitServerList>>>,
    /// A lock free shared queue of registration requests, these are processed by the registration loop
    pub registration_queue: Arc<SegQueue<RegistrationRequest>>,
    /// Data about the number of texts sent to each phone number, each instant represents the last time
    /// a text was sent to that number
    pub texts_sent: Arc<RwLock<HashMap<PhoneNumber, Vec<Instant>>>>,
}

impl ConfigAndCache {
    pub fn insert(&self, key: Address, value: SignedExitServerList) {
        self.cache.write().unwrap().insert(key, value);
    }

    pub fn get_all(&self) -> HashMap<Address, SignedExitServerList> {
        self.cache.read().unwrap().clone()
    }

    pub fn get(&self, key: &Address) -> Option<SignedExitServerList> {
        self.cache.read().unwrap().get(key).cloned()
    }

    pub fn get_config(&self) -> Arc<Config> {
        self.config.clone()
    }

    pub fn insert_client_to_reg_queue(&self, request: RegistrationRequest) {
        self.registration_queue.push(request);
    }

    /// Limits for how many texts can be sent to a given phone number in a given time period
    /// expnentially decreasing over time to prevent spam
    const TEXT_LIMITS: [(Duration, u8); 3] = [
        (Duration::from_secs(60), 1),
        (Duration::from_secs(3600), 10),
        (Duration::from_secs(86400), 20),
    ];
    /// How long to keep a text in the history before dropping it
    const DROP_TEXT_HISTORY: Duration = Duration::from_secs(864000);
    pub fn has_hit_text_limit(&self, key: &PhoneNumber) -> bool {
        let now = Instant::now();
        for (time, limit) in Self::TEXT_LIMITS.iter() {
            let texts = self.get_texts_sent(key);
            let mut count = 0;
            for text in texts.iter() {
                if now.duration_since(*text) < *time {
                    count += 1;
                }
            }
            if count >= *limit {
                return true;
            }
        }
        false
    }

    pub fn get_texts_sent(&self, key: &PhoneNumber) -> Vec<Instant> {
        self.texts_sent
            .read()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    pub fn insert_text_sent(&self, key: PhoneNumber) {
        // clean up old texts while inserting a new one
        let mut texts = self.texts_sent.write().unwrap();
        for (_, texts) in texts.iter_mut() {
            texts.retain(|text| Instant::now().duration_since(*text) < Self::DROP_TEXT_HISTORY);
        }
        texts.entry(key).or_default().push(Instant::now());
    }
}
