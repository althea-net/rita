#[cfg(test)]
#[warn(clippy::module_inception)]
pub mod test {

    use crate::usage_tracker::{
        self, get_current_hour, FormattedPaymentTx, IOError, PaymentHour, UsageHour, UsageTracker,
        MINIMUM_NUMBER_OF_TRANSACTIONS_LARGE_STORAGE,
    };
    use althea_types::Identity;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use settings::client::RitaClientSettings;
    use settings::{get_rita_common, set_rita_client, set_rita_common};
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::Write;
    impl UsageTracker {
        // previous implementation of save which uses serde_json to serialize
        fn save2(&self) -> Result<(), IOError> {
            let serialized = serde_json::to_vec(self)?;
            let mut file = File::create(settings::get_rita_common().network.usage_tracker_file)?;
            let buffer: Vec<u8> = Vec::new();
            let mut encoder = ZlibEncoder::new(buffer, Compression::default());
            encoder.write_all(&serialized)?;
            let compressed_bytes = encoder.finish()?;
            file.write_all(&compressed_bytes)
        }
    }

    #[test]
    fn save_usage_tracker_bincode() {
        let rset = RitaClientSettings::new("../settings/test.toml").unwrap();
        set_rita_client(rset);
        let mut newrc = get_rita_common();
        newrc.network.usage_tracker_file = "/tmp/usage_tracker.bincode".to_string();
        set_rita_common(newrc);

        let mut dummy_usage_tracker = generate_dummy_usage_tracker();
        let res = dummy_usage_tracker.save(); // saving to bincode with the new method
        info!("Saving test  data: {:?}", res);

        let res2 = usage_tracker::UsageTracker::load_from_disk();
        info!("Loading test  data: {:?}", res2);

        assert_eq!(dummy_usage_tracker, res2);
    }

    #[test]
    fn convert_legacy_usage_tracker() {
        //env_logger::init();
        // make a dummy usage tracker instance
        // save it as gzipped json ( pull code from the git history that you deleted and put it in this test)
        // makes sure the file exists
        // deserialize the file using the upgrade function
        // make sure it's equal to the original dummy we made
        let rset = RitaClientSettings::new("../settings/test.toml").unwrap();
        set_rita_client(rset);
        let mut newrc = get_rita_common();
        newrc.network.usage_tracker_file = "/tmp/usage_tracker.json".to_string();
        set_rita_common(newrc);
        info!("Generating large usage tracker history");
        let dummy_usage_tracker = generate_dummy_usage_tracker();

        info!("Saving test data as json");
        dummy_usage_tracker.save2().unwrap();

        // using load_from_disk() with usage_tracker_file set to a .json writes bincode
        // serialized data to a .json extended file, but because load_from_disk() deletes
        // the .json file, this test ends with no file left.
        info!("Loading test data from json");
        let mut res2 = usage_tracker::UsageTracker::load_from_disk();

        // setting the usage_tracker_file to .bincode, which is what this upgrade expects
        let mut newrc2 = get_rita_common();
        newrc2.network.usage_tracker_file = "/tmp/usage_tracker.bincode".to_string();
        set_rita_common(newrc2);

        // Saving res2 with the new save() and updated usage_tracker_file in order to end with
        // a .bincode file from the loaded json data saved to res2.
        res2.save().unwrap();
        info!("Saving test data as bincode");
        let res4 = usage_tracker::UsageTracker::load_from_disk();
        info!("Loading test data from bincode");

        // use == to avoid printing out the compared data
        // when it failed, as it is enormous
        assert!(dummy_usage_tracker == res2);
        assert!(res2 == res4);
    }
    // generates a nontrivial usage tracker struct for testing
    pub fn generate_dummy_usage_tracker() -> UsageTracker {
        let current_hour = get_current_hour().unwrap();
        UsageTracker {
            last_save_hour: current_hour,
            client_bandwidth: generate_bandwidth(current_hour),
            relay_bandwidth: generate_bandwidth(current_hour),
            exit_bandwidth: generate_bandwidth(current_hour),
            payments: generate_payments(current_hour),
        }
    }
    // generates dummy usage hour data randomly
    fn generate_bandwidth(starting_hour: u64) -> VecDeque<UsageHour> {
        let num_to_generate: u16 = rand::random();
        let mut output = VecDeque::new();
        for i in 0..num_to_generate {
            output.push_front(UsageHour {
                index: starting_hour - i as u64,
                up: rand::random(),
                down: rand::random(),
                price: rand::random(),
            });
        }
        output
    }
    // generates dummy payment data randomly
    fn generate_payments(starting_hour: u64) -> VecDeque<PaymentHour> {
        let mut num_to_generate: u8 = rand::random();
        while (num_to_generate as usize) < MINIMUM_NUMBER_OF_TRANSACTIONS_LARGE_STORAGE {
            num_to_generate = rand::random();
        }
        let our_id = random_identity();
        let neighbor_ids = get_neighbor_ids();
        let mut output = VecDeque::new();
        for i in 0..num_to_generate {
            let num_payments_generate: u8 = rand::random();
            let mut payments = Vec::new();
            for _ in 0..num_payments_generate {
                let neighbor_idx: u8 = rand::random();
                let amount: u128 = rand::random();
                let to_us: bool = rand::random();
                let (to, from) = if to_us {
                    (our_id, neighbor_ids[neighbor_idx as usize])
                } else {
                    (neighbor_ids[neighbor_idx as usize], our_id)
                };
                let txid: u128 = rand::random();
                payments.push(FormattedPaymentTx {
                    to,
                    from,
                    amount: amount.into(),
                    txid: txid.to_string(),
                })
            }
            output.push_front(PaymentHour {
                index: starting_hour - i as u64,
                payments,
            });
        }
        output
    }
    // gets a list of pregenerated neighbor id
    fn get_neighbor_ids() -> Vec<Identity> {
        let mut id = Vec::new();
        for _ in 0..256 {
            id.push(random_identity());
        }
        id
    }
    /// generates a random identity, never use in production, your money will be stolen
    pub fn random_identity() -> Identity {
        use clarity::PrivateKey;

        let secret: [u8; 32] = rand::random();
        let mut ip: [u8; 16] = [0; 16];
        ip.copy_from_slice(&secret[0..16]);

        // the starting location of the funds
        let eth_key = PrivateKey::from_slice(&secret).unwrap();
        let eth_address = eth_key.to_address();

        Identity {
            mesh_ip: ip.into(),
            eth_address,
            wg_public_key: secret.into(),
            nickname: None,
        }
    }
}
