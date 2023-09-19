#[warn(clippy::module_inception)]
#[allow(unused)]
pub mod test {

    use crate::usage_tracker::structs::{
        convert_payment_set_to_payment_hour, UsageTrackerPayment, UsageTrackerStorageOld,
    };
    use crate::usage_tracker::{
        get_current_hour, IOError, PaymentHour, Usage, UsageTrackerStorage, MAX_USAGE_ENTRIES,
        MINIMUM_NUMBER_OF_TRANSACTIONS_LARGE_STORAGE,
    };
    use crate::RitaCommonError;
    use althea_types::{
        convert_map_to_flat_usage_data, Identity, IndexedUsageHour, UnpublishedPaymentTx,
        UsageTrackerTransfer,
    };
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use rand::{thread_rng, Rng};
    use settings::client::RitaClientSettings;
    use settings::{get_rita_common, set_rita_client, set_rita_common};
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::convert::TryInto;
    use std::fs::File;
    use std::io::Write;
    #[cfg(test)]
    impl UsageTrackerStorage {
        // previous implementation of save which uses the old struct to serialize
        fn save2(&self) -> Result<(), RitaCommonError> {
            let old_struct = UsageTrackerStorageOld {
                last_save_hour: self.last_save_hour,
                client_bandwidth: convert_map_to_flat_usage_data(self.client_bandwidth.clone()),
                relay_bandwidth: convert_map_to_flat_usage_data(self.relay_bandwidth.clone()),
                exit_bandwidth: convert_map_to_flat_usage_data(self.exit_bandwidth.clone()),
                payments: convert_payment_set_to_payment_hour(self.payments.clone()),
            };
            let serialized = bincode::serialize(&old_struct)?;
            let mut file = File::create(settings::get_rita_common().network.usage_tracker_file)?;
            let buffer: Vec<u8> = Vec::new();
            let mut encoder = ZlibEncoder::new(buffer, Compression::default());
            encoder.write_all(&serialized)?;
            let compressed_bytes = encoder.finish()?;
            Ok(file.write_all(&compressed_bytes)?)
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

        let res2 = UsageTrackerStorage::load_from_disk();
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
        newrc.network.usage_tracker_file = "/tmp/usage_tracker.bincode".to_string();
        set_rita_common(newrc);
        info!("Generating large usage tracker history");
        let dummy_usage_tracker = generate_dummy_usage_tracker();

        info!("Saving test data in old format");
        dummy_usage_tracker.save2().unwrap();

        info!("Loading test data from oldformat");
        let mut res2 = UsageTrackerStorage::load_from_disk();

        // Saving res2 with the new save() and updated usage_tracker_file in order to end with
        // a .bincode file from the old format bincode file.
        res2.save().unwrap();
        info!("Saving test data as bincode");
        let res4 = UsageTrackerStorage::load_from_disk();
        info!("Loading test data from bincode");

        // use == to avoid printing out the compared data
        // when it failed, as it is enormous
        assert!(dummy_usage_tracker == res2);
        assert!(res2 == res4);
    }

    /// tests that the flat conversion comes out in the right order (decreasing usage hours)
    #[test]
    fn check_flat_conversion() {
        let tracker = generate_dummy_usage_tracker();
        let flat = convert_map_to_flat_usage_data(tracker.client_bandwidth);
        let mut last: Option<IndexedUsageHour> = None;
        for i in flat {
            if let Some(last) = last {
                assert!(i.index < last.index)
            }
            last = Some(i)
        }
    }

    // generates a nontrivial usage tracker struct for testing
    pub fn generate_dummy_usage_tracker() -> UsageTrackerStorage {
        let current_hour = get_current_hour().unwrap();
        UsageTrackerStorage {
            last_save_hour: current_hour,
            client_bandwidth: generate_bandwidth(current_hour),
            relay_bandwidth: generate_bandwidth(current_hour),
            exit_bandwidth: generate_bandwidth(current_hour),
            payments: generate_payments(current_hour),
        }
    }
    // generates dummy usage hour data randomly
    fn generate_bandwidth(starting_hour: u64) -> HashMap<u64, Usage> {
        let num_to_generate: u16 = thread_rng()
            .gen_range(50..MAX_USAGE_ENTRIES)
            .try_into()
            .unwrap();
        let mut output = HashMap::new();
        for i in 0..num_to_generate {
            output.insert(
                i as u64,
                Usage {
                    up: rand::random(),
                    down: rand::random(),
                    price: rand::random(),
                },
            );
        }
        output
    }
    // generates dummy payment data randomly
    fn generate_payments(starting_hour: u64) -> HashSet<UsageTrackerPayment> {
        let mut num_to_generate: u8 = rand::random();
        while (num_to_generate as usize) < MINIMUM_NUMBER_OF_TRANSACTIONS_LARGE_STORAGE {
            num_to_generate = rand::random();
        }
        let our_id = random_identity();
        let neighbor_ids = get_neighbor_ids();
        let mut output = HashSet::new();
        for i in 0..num_to_generate {
            let num_payments_generate: u8 = rand::random();
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
                output.insert(UsageTrackerPayment {
                    to,
                    from,
                    amount: amount.into(),
                    txid: txid.into(),
                    index: starting_hour - i as u64,
                });
            }
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
        let eth_key = PrivateKey::from_bytes(secret).unwrap();
        let eth_address = eth_key.to_address();

        Identity {
            mesh_ip: ip.into(),
            eth_address,
            wg_public_key: secret.into(),
            nickname: None,
        }
    }
}
