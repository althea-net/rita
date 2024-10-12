#[warn(clippy::module_inception)]
#[allow(unused)]
#[cfg(test)]
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
    use althea_types::{identity::random_identity, PaymentTx};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use rand::{thread_rng, Rng};
    use serial_test::serial;
    use settings::client::RitaClientSettings;
    use settings::{get_rita_common, set_rita_client, set_rita_common};
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::convert::TryInto;
    use std::fs::File;
    use std::io::Write;

    #[test]
    #[serial]
    fn save_usage_tracker_bincode() {
        let rset = RitaClientSettings::new("../settings/test.toml").unwrap();
        let rset = RitaClientSettings::default();
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

    /// tests that the flat conversion comes out in the right order (increasing usage hours)
    #[test]
    fn check_flat_conversion() {
        let tracker = generate_dummy_usage_tracker();
        let flat = convert_map_to_flat_usage_data(tracker.client_bandwidth);
        let mut last: Option<IndexedUsageHour> = None;
        for i in flat {
            if let Some(last) = last {
                assert!(i.index > last.index)
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
}
