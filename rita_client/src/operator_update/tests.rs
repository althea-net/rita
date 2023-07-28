#[cfg(test)]
mod test {
    use rand::seq::SliceRandom;
    // TODO: Why is this import broken?
    //use rita_common::usage_tracker::generate_dummy_usage_tracker;
    use rita_common::usage_tracker::get_current_hour;
    use rita_common::usage_tracker::UsageHour as RCUsageHour;
    use rita_common::usage_tracker::UsageTracker as RCUsageTracker;
    use serde_json::json;
    use serde_json::Value;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Write};
    use std::{fs, io::Error, path::Path};

    use crate::operator_update::contains_forbidden_key;
    use crate::operator_update::process_usage_data;
    use crate::operator_update::update_authorized_keys;

    const FORBIDDEN_MERGE_VALUES: [&str; 2] = ["test_key", "other_test_key"];

    #[test]
    fn test_contains_key() {
        // exact key match should fail
        let object = json!({"localization": { "wyre_enabled": true, "wyre_account_id": "test_key", "test_key": false}});
        if let Value::Object(map) = object {
            assert!(contains_forbidden_key(map, &FORBIDDEN_MERGE_VALUES));
        } else {
            panic!("Not a json map!");
        }

        // slightly modified key should not match
        let object = json!({"localization": { "wyre_enabled": true, "wyre_account_id": "test_key", "test_key1": false}});
        if let Value::Object(map) = object {
            assert!(!contains_forbidden_key(map, &FORBIDDEN_MERGE_VALUES));
        } else {
            panic!("Not a json map!");
        }
    }
    fn touch_temp_file(file_name: &str) -> &str {
        let test_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_name);
        let operator_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL+UBakquB9rJ7tA2H+U43H/xNmpJiHpOkHGpVfFUXgP OPERATOR";
        writeln!(test_file.unwrap(), "{operator_key}").expect("setup failed to create temp file");
        operator_key
    }
    fn remove_temp_file(file_name: &str) -> Result<(), Error> {
        fs::remove_file(file_name)
    }
    fn parse_keys(file_name: &str) -> Vec<String> {
        let mut temp = Vec::new();
        let expected = File::open(file_name).unwrap();
        let reader = BufReader::new(expected);
        for key in reader.lines() {
            temp.push(key.unwrap());
        }
        temp
    }

    #[test]
    fn test_update_auth_keys() {
        let added_keys = vec![String::from("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFgFrnSm9MFS1zpHHvwtfLohjqtsK13NyL41g/zyIhK test@hawk-net")];
        let removed_keys = vec![];
        let key_file: &str = "authorized_keys";
        let operator_key = touch_temp_file(key_file);

        let _update = update_authorized_keys(added_keys.clone(), removed_keys, key_file);
        let result = parse_keys(key_file);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&added_keys[0]));
        assert!(result.contains(&operator_key.to_string()));
        remove_temp_file(key_file).unwrap();
    }

    #[test]
    fn test_update_auth_multiple_keys() {
        let added_keys = vec![String::from("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFgFrnSm9MFS1zpHHvwtfLohjqtsK13NyL41g/zyIhK test@hawk-net"),
               String::from("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVF1POOko4/fTE/SowsURSmd+kAUFDX6VPNqICJjn8eQk8FZ15WsZKfBdrGXLhl2+pxM66VWMUVRQOq84iSRVSVPA3abz0H7JYIGzO8psTweSZfK1jwHfKDGQA1h1aPuspnPrX7dyS1qLZf3YeVUUi+BFsW2gSiMadbS4zal2c2F1AG5Ezr3zcRVA8y3D0bZxScPAEX74AeTFcimHpHFyzDtUsRpf0uSEXZcMFqX5j4ETKlIs28k1v8LlhHo91IQYHEtbyi/I1M0axbF4VCz5JlcbAs9LUEJg8Kx8LxzJSeSJbxVwyk5WiEDwVsCL2MAtaOcJ+/FhxLb0ZEELAHnXFNSqmY8QoHeSdHrGP7FmVCBjRb/AhVUHYvsG94rO3Ij4H5XsbsQbP3AHVKbvf387WB53Wga7VrBXvRC9aDisetdP9+4/seVIBbOIePotaiHoTyS1cJ+Jg0PkKy96enqwMt9T1Wt8jURB+s/A/bDGHkjB3dxomuGxux8dD6UNX54M= test-rsa@hawk-net"),
        ];
        let removed_keys = vec![];
        let key_file: &str = "add_keys";

        let operator_key = touch_temp_file(key_file);

        let _update = update_authorized_keys(added_keys.clone(), removed_keys, key_file);
        let result = parse_keys(key_file);
        assert!(result.contains(&added_keys[0]));
        assert!(result.contains(&added_keys[1]));
        assert!(result.contains(&operator_key.to_string()));
        assert_eq!(result.len(), 3);
        remove_temp_file(key_file).unwrap();
    }

    #[test]
    fn test_update_auth_remove_keys() {
        let added_keys = vec![];
        let removed_keys = vec![
            String::from("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFgFrnSm9MFS1zpHHvwtfLohjqtsK13NyL41g/zyIhK test@hawk-net"),
            String::from("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVF1POOko4/fTE/SowsURSmd+kAUFDX6VPNqICJjn8eQk8FZ15WsZKfBdrGXLhl2+pxM66VWMUVRQOq84iSRVSVPA3abz0H7JYIGzO8psTweSZfK1jwHfKDGQA1h1aPuspnPrX7dyS1qLZf3YeVUUi+BFsW2gSiMadbS4zal2c2F1AG5Ezr3zcRVA8y3D0bZxScPAEX74AeTFcimHpHFyzDtUsRpf0uSEXZcMFqX5j4ETKlIs28k1v8LlhHo91IQYHEtbyi/I1M0axbF4VCz5JlcbAs9LUEJg8Kx8LxzJSeSJbxVwyk5WiEDwVsCL2MAtaOcJ+/FhxLb0ZEELAHnXFNSqmY8QoHeSdHrGP7FmVCBjRb/AhVUHYvsG94rO3Ij4H5XsbsQbP3AHVKbvf387WB53Wga7VrBXvRC9aDisetdP9+4/seVIBbOIePotaiHoTyS1cJ+Jg0PkKy96enqwMt9T1Wt8jURB+s/A/bDGHkjB3dxomuGxux8dD6UNX54M= test-rsa@hawk-net"),
        ];
        let key_file: &str = "auth_remove_keys";

        let operator_key = touch_temp_file(key_file);

        let _update = update_authorized_keys(added_keys, removed_keys, key_file);
        let result = parse_keys(key_file);
        assert!(result.contains(&operator_key.to_string()));

        assert_eq!(result.len(), 1);

        remove_temp_file(key_file).unwrap();
    }
    #[test]
    fn test_removing_existing_key() {
        let added_keys = vec![];
        let key_file: &str = "remove_keys";

        let operator_key = touch_temp_file(key_file);
        let removed_keys = vec![String::from(operator_key)];
        let _update = update_authorized_keys(added_keys, removed_keys.clone(), key_file);

        let result = parse_keys(key_file);
        for item in result {
            assert_eq!(item, removed_keys[0].to_string());
        }

        remove_temp_file(key_file).unwrap();
    }
    #[test]
    fn test_authorized_keys_create_if_missing() {
        let added_keys = vec![
            String::from("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFgFrnSm9MFS1zpHHvwtfLohjqtsK13NyL41g/zyIhK test@hawk-net ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVF1POOko4/fTE/SowsURSmd+kAUFDX6VPNqICJjn8eQk8FZ15WsZKfBdrGXLhl2+pxM66VWMUVRQOq84iSRVSVPA3abz0H7JYIGzO8psTweSZfK1jwHfKDGQA1h1aPuspnPrX7dyS1qLZf3YeVUUi+BFsW2gSiMadbS4zal2c2F1AG5Ezr3zcRVA8y3D0bZxScPAEX74AeTFcimHpHFyzDtUsRpf0uSEXZcMFqX5j4ETKlIs28k1v8LlhHo91IQYHEtbyi/I1M0axbF4VCz5JlcbAs9LUEJg8Kx8LxzJSeSJbxVwyk5WiEDwVsCL2MAtaOcJ+/FhxLb0ZEELAHnXFNSqmY8QoHeSdHrGP7FmVCBjRb/AhVUHYvsG94rO3Ij4H5XsbsQbP3AHVKbvf387WB53Wga7VrBXvRC9aDisetdP9+4/seVIBbOIePotaiHoTyS1cJ+Jg0PkKy96enqwMt9T1Wt8jURB+s/A/bDGHkjB3dxomuGxux8dD6UNX54M= test-rsa@hawk-net"),
        ];
        let removed_keys: Vec<String> = vec![];
        let key_file: &str = "create_keys_file";
        let _update = update_authorized_keys(added_keys, removed_keys, key_file);
        assert!(Path::new(key_file).exists());
    }
    #[test]
    fn test_usage_data_processing() {
        // this tests the flow used in rita client's operator update loop used to process usage data sent up to ops
        let dummy_usage_tracker = generate_dummy_usage_tracker_temp();
        let mut usage_data_client = dummy_usage_tracker.client_bandwidth.clone();
        let mut usage_data_relay = dummy_usage_tracker.relay_bandwidth;
        let mut unshuffled_client = usage_data_client.clone();
        let mut unshuffled_relay = usage_data_relay.clone();

        // Test the sort function first:
        // shuffle the data because it's currently ordered
        usage_data_client
            .make_contiguous()
            .shuffle(&mut rand::thread_rng());
        println!(
            "Sample of current shuffle is {} {} {}",
            usage_data_client.get(0).unwrap().index,
            usage_data_client.get(1).unwrap().index,
            usage_data_client.get(2).unwrap().index
        );
        usage_data_relay
            .make_contiguous()
            .shuffle(&mut rand::thread_rng());
        // The processing function sorts these lowest index to highest. Note that usage hours are stored to disk as
        // the opposite order where newest are added to the front, so this is inefficient.
        // Options here to optimize are either a/write my own binary sort again which will compare for the existing structure
        // where the saved vecdeque is highest index to lowest index, b/rework usage tracker so that we save data lowest index
        // to highest index, or c/the current solution(inefficient, as we will be fully reversing the whole vecdeque of each
        // client and relay at least once per hour on rollover): sort the entire list in reverse order to use with the builtin
        // bin search from vecdeque

        // for this purpose our last seen will be start hour - 10.
        let current_hour = get_current_hour().unwrap();
        let last_seen_hour = current_hour - 10;
        let res_usage = process_usage_data(
            usage_data_client.clone(),
            usage_data_relay.clone(),
            last_seen_hour,
            current_hour,
        )
        .unwrap();
        let res_usage_client = res_usage.client_bandwidth;
        let res_usage_relay = res_usage.relay_bandwidth;

        // check that the sorting in process_usage_data is correct after shuffling and sending it through
        assert!(
            res_usage_relay.get(0).unwrap().index < res_usage_relay.get(1).unwrap().index
                && res_usage_relay.get(1).unwrap().index < res_usage_relay.get(2).unwrap().index
        );
        assert!(
            res_usage_client.get(0).unwrap().index < res_usage_client.get(1).unwrap().index
                && res_usage_client.get(1).unwrap().index < res_usage_client.get(2).unwrap().index
        );
        // check that the binary searching is correct: we did not remove any entries from usage client; so we should have started exactly
        // from the last seen hour. we removed the last seen from usage relay, so we should expect to see our earliest hour as one fewer
        assert!(res_usage_client.get(0).unwrap().index == last_seen_hour);
        assert!(res_usage_relay.get(0).unwrap().index == last_seen_hour);

        // now check that same thing, but in case we have a gap in the data. we'll remove the entry for the last_seen_hour from usage_data_relay
        // to make sure we are successfully returning the next earliest hour (in our case, the last seen -1). we use res_usage client and relay
        // because to remove the correct entry it needs to be presorted (if we've gotten here it's guaranteed.)
        // we successfully search for the entry or return the next one down.
        unshuffled_client.remove(unshuffled_client.len() - 11);
        unshuffled_relay.remove(unshuffled_relay.len() - 11);
        // so the index of our last seen hour if we say last seen is current - 10... will be at len - 11.
        let res_usage = process_usage_data(
            unshuffled_client,
            unshuffled_relay,
            last_seen_hour,
            current_hour,
        )
        .unwrap();
        let res_usage_client = res_usage.client_bandwidth;
        let res_usage_relay = res_usage.relay_bandwidth;
        // after processing we should start at last seen - 1.
        println!(
            "{:?} last seen {:?}",
            res_usage_relay.get(0).unwrap().index,
            last_seen_hour
        );
        assert!(res_usage_relay.get(0).unwrap().index == last_seen_hour - 1);
        assert!(res_usage_client.get(0).unwrap().index == last_seen_hour - 1);

        // check that our iteration function does indeed stop at a month of data:
        assert!(res_usage_client.len() <= 730);
        assert!(res_usage_relay.len() <= 730);
    }

    // generates a usage tracker struct for testing without payments since these do not get sent up in ops updates.
    // using this while I can't get the import working... as a note the original function needs to be updated to push to back
    // instead of front, as this generates data in the wrong order
    fn generate_dummy_usage_tracker_temp() -> RCUsageTracker {
        let current_hour = get_current_hour().unwrap();
        RCUsageTracker {
            last_save_hour: current_hour,
            client_bandwidth: generate_bandwidth(current_hour),
            relay_bandwidth: generate_bandwidth(current_hour),
            exit_bandwidth: VecDeque::new(),
            payments: VecDeque::new(),
        }
    }
    #[cfg(test)]
    // generates dummy usage hour data randomly
    fn generate_bandwidth(starting_hour: u64) -> VecDeque<RCUsageHour> {
        use rand::{thread_rng, Rng};
        // 8760 is the max number of saved usage entries(1 year)
        let num_to_generate: u16 = thread_rng().gen_range(50..8760);
        let mut output = VecDeque::new();
        for i in 0..num_to_generate {
            output.push_front(RCUsageHour {
                index: starting_hour - i as u64,
                up: rand::random(),
                down: rand::random(),
                price: rand::random(),
            });
        }
        output
    }
}
