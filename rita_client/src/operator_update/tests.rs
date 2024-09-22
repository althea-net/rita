#[cfg(test)]
mod test {
    use crate::operator_update::contains_forbidden_key;
    use crate::operator_update::prepare_usage_data_for_upload;
    use crate::operator_update::update_authorized_keys;
    use serde_json::json;
    use serde_json::Value;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Write};
    use std::{fs, io::Error, path::Path};

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

        update_authorized_keys(added_keys.clone(), removed_keys, key_file).unwrap();
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

        update_authorized_keys(added_keys.clone(), removed_keys, key_file).unwrap();
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

        update_authorized_keys(added_keys, removed_keys, key_file).unwrap();
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
        update_authorized_keys(added_keys, removed_keys.clone(), key_file).unwrap();

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
        update_authorized_keys(added_keys, removed_keys, key_file).unwrap();
        assert!(Path::new(key_file).exists());
    }
    #[test]
    fn test_prepare_usage_data_for_upload() {
        assert_eq!(prepare_usage_data_for_upload(None).unwrap(), None);
    }
}
