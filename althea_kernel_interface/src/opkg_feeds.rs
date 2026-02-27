use crate::file_io::get_lines;
use crate::file_io::write_out;
use crate::KernelInterfaceError as Error;

pub static CUSTOMFEEDS: &str = "/etc/opkg/customfeeds.conf";

pub fn get_release_feed(customfeeds: &str, feed_name: &str) -> Result<String, Error> {
    let lines = get_lines(customfeeds)?;
    for line in lines.iter() {
        // there may be other custom feeds configured, if it's not althea skip it
        if !line.contains(feed_name) {
            continue;
        }
        return Ok(line.to_string());
    }
    Err(Error::NoAltheaReleaseFeedFound)
}

pub fn set_release_feed(
    val: &str,
    feed_name: &str,
    old_feed_name: Option<&str>,
    customfeeds: &str,
) -> Result<(), Error> {
    let mut lines = get_lines(customfeeds)?;
    // Search for old_feed_name if provided (for transitions), otherwise search for feed_name
    let search_name = old_feed_name.unwrap_or(feed_name);

    let mut found = false;
    for line in lines.iter_mut() {
        if line.contains(search_name) {
            let src_line = val.to_string();
            // Use the new feed_name in the output
            let mut owned_string = format!("src/gz {} ", feed_name);
            owned_string.push_str(&src_line);
            *line = owned_string;
            found = true;
            break; // Only update the first match
        }
    }

    // If no existing feed was found, add a new one
    if !found {
        let new_line = format!("src/gz {} {}", feed_name, val);
        lines.push(new_line);
    }

    write_out(customfeeds, lines)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to ensure tests that modify the same file don't run in parallel
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn setup_test_file(path: &str) {
        use crate::file_io::write_out;
        let lines = vec!["src/gz althea www.dummyurl.com".to_string()];
        let _res = write_out(path, lines);
    }

    #[test]
    fn test_reading_feed() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let path = "../settings/customfeed.conf";
        setup_test_file(path);

        assert_eq!(
            "src/gz althea www.dummyurl.com".to_string(),
            get_release_feed(path, "althea").unwrap()
        );
    }

    #[test]
    fn test_updating_existing_feed() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let path = "../settings/customfeed.conf";
        setup_test_file(path);

        // Update existing "althea" feed with new URL
        let _res = set_release_feed("www.newurl.com", "althea", None, path);
        assert_eq!(
            "src/gz althea www.newurl.com".to_string(),
            get_release_feed(path, "althea").unwrap()
        );

        // Cleanup: restore original
        setup_test_file(path);
    }

    #[test]
    fn test_transitioning_feed_name() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let path = "../settings/customfeed.conf";
        setup_test_file(path);

        // Transition from "althea" to "hawk" with new URL
        let _res = set_release_feed("www.hawkurl.com", "hawk", Some("althea"), path);

        // Old feed name should no longer exist
        assert!(get_release_feed(path, "althea").is_err());

        // New feed name should exist with new URL
        assert_eq!(
            "src/gz hawk www.hawkurl.com".to_string(),
            get_release_feed(path, "hawk").unwrap()
        );

        // Cleanup: restore original
        setup_test_file(path);
    }

    #[test]
    fn test_adding_new_feed() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let path = "../settings/customfeed.conf";
        setup_test_file(path);

        // Add a completely new feed that doesn't exist
        let _res = set_release_feed("www.newfeedurl.com", "newfeed", None, path);

        // New feed should exist
        assert_eq!(
            "src/gz newfeed www.newfeedurl.com".to_string(),
            get_release_feed(path, "newfeed").unwrap()
        );

        // Original feed should still exist
        assert_eq!(
            "src/gz althea www.dummyurl.com".to_string(),
            get_release_feed(path, "althea").unwrap()
        );

        // Cleanup: restore original (remove the new feed)
        setup_test_file(path);
    }
}
