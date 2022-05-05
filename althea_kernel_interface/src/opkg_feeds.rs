use crate::file_io::get_lines;
use crate::file_io::write_out;
use crate::KernelInterfaceError as Error;

pub static CUSTOMFEEDS: &str = "/etc/opkg/customfeeds.conf";
static FEED_NAME: &str = "althea";

pub fn get_release_feed(customfeeds: &str) -> Result<String, Error> {
    let lines = get_lines(customfeeds)?;
    for line in lines.iter() {
        // there may be other custom feeds configured, if it's not althea skip it
        if !line.contains(&FEED_NAME.to_string()) {
            continue;
        }
        return Ok(line.to_string());
    }
    Err(Error::NoAltheaReleaseFeedFound)
}

pub fn set_release_feed(val: &str, customfeeds: &str) -> Result<(), Error> {
    let mut lines = get_lines(customfeeds)?;

    for line in lines.iter_mut() {
        if line.contains(&FEED_NAME.to_string()) {
            let src_line = val.to_string();
            let mut owned_string = "src/gz althea ".to_string().to_owned();
            owned_string.push_str(&src_line);
            *line = owned_string;
        }
    }
    write_out(customfeeds, lines)?;
    Ok(())
}

#[test]
fn test_reading_feed() {
    let path = "../settings/customfeed.conf";
    assert_eq!(
        "src/gz althea www.dummyurl.com".to_string(),
        get_release_feed(path).unwrap()
    );
}

#[test]
fn test_writing_feed() {
    let path = "../settings/customfeed.conf";
    let _res = set_release_feed("www.dummyurl.com", path);
    assert_eq!(
        "src/gz althea www.dummyurl.com".to_string(),
        get_release_feed(path).unwrap()
    );
}
