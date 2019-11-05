use crate::file_io::get_lines;
use crate::file_io::write_out;
use althea_types::ReleaseStatus;
use failure::Error;
use regex::Regex;

static CUSTOMFEEDS: &str = "/etc/opkg/customfeeds.conf";
static FEED_NAME: &str = "openwrt_althea";

pub fn get_release_feed() -> Result<ReleaseStatus, Error> {
    let lines = get_lines(CUSTOMFEEDS)?;
    for line in lines.iter() {
        // there may be other custom feeds configured, if it's not openwrt_althea skip it
        if !line.contains(&FEED_NAME.to_string()) {
            continue;
        }
        return get_feed(line);
    }
    Err(format_err!("No feed openwrt_althea found!"))
}

pub fn set_release_feed(val: ReleaseStatus) -> Result<(), Error> {
    let mut lines = get_lines(CUSTOMFEEDS)?;

    for line in lines.iter_mut() {
        if line.contains(&FEED_NAME.to_string()) {
            let arch = get_arch(line)?;
            let src_line = match val {
                ReleaseStatus::GeneralAvailability => format!(
                    "src/gz openwrt_althea https://updates.altheamesh.com/packages/{}/althea",
                    arch
                ),
                ReleaseStatus::PreRelease => format!(
                    "src/gz openwrt_althea https://updates.altheamesh.com/pr/packages/{}/althea",
                    arch
                ),
                ReleaseStatus::ReleaseCandidate => format!(
                    "src/gz openwrt_althea https://updates.altheamesh.com/rc/packages/{}/althea",
                    arch
                ),
                ReleaseStatus::Custom(ref s) => format!(
                    "src/gz openwrt_althea https://updates.altheamesh.com/{}/packages/{}/althea",
                    s, arch
                ),
            };
            *line = src_line;
        }
    }
    write_out(CUSTOMFEEDS, lines)?;
    Ok(())
}

fn get_arch(line: &str) -> Result<String, Error> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(/packages/([A-Za-z0-9\-_]+)/althea)")
            .expect("Unable to compile regular expression");
    }
    let cap = RE.captures(line).unwrap()[0].to_string();
    let arch = cap
        .replace("packages", "")
        .replace("althea", "")
        .replace("/", "");
    Ok(arch)
}

fn get_feed(line: &str) -> Result<ReleaseStatus, Error> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"/(([A-Za-z0-9\-_]+)/packages/)")
            .expect("Unable to compile regular expression");
    }
    if let Some(feed) = RE.captures(&line) {
        if let Some(val) = feed.get(0) {
            let a: Vec<&str> = val.as_str().split('/').collect();
            let feed = a[1];
            return Ok(feed.parse()?);
        }
    }
    Ok(ReleaseStatus::GeneralAvailability)
}

#[test]
fn test_feed_feed_rc() {
    let val = get_feed(
        "src/gz openwrt_althea https://updates.altheamesh.com/rc/packages/mipsel_24kc/althea",
    );
    assert_eq!(val.unwrap(), ReleaseStatus::ReleaseCandidate)
}

#[test]
fn test_feed_feed_ga() {
    let val = get_feed(
        "src/gz openwrt_althea https://updates.altheamesh.com/packages/mipsel_24kc/althea",
    );
    assert_eq!(val.unwrap(), ReleaseStatus::GeneralAvailability)
}

#[test]
fn test_feed_feed_pr() {
    let val = get_feed(
        "src/gz openwrt_althea https://updates.altheamesh.com/pr/packages/mipsel_24kc/althea",
    );
    assert_eq!(val.unwrap(), ReleaseStatus::PreRelease)
}

#[test]
fn test_feed_feed_custom() {
    let val = get_feed(
        "src/gz openwrt_althea https://updates.altheamesh.com/customVal/packages/mipsel_24kc/althea",
    );
    assert_eq!(val.unwrap(), ReleaseStatus::Custom("customVal".to_string()))
}

#[test]
fn test_regex_com() {
    let val = get_arch(
        "src/gz openwrt_althea https://updates.altheamesh.com/rc/packages/mipsel_24kc/althea",
    );
    assert_eq!(&val.unwrap(), "mipsel_24kc");
}

#[test]
fn test_regex_net() {
    let val =
        get_arch("src/gz openwrt_althea https://updates.althea.net/packages/mipsel_24kc/althea");
    assert_eq!(&val.unwrap(), "mipsel_24kc");
}
