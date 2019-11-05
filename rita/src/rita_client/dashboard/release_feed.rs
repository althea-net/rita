use crate::rita_client::dashboard::get_lines;
use crate::rita_client::dashboard::write_out;
use crate::KI;
use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Path;
use failure::Error;
use regex::Regex;
use std::str::FromStr;

static CUSTOMFEEDS: &str = "/etc/opkg/customfeeds.conf";
static FEED_NAME: &str = "openwrt_althea";

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ReleaseStatus {
    Custom(String),
    ReleaseCandidate,
    PreRelease,
    GeneralAvailability,
}

impl FromStr for ReleaseStatus {
    type Err = Error;
    fn from_str(s: &str) -> Result<ReleaseStatus, Error> {
        match s {
            "rc" => Ok(ReleaseStatus::ReleaseCandidate),
            "pr" => Ok(ReleaseStatus::PreRelease),
            "ReleaseCandidate" => Ok(ReleaseStatus::ReleaseCandidate),
            "PreRelease" => Ok(ReleaseStatus::PreRelease),
            "GeneralAvailability" => Ok(ReleaseStatus::GeneralAvailability),
            _ => {
                if !s.is_empty() {
                    Ok(ReleaseStatus::Custom(s.to_string()))
                } else {
                    Err(format_err!(
                        "Empty string can't possibly be a valid release!"
                    ))
                }
            }
        }
    }
}

pub fn get_release_feed_http(_req: HttpRequest) -> Result<HttpResponse, Error> {
    if !KI.is_openwrt() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST));
    }
    let res = get_release_feed()?;
    Ok(HttpResponse::Ok().json(res))
}

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

pub fn set_release_feed_http(path: Path<String>) -> Result<HttpResponse, Error> {
    if !KI.is_openwrt() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST));
    }

    let val = path.into_inner().parse();
    if val.is_err() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json(format!(
                "Could not parse {:?} into a ReleaseStatus enum!",
                val
            )));
    }
    let val = val.unwrap();
    if let Err(e) = set_release_feed(val) {
        return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
            .into_builder()
            .json(format!("Failed to write new release feed with {:?}", e)));
    }

    Ok(HttpResponse::Ok().json(()))
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
