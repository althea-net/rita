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

#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
pub enum ReleaseStatus {
    ReleaseCandidate,
    PreRelease,
    GeneralAvailability,
}

impl FromStr for ReleaseStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<ReleaseStatus, ()> {
        match s {
            "ReleaseCandidate" => Ok(ReleaseStatus::ReleaseCandidate),
            "PreRelease" => Ok(ReleaseStatus::PreRelease),
            "GeneralAvailability" => Ok(ReleaseStatus::GeneralAvailability),
            _ => Err(()),
        }
    }
}

pub fn get_release_feed(_req: HttpRequest) -> Result<HttpResponse, Error> {
    if !KI.is_openwrt() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST));
    }

    let lines = get_lines(CUSTOMFEEDS)?;
    for line in lines.iter() {
        if line.contains(&"/rc/".to_string()) && line.contains(&FEED_NAME.to_string()) {
            return Ok(HttpResponse::Ok().json(ReleaseStatus::ReleaseCandidate));
        } else if line.contains(&"/pr/".to_string()) && line.contains(&FEED_NAME.to_string()) {
            return Ok(HttpResponse::Ok().json(ReleaseStatus::PreRelease));
        }
    }
    Ok(HttpResponse::Ok().json(ReleaseStatus::GeneralAvailability))
}

pub fn set_release_feed(path: Path<String>) -> Result<HttpResponse, Error> {
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
            };
            *line = src_line;
        }
    }
    write_out(CUSTOMFEEDS, lines)?;

    Ok(HttpResponse::Ok().json(()))
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
