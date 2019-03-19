use crate::rita_common::tunnel_manager::make_babel_stream;
use crate::KI;
use crate::SETTING;
use babel_monitor::{Babel, Route};
use failure::Error;
use ipnetwork::IpNetwork;
use reqwest;
use settings::exit::RitaExitSettings;
use std::collections::HashMap;
use std::net::IpAddr;

/// gets the gateway ip for a given mesh IP
pub fn get_gateway_ip_single(mesh_ip: IpAddr) -> Result<IpAddr, Error> {
    let mut babel = Babel::new(make_babel_stream()?);
    babel.start_connection()?;
    let routes = babel.parse_routes()?;

    let mut route_to_des: Option<Route> = None;

    for route in routes.iter() {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed && IpAddr::V6(ip.ip()) == mesh_ip {
                route_to_des = Some(route.clone());
            }
        }
    }

    match route_to_des {
        Some(route) => Ok(KI.get_wg_remote_ip(&route.iface)?),
        None => bail!("No route found for mesh ip: {:?}", mesh_ip),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IpPair {
    pub mesh_ip: IpAddr,
    pub gateway_ip: IpAddr,
}

/// gets the gateway ip for a given set of mesh IPs, inactive addresses will simply
/// not appear in the result vec
pub fn get_gateway_ip_bulk(mesh_ip_list: Vec<IpAddr>) -> Result<Vec<IpPair>, Error> {
    let mut babel = Babel::new(make_babel_stream()?);
    babel.start_connection()?;
    let routes = babel.parse_routes()?;
    let mut results = Vec::new();

    for mesh_ip in mesh_ip_list {
        for route in routes.iter() {
            // Only ip6
            if let IpNetwork::V6(ref ip) = route.prefix {
                // Only host addresses and installed routes
                if ip.prefix() == 128 && route.installed && IpAddr::V6(ip.ip()) == mesh_ip {
                    match KI.get_wg_remote_ip(&route.iface) {
                        Ok(remote_ip) => results.push(IpPair {
                            mesh_ip: mesh_ip,
                            gateway_ip: remote_ip,
                        }),
                        Err(e) => error!("Failure looking up remote ip {:?}", e),
                    }
                }
            }
        }
    }

    Ok(results)
}

#[derive(Deserialize, Debug)]
struct GeoIPRet {
    country: CountryDetails,
}

#[derive(Deserialize, Debug)]
struct CountryDetails {
    iso_code: String,
}

/// get ISO country code from ip, consults a in memory cache
pub fn get_country(ip: &IpAddr, cache: &mut HashMap<IpAddr, String>) -> Result<String, Error> {
    info!("get GeoIP country for {}", ip.to_string());
    let client = reqwest::Client::new();
    let api_user = SETTING
        .get_exit_network()
        .geoip_api_user
        .clone()
        .expect("No api key configured!");
    let api_key = SETTING
        .get_exit_network()
        .geoip_api_key
        .clone()
        .expect("No api key configured!");

    match cache.get(ip) {
        Some(code) => Ok(code.clone()),
        None => {
            let geo_ip_url = format!("https://geoip.maxmind.com/geoip/v2.1/country/{}", ip);
            info!(
                "making GeoIP request to {} for {}",
                geo_ip_url,
                ip.to_string()
            );

            let res: GeoIPRet = match client
                .get(&geo_ip_url)
                .basic_auth(api_user, Some(api_key))
                .send()
            {
                Ok(mut r) => match r.json() {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to Jsonize GeoIP response {:?}", e);
                        bail!("Failed to jsonize GeoIP response {:?}", e)
                    }
                },
                Err(e) => {
                    warn!("Get request for GeoIP failed! {:?}", e);
                    bail!("Get request for GeoIP failed {:?}", e)
                }
            };
            info!("Got {:?} from GeoIP request", res);
            cache.insert(*ip, res.country.iso_code.clone());

            Ok(res.country.iso_code)
        }
    }
}

/// Returns true or false if an ip is confirmed to be inside or outside the region and error
/// if an api error is encountered trying to figure that out.
pub fn verify_ip(request_ip: &IpAddr, cache: &mut HashMap<IpAddr, String>) -> Result<bool, Error> {
    if SETTING.get_allowed_countries().is_empty() {
        Ok(true)
    } else {
        let country = get_country(request_ip, cache)?;

        if !SETTING.get_allowed_countries().is_empty()
            && !SETTING.get_allowed_countries().contains(&country)
        {
            return Ok(false);
        }

        Ok(true)
    }
}

#[test]
#[ignore]
fn test_get_country() {
    get_country(&"8.8.8.8".parse().unwrap(), &mut HashMap::new()).unwrap();
}
