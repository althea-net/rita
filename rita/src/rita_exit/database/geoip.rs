use crate::rita_common::utils::ip_increment::is_unicast_link_local;
use crate::KI;
use crate::SETTING;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::start_connection;
use failure::Error;
use futures01::future;
use futures01::future::Future;
use ipnetwork::IpNetwork;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

lazy_static! {
    static ref GEOIP_CACHE: Arc<RwLock<HashMap<IpAddr, String>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// gets the gateway ip for a given mesh IP
pub fn get_gateway_ip_single(mesh_ip: IpAddr) -> Box<dyn Future<Item = IpAddr, Error = Error>> {
    let babel_port = SETTING.get_network().babel_port;

    Box::new(
        open_babel_stream(babel_port)
            .from_err()
            .and_then(move |stream| {
                start_connection(stream).and_then(move |stream| {
                    parse_routes(stream).and_then(move |routes| {
                        let mut route_to_des = None;
                        for route in routes.1.iter() {
                            // Only ip6
                            if let IpNetwork::V6(ref ip) = route.prefix {
                                // Only host addresses and installed routes
                                if ip.prefix() == 128
                                    && route.installed
                                    && IpAddr::V6(ip.ip()) == mesh_ip
                                {
                                    route_to_des = Some(route.clone());
                                }
                            }
                        }

                        match route_to_des {
                            Some(route) => Ok(KI.get_wg_remote_ip(&route.iface)?),
                            None => bail!("No route found for mesh ip: {:?}", mesh_ip),
                        }
                    })
                })
            }),
    )
}

#[derive(Debug, Clone, Copy)]
pub struct IpPair {
    pub mesh_ip: IpAddr,
    pub gateway_ip: IpAddr,
}

/// gets the gateway ip for a given set of mesh IPs, inactive addresses will simply
/// not appear in the result vec
pub fn get_gateway_ip_bulk(
    mesh_ip_list: Vec<IpAddr>,
) -> Box<dyn Future<Item = Vec<IpPair>, Error = Error>> {
    let babel_port = SETTING.get_network().babel_port;
    trace!("getting gateway ip bulk");

    Box::new(open_babel_stream(babel_port).from_err().and_then(|stream| {
        start_connection(stream).and_then(|stream| {
            parse_routes(stream).and_then(|routes| {
                trace!("done talking to babel for gateway ip bulk");
                let mut remote_ip_cache: HashMap<String, IpAddr> = HashMap::new();
                let mut results = Vec::new();
                for mesh_ip in mesh_ip_list {
                    for route in routes.1.iter() {
                        // Only ip6
                        if let IpNetwork::V6(ref ip) = route.prefix {
                            // Only host addresses and installed routes
                            if ip.prefix() == 128
                                && route.installed
                                && IpAddr::V6(ip.ip()) == mesh_ip
                            {
                                // check if we've already looked up this interface this round, since gateways
                                // have many clients this will often be the case
                                if let Some(remote_ip) = remote_ip_cache.get(&route.iface) {
                                    results.push(IpPair {
                                        mesh_ip,
                                        gateway_ip: *remote_ip,
                                    });
                                } else {
                                    match KI.get_wg_remote_ip(&route.iface) {
                                        Ok(remote_ip) => {
                                            remote_ip_cache.insert(route.iface.clone(), remote_ip);
                                            results.push(IpPair {
                                                mesh_ip,
                                                gateway_ip: remote_ip,
                                            })
                                        }
                                        Err(e) => error!("Failure looking up remote ip {:?}", e),
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(results)
            })
        })
    }))
}

#[derive(Deserialize, Debug)]
struct GeoIpRet {
    country: CountryDetails,
}

#[derive(Deserialize, Debug)]
struct CountryDetails {
    iso_code: String,
}

pub fn get_country_async(ip: IpAddr) -> impl Future<Item = String, Error = Error> {
    match get_country(ip) {
        Ok(res) => future::ok(res),
        Err(e) => future::err(e),
    }
}

/// get ISO country code from ip, consults a in memory cache
pub fn get_country(ip: IpAddr) -> Result<String, Error> {
    trace!("get GeoIP country for {}", ip.to_string());

    // if allowed countries is not configured we don't care and will insert
    // empty stings into the DB.
    if SETTING.get_allowed_countries().is_empty() {
        return Ok(String::new());
    }

    // in this case we have a gateway directly attached to the exit, so our
    // peer address for them will be an fe80 linklocal ip address. When we
    // detect this we go ahead and assign the user one of our allowed countries
    // and move on. In the common case where we have only one allowed country
    // this will produce the correct result. We can affirm this will never panic
    // because we just checked that allowed countries contains at least one value
    // above
    if let IpAddr::V6(val) = ip {
        if is_unicast_link_local(&val) {
            return Ok(SETTING
                .get_allowed_countries()
                .iter()
                .next()
                .unwrap()
                .clone());
        }
    }

    // on the other hand if there is a configured list of allowed countries
    // but no configured api details, we panic
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

    // we have to turn this option into a string in order to avoid
    // the borrow checker trying to keep this lock open for a long period
    let cache_result = GEOIP_CACHE
        .read()
        .unwrap()
        .get(&ip)
        .map(|val| val.to_string());

    match cache_result {
        Some(code) => Ok(code),
        None => {
            let geo_ip_url = format!("https://geoip.maxmind.com/geoip/v2.1/country/{}", ip);
            info!(
                "making GeoIP request to {} for {}",
                geo_ip_url,
                ip.to_string()
            );
            let client = reqwest::blocking::Client::new();
            if let Ok(res) = client
                .get(&geo_ip_url)
                .basic_auth(api_user, Some(api_key))
                .timeout(Duration::from_secs(1))
                .send()
            {
                trace!("Got geoip result {:?}", res);
                if let Ok(res) = res.json() {
                    let value: GeoIpRet = res;
                    let code = value.country.iso_code;
                    trace!("Adding GeoIP value {:?} to cache", code);
                    GEOIP_CACHE.write().unwrap().insert(ip, code.clone());
                    trace!("Added to cache, returning");
                    Ok(code)
                } else {
                    Err(format_err!("Failed to deserialize geoip response"))
                }
            } else {
                Err(format_err!("request failed"))
            }
        }
    }
}

/// Returns true or false if an ip is confirmed to be inside or outside the region and error
/// if an api error is encountered trying to figure that out.
pub fn verify_ip(request_ip: IpAddr) -> impl Future<Item = bool, Error = Error> {
    match verify_ip_sync(request_ip) {
        Ok(item) => future::ok(item),
        Err(e) => future::err(e),
    }
}

/// Returns true or false if an ip is confirmed to be inside or outside the region and error
/// if an api error is encountered trying to figure that out.
pub fn verify_ip_sync(request_ip: IpAddr) -> Result<bool, Error> {
    // in this case we have a gateway directly attached to the exit, so our
    // peer address for them will be an fe80 linklocal ip address. When we
    // detect this we know that they are in the allowed countries list because
    // we assume the exit itself is in one of it's allowed countries.
    if let IpAddr::V6(val) = request_ip {
        if is_unicast_link_local(&val) {
            return Ok(true);
        }
    }

    if SETTING.get_allowed_countries().is_empty() {
        Ok(true)
    } else {
        let country = get_country(request_ip)?;
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
    get_country("8.8.8.8".parse().unwrap()).unwrap();
}
