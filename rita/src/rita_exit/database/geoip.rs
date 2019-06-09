use crate::GEOIP_CACHE;
use crate::KI;
use crate::SETTING;
use actix_web::client as actix_client;
use actix_web::HttpMessage;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::start_connection;
use failure::Error;
use future::Either;
use futures::future;
use futures::future::Future;
use ipnetwork::IpNetwork;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::net::IpAddr;

/// gets the gateway ip for a given mesh IP
pub fn get_gateway_ip_single(mesh_ip: IpAddr) -> Box<Future<Item = IpAddr, Error = Error>> {
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
) -> Box<Future<Item = Vec<IpPair>, Error = Error>> {
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
struct GeoIPRet {
    country: CountryDetails,
}

#[derive(Deserialize, Debug)]
struct CountryDetails {
    iso_code: String,
}

/// get ISO country code from ip, consults a in memory cache
pub fn get_country(ip: IpAddr) -> impl Future<Item = String, Error = Error> {
    trace!("get GeoIP country for {}", ip.to_string());

    // if allowed countries is not configured we don't care and will insert
    // empty stings into the DB.
    if SETTING.get_allowed_countries().is_empty() {
        return Either::A(future::ok(String::new()));
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

    match GEOIP_CACHE.read().unwrap().get(&ip) {
        Some(code) => Either::A(future::ok(code.clone())),
        None => {
            let geo_ip_url = format!("https://geoip.maxmind.com/geoip/v2.1/country/{}", ip);
            info!(
                "making GeoIP request to {} for {}",
                geo_ip_url,
                ip.to_string()
            );
            Either::B(
                actix_client::get(&geo_ip_url)
                    .basic_auth(api_user, Some(api_key))
                    .finish()
                    .unwrap()
                    .send()
                    .from_err()
                    .and_then(move |response| {
                        response.json().from_err().and_then(move |result| {
                            let value: GeoIPRet = result;
                            let code = value.country.iso_code;
                            GEOIP_CACHE.write().unwrap().insert(ip, code.clone());
                            Ok(code)
                        })
                    }),
            )
        }
    }
}

/// Returns true or false if an ip is confirmed to be inside or outside the region and error
/// if an api error is encountered trying to figure that out.
pub fn verify_ip(request_ip: IpAddr) -> impl Future<Item = bool, Error = Error> {
    if SETTING.get_allowed_countries().is_empty() {
        Either::A(future::ok(true))
    } else {
        Either::B(get_country(request_ip).and_then(|country| {
            if !SETTING.get_allowed_countries().is_empty()
                && !SETTING.get_allowed_countries().contains(&country)
            {
                return Ok(false);
            }

            Ok(true)
        }))
    }
}

#[test]
#[ignore]
fn test_get_country() {
    get_country("8.8.8.8".parse().unwrap()).wait().unwrap();
}
