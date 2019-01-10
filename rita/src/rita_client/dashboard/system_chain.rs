use super::*;

/// Changes the full node configuration value between test/prod and other networks
pub fn set_system_blockchain(
    path: Path<String>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    info!("Blockchain change endpoint hit!");
    let id = path.into_inner();

    if id.to_lowercase() == "eth" {
        SETTING.get_payment_mut().node_list = vec!["https://eth.althea.org:443".to_string()];
        SETTING.get_dao_mut().node_list = vec!["https://eth.althea.org:443".to_string()];
    } else if id.to_ascii_lowercase() == "rinkeby" {
        SETTING.get_payment_mut().node_list = vec!["http://rinkeby.althea.org:8545".to_string()];
        SETTING.get_dao_mut().node_list = vec!["http://rinkeby.althea.org:8545".to_string()];
    } else {
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(format!("No known chain by the identifier {}", id)),
        ));
    }

    Box::new(future::ok(HttpResponse::Ok().json(())))
}
