use super::*;

use althea_types::SystemChain;

/// Changes the full node configuration value between test/prod and other networks
pub fn set_system_blockchain(
    path: Path<String>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    info!("Blockchain change endpoint hit!");
    let id: Result<SystemChain, ()> = path.into_inner().parse();
    if id.is_err() {
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(format!("Could not parse {:?} into a SystemChain enum!", id)),
        ));
    }
    let id = id.unwrap();

    let mut payment = SETTING.get_payment_mut();
    if id == SystemChain::Ethereum {
        payment.node_list = vec![
            "https://eth.althea.org:443".to_string(),
            "https://mainnet.infura.io/v3/6b080f02d7004a8394444cdf232a7081".to_string(),
        ];
        payment.net_version = Some(1);
        payment.system_chain = SystemChain::Ethereum;
        payment.price_oracle_url = "https://updates.altheamesh.com/prices".to_string();
    } else if id == SystemChain::Xdai {
        payment.node_list = vec!["https://dai.althea.org/".to_string()];
        payment.net_version = Some(100);
        payment.system_chain = SystemChain::Xdai;
        payment.price_oracle_url = "https://updates.altheamesh.com/xdaiprices".to_string();
    } else if id == SystemChain::Rinkeby {
        payment.node_list =
            vec!["https://rinkeby.infura.io/v3/174d2ebf288a452fab8a8f90eab57be7".to_string()];
        payment.net_version = Some(4);
        payment.system_chain = SystemChain::Rinkeby;
        payment.price_oracle_url = "https://updates.altheamesh.com/prices".to_string();
    } else {
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(format!("No known chain by the identifier {:?}", id)),
        ));
    }
    drop(payment);

    let mut dao = SETTING.get_dao_mut();
    if id == SystemChain::Ethereum {
        dao.node_list = vec![
            "https://eth.althea.org:443".to_string(),
            "https://mainnet.infura.io/v3/6b080f02d7004a8394444cdf232a7081".to_string(),
        ];
    } else if id == SystemChain::Xdai {
        dao.node_list = vec!["https://dai.althea.org/".to_string()];
    } else if id == SystemChain::Rinkeby {
        dao.node_list =
            vec!["https://rinkeby.infura.io/v3/174d2ebf288a452fab8a8f90eab57be7".to_string()];
    } else {
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(format!("No known chain by the identifier {:?}", id)),
        ));
    }
    drop(dao);

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Box::new(future::err(e));
    }

    Box::new(future::ok(HttpResponse::Ok().json(())))
}

pub fn get_system_blockchain(
    _req: HttpRequest,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    debug!("/blockchain/ GET hit");

    Box::new(future::ok(
        HttpResponse::Ok().json(SETTING.get_payment().system_chain),
    ))
}
