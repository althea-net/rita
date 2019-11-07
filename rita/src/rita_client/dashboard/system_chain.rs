use crate::ARGS;
use crate::SETTING;
use ::actix_web::http::StatusCode;
use ::actix_web::Path;
use ::actix_web::{HttpRequest, HttpResponse};
use althea_types::SystemChain;
use failure::Error;
use settings::FileWrite;
use settings::RitaCommonSettings;

/// Changes the full node configuration value between test/prod and other networks
pub fn set_system_blockchain(path: Path<String>) -> Result<HttpResponse, Error> {
    info!("Blockchain change endpoint hit!");
    let id: Result<SystemChain, ()> = path.into_inner().parse();
    if id.is_err() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json(format!("Could not parse {:?} into a SystemChain enum!", id)));
    }
    let id = id.unwrap();

    let oracle_url;
    let mut payment = SETTING.get_payment_mut();
    match id {
        SystemChain::Ethereum => {
            payment.node_list = vec![
                "https://eth.althea.org:443".to_string(),
                "https://mainnet.infura.io/v3/6b080f02d7004a8394444cdf232a7081".to_string(),
            ];
            payment.net_version = Some(1);
            payment.system_chain = SystemChain::Ethereum;
            payment.withdraw_chain = SystemChain::Ethereum;
            oracle_url = "https://updates.altheamesh.com/prices".to_string();
            // reset balance so that things take effect immediatley in the UI
            payment.balance = 0u32.into();
        }
        SystemChain::Xdai => {
            payment.node_list = vec!["https://dai.althea.org/".to_string()];
            payment.net_version = Some(100);
            payment.system_chain = SystemChain::Xdai;
            payment.withdraw_chain = SystemChain::Xdai;
            oracle_url = "https://updates.altheamesh.com/xdaiprices".to_string();
            // reset balance so that things take effect immediatley in the UI
            payment.balance = 0u32.into();
        }
        SystemChain::Rinkeby => {
            payment.node_list =
                vec!["https://rinkeby.infura.io/v3/174d2ebf288a452fab8a8f90eab57be7".to_string()];
            payment.net_version = Some(4);
            payment.system_chain = SystemChain::Rinkeby;
            payment.withdraw_chain = SystemChain::Rinkeby;
            oracle_url = "https://updates.altheamesh.com/testprices".to_string();
            // reset balance so that things take effect immediatley in the UI
            payment.balance = 0u32.into();
        }
    }
    drop(payment);

    let mut dao = SETTING.get_dao_mut();
    let have_dao = !dao.dao_addresses.is_empty();
    // if there is no dao configured use the currency oracle value
    if !have_dao {
        dao.oracle_url = Some(oracle_url);
    }
    drop(dao);

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }

    Ok(HttpResponse::Ok().json(()))
}

pub fn get_system_blockchain(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/blockchain/ GET hit");

    Ok(HttpResponse::Ok().json(SETTING.get_payment().system_chain))
}
