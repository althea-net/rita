use actix_web::http::StatusCode;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse};
use althea_types::SystemChain;
use failure::Error;
use settings::payment::PaymentSettings;
use settings::payment::ETH_FEE_MULTIPLIER;
use settings::payment::ETH_MIN_GAS;
use settings::payment::XDAI_FEE_MULTIPLIER;
use settings::payment::XDAI_MIN_GAS;

/// Changes the full node configuration value between test/prod and other networks
pub fn set_system_blockchain_endpoint(path: Path<String>) -> Result<HttpResponse, Error> {
    info!("Blockchain change endpoint hit!");
    let id: Result<SystemChain, ()> = path.into_inner().parse();
    if id.is_err() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json(format!("Could not parse {:?} into a SystemChain enum!", id)));
    }
    let id = id.unwrap();

    let mut rita_client = settings::get_rita_client();
    let mut payment = rita_client.payment;
    set_system_blockchain(id, &mut payment);
    rita_client.payment = payment;
    settings::set_rita_client(rita_client);

    settings::write_config()?;

    Ok(HttpResponse::Ok().json(()))
}

pub fn get_system_blockchain(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/blockchain/ GET hit");

    Ok(HttpResponse::Ok().json(settings::get_rita_client().payment.system_chain))
}

pub fn set_system_blockchain(id: SystemChain, payment: &mut PaymentSettings) {
    match id {
        SystemChain::Ethereum => {
            payment.node_list = vec![
                "https://eth.althea.org:443".to_string(),
                "https://mainnet.infura.io/v3/6b080f02d7004a8394444cdf232a7081".to_string(),
            ];
            payment.net_version = Some(1);
            payment.system_chain = SystemChain::Ethereum;
            payment.withdraw_chain = SystemChain::Ethereum;
            // reset balance so that things take effect immediatley in the UI
            payment.balance = 0u32.into();
            payment.dynamic_fee_multiplier = ETH_FEE_MULTIPLIER;
            payment.min_gas = ETH_MIN_GAS;
        }
        SystemChain::Xdai => {
            payment.node_list = vec!["https://dai.althea.org/".to_string()];
            payment.net_version = Some(100);
            payment.system_chain = SystemChain::Xdai;
            payment.withdraw_chain = SystemChain::Xdai;
            // reset balance so that things take effect immediatley in the UI
            payment.balance = 0u32.into();
            payment.dynamic_fee_multiplier = XDAI_FEE_MULTIPLIER;
            payment.min_gas = XDAI_MIN_GAS;
        }
        SystemChain::Rinkeby => {
            payment.node_list =
                vec!["https://rinkeby.infura.io/v3/174d2ebf288a452fab8a8f90eab57be7".to_string()];
            payment.net_version = Some(4);
            payment.system_chain = SystemChain::Rinkeby;
            payment.withdraw_chain = SystemChain::Rinkeby;
            // reset balance so that things take effect immediatley in the UI
            payment.balance = 0u32.into();
            payment.dynamic_fee_multiplier = ETH_FEE_MULTIPLIER;
            payment.min_gas = ETH_MIN_GAS;
        }
    }
}
