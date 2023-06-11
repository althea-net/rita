use actix_web_async::http::StatusCode;
use actix_web_async::web::Path;
use actix_web_async::{HttpRequest, HttpResponse};
use althea_types::SystemChain;
use rita_common::blockchain_oracle::{set_oracle_balance, set_oracle_net_version};
use settings::payment::PaymentSettings;

/// Changes the full node configuration value between test/prod and other networks
pub async fn set_system_blockchain_endpoint(path: Path<String>) -> HttpResponse {
    info!("Blockchain change endpoint hit!");
    let id: Result<SystemChain, ()> = path.into_inner().parse();
    if id.is_err() {
        return HttpResponse::build(StatusCode::BAD_REQUEST)
            .json(format!("Could not parse {id:?} into a SystemChain enum!"));
    }
    let id = id.unwrap();

    let mut rita_client = settings::get_rita_client();
    let mut payment = rita_client.payment;
    set_system_blockchain(id, &mut payment);
    rita_client.payment = payment;
    settings::set_rita_client(rita_client);

    if let Err(e) = settings::write_config() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("Error while writing config: {e:?}"));
    }

    HttpResponse::Ok().json(())
}

pub async fn get_system_blockchain(_req: HttpRequest) -> HttpResponse {
    debug!("/blockchain/ GET hit");

    HttpResponse::Ok().json(settings::get_rita_client().payment.system_chain)
}

pub fn set_system_blockchain(id: SystemChain, payment: &mut PaymentSettings) {
    match id {
        SystemChain::Ethereum => {
            payment.eth_node_list = vec![
                "https://eth.althea.org:443".to_string(),
                "https://mainnet.infura.io/v3/6b080f02d7004a8394444cdf232a7081".to_string(),
            ];
            set_oracle_net_version(1);
            payment.system_chain = SystemChain::Ethereum;
            payment.withdraw_chain = SystemChain::Ethereum;
            // reset balance so that things take effect immediatley in the UI
            set_oracle_balance(Some(0u32.into()));
        }
        SystemChain::Xdai => {
            payment.eth_node_list = vec!["https://dai.althea.org/".to_string()];
            set_oracle_net_version(100);
            payment.system_chain = SystemChain::Xdai;
            payment.withdraw_chain = SystemChain::Xdai;
            // reset balance so that things take effect immediatley in the UI
            set_oracle_balance(Some(0u32.into()));
        }
        SystemChain::Rinkeby => {
            payment.eth_node_list =
                vec!["https://rinkeby.infura.io/v3/174d2ebf288a452fab8a8f90eab57be7".to_string()];
            set_oracle_net_version(4);
            payment.system_chain = SystemChain::Rinkeby;
            payment.withdraw_chain = SystemChain::Rinkeby;
            // reset balance so that things take effect immediatley in the UI
            set_oracle_balance(Some(0u32.into()));
        }
        SystemChain::Althea => {
            todo!();
        }
    }
}
