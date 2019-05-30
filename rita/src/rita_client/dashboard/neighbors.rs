use crate::rita_common::dashboard::Dashboard;
use crate::rita_common::debt_keeper::{DebtKeeper, Dump, NodeDebtData};
use crate::rita_common::tunnel_manager::{GetNeighbors, Neighbor, TunnelManager};
use crate::SETTING;
use ::actix::{Handler, Message, ResponseFuture, SystemService};
use ::actix_web::AsyncResponder;
use ::actix_web::{HttpRequest, Json};
use althea_types::Identity;
use arrayvec::ArrayString;
use babel_monitor::get_route_via_neigh;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::start_connection;
use failure::Error;
use futures::Future;
use num256::{Int256, Uint256};
use settings::client::RitaClientSettings;
use settings::RitaCommonSettings;
use std::boxed::Box;
use std::collections::HashMap;

#[derive(Serialize)]
pub struct NodeInfo {
    pub nickname: String,
    pub ip: String,
    pub route_metric_to_exit: u16,
    pub total_payments: Uint256,
    pub debt: Int256,
    pub link_cost: u16,
    pub price_to_exit: u32,
}

pub struct GetNeighborInfo;

impl Message for GetNeighborInfo {
    type Result = Result<Vec<NodeInfo>, Error>;
}

/// Gets info about neighbors, including interested data about what their route
/// price is to the exit and how much we may owe them. The debt data is now legacy
/// since the /debts endpoint was introduced, and should be removed when it can be
/// coordinated with the frontend.
/// The routes info might also belong in /exits or a dedicated /routes endpoint
impl Handler<GetNeighborInfo> for Dashboard {
    type Result = ResponseFuture<Vec<NodeInfo>, Error>;

    fn handle(&mut self, _msg: GetNeighborInfo, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            DebtKeeper::from_registry()
                .send(Dump {})
                .from_err()
                .and_then(|debts| {
                    TunnelManager::from_registry()
                        .send(GetNeighbors {})
                        .from_err()
                        .and_then(|neighbors| {
                            let mut debts = debts.unwrap();
                            if neighbors.is_ok() {
                                let neighbors = neighbors.unwrap();
                                merge_debts_and_neighbors(neighbors, &mut debts);
                            }

                            let babel_port = SETTING.get_network().babel_port;

                            open_babel_stream(babel_port)
                                .from_err()
                                .and_then(move |stream| {
                                    start_connection(stream).then(move |stream| {
                                        let stream = stream.expect("Unexpected babel version!");
                                        parse_routes(stream).and_then(move |routes| {
                                            let route_table_sample = routes.1;

                                            let mut output = Vec::new();

                                            let exit_client = SETTING.get_exit_client();
                                            let current_exit = exit_client.get_current_exit();

                                            for (identity, debt_info) in debts.iter() {
                                                let nickname = match identity.nickname {
                                                    Some(val) => val,
                                                    None => {
                                                        ArrayString::<[u8; 32]>::from("No Nickname")
                                                            .unwrap()
                                                    }
                                                };

                                                if current_exit.is_some() {
                                                    let exit_ip = current_exit.unwrap().id.mesh_ip;
                                                    let maybe_route = get_route_via_neigh(
                                                        identity.mesh_ip,
                                                        exit_ip,
                                                        &route_table_sample,
                                                    );

                                                    // We have a peer that is an exit, so we can't find a route
                                                    // from them to our selected exit. Other errors can also get
                                                    // caught here
                                                    if maybe_route.is_err() {
                                                        output.push(nonviable_node_info(
                                                            nickname,
                                                            identity.mesh_ip.to_string(),
                                                        ));
                                                        continue;
                                                    }
                                                    // we check that this is safe above
                                                    let route = maybe_route.unwrap();

                                                    output.push(NodeInfo {
                                                        nickname: nickname.to_string(),
                                                        ip: serde_json::to_string(
                                                            &identity.mesh_ip,
                                                        )
                                                        .unwrap(),
                                                        route_metric_to_exit: route.metric,
                                                        total_payments: debt_info
                                                            .total_payment_received
                                                            .clone(),
                                                        debt: debt_info.debt.clone(),
                                                        link_cost: route.refmetric,
                                                        price_to_exit: route.price,
                                                    })
                                                } else {
                                                    output.push(NodeInfo {
                                                        nickname: nickname.to_string(),
                                                        ip: serde_json::to_string(
                                                            &identity.mesh_ip,
                                                        )
                                                        .unwrap(),
                                                        route_metric_to_exit: u16::max_value(),
                                                        total_payments: debt_info
                                                            .total_payment_received
                                                            .clone(),
                                                        debt: debt_info.debt.clone(),
                                                        link_cost: u16::max_value(),
                                                        price_to_exit: u32::max_value(),
                                                    })
                                                }
                                            }

                                            Ok(output)
                                        })
                                    })
                                })
                        })
                }),
        )
    }
}

pub fn get_neighbor_info(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<Vec<NodeInfo>>, Error = Error>> {
    debug!("Neighbors endpoint hit!");
    Dashboard::from_registry()
        .send(GetNeighborInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

/// Takes a list of neighbors and debts, if an entry
/// is found in the neighbors list that is not in the debts list
/// the debts list is extended to include it
fn merge_debts_and_neighbors(
    neighbors: Vec<Neighbor>,
    debts: &mut HashMap<Identity, NodeDebtData>,
) {
    for neighbor in neighbors {
        let id = neighbor.identity.global;
        debts.entry(id).or_insert_with(NodeDebtData::new);
    }
}

fn nonviable_node_info(nickname: ArrayString<[u8; 32]>, ip: String) -> NodeInfo {
    NodeInfo {
        nickname: nickname.to_string(),
        ip,
        total_payments: 0u32.into(),
        debt: 0.into(),
        link_cost: 0,
        price_to_exit: 0,
        route_metric_to_exit: u16::max_value(),
    }
}
