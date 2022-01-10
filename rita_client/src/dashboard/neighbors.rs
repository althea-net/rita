use actix::SystemService;
use actix_web::AsyncResponder;
use actix_web::{HttpRequest, Json};
use althea_types::Identity;
use arrayvec::ArrayString;
use babel_monitor::{get_installed_route, get_route_via_neigh, Route as RouteLegacy};
use babel_monitor_legacy::open_babel_stream_legacy;
use babel_monitor_legacy::parse_routes_legacy;
use babel_monitor_legacy::start_connection_legacy;
use futures01::Future;
use num256::{Int256, Uint256};
use rita_common::debt_keeper::{dump, NodeDebtData};
use rita_common::network_monitor::{GetStats, IfaceStats, NetworkMonitor, Stats};
use rita_common::tunnel_manager::{GetNeighbors, Neighbor, TunnelManager};
use std::collections::HashMap;

use crate::RitaClientError;

#[derive(Serialize)]
pub struct NodeInfo {
    pub nickname: String,
    // TODO: Remove this once the dashboard no longer depends on it.
    pub ip: String,
    pub id: Identity,
    pub route_metric_to_exit: u16,
    pub route_metric: u16,
    pub total_payments: Uint256,
    pub debt: Int256,
    pub link_cost: u16,
    pub price_to_exit: u32,
    pub speed_limit: Option<usize>,
    pub stats: IfaceStats,
}

pub fn get_routes(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<Vec<RouteLegacy>>, Error = RitaClientError>> {
    let babel_port = settings::get_rita_client().network.babel_port;
    Box::new(
        open_babel_stream_legacy(babel_port)
            .from_err()
            .and_then(move |stream| {
                start_connection_legacy(stream).and_then(move |stream| {
                    parse_routes_legacy(stream)
                        .and_then(|(_stream, routes)| Ok(Json(routes)))
                        .responder()
                })
            }),
    )
}

/// Gets info about neighbors, including interested data about what their route
/// price is to the exit and how much we may owe them. The debt data is now legacy
/// since the /debts endpoint was introduced, and should be removed when it can be
/// coordinated with the frontend.
/// The routes info might also belong in /exits or a dedicated /routes endpoint
pub fn get_neighbor_info(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<Vec<NodeInfo>>, Error = RitaClientError>> {
    let debts = dump();
    Box::new(
        TunnelManager::from_registry()
            .send(GetNeighbors {})
            .from_err()
            .and_then(|neighbors| {
                let neighbors = neighbors.unwrap();

                let combined_list = merge_debts_and_neighbors(neighbors, debts);

                let babel_port = settings::get_rita_client().network.babel_port;

                open_babel_stream_legacy(babel_port)
                    .from_err()
                    .and_then(move |stream| {
                        start_connection_legacy(stream).and_then(move |stream| {
                            parse_routes_legacy(stream)
                                .and_then(|(_stream, routes)| {
                                    let route_table_sample = routes;

                                    NetworkMonitor::from_registry()
                                        .send(GetStats {})
                                        .from_err()
                                        .and_then(|stats| {
                                            let stats = stats.unwrap();
                                            let output = generate_neighbors_list(
                                                stats,
                                                route_table_sample,
                                                combined_list,
                                            );

                                            Ok(Json(output))
                                        })
                                })
                                .responder()
                        })
                    })
            }),
    )
}

/// generates a list of neighbors coorelated with the quality of the route to the exit they provide
fn generate_neighbors_list(
    stats: Stats,
    route_table_sample: Vec<RouteLegacy>,
    debts: HashMap<Identity, (NodeDebtData, Neighbor)>,
) -> Vec<NodeInfo> {
    let mut output = Vec::new();
    let rita_client = settings::get_rita_client();
    let exit_client = rita_client.exit_client;
    let current_exit = exit_client.get_current_exit();

    for (identity, (debt_info, neigh)) in debts.iter() {
        let nickname = match identity.nickname {
            Some(val) => val,
            None => ArrayString::<32>::from("No Nickname").unwrap(),
        };
        let maybe_route = get_installed_route(&identity.mesh_ip, &route_table_sample);
        if maybe_route.is_err() {
            output.push(nonviable_node_info(
                nickname,
                u16::max_value(),
                identity.mesh_ip.to_string(),
                *identity,
                neigh.speed_limit,
            ));
            continue;
        }
        let neigh_route = maybe_route.unwrap();

        let tup = (current_exit, stats.get(&neigh_route.iface));
        if let (Some(current_exit), Some(stats_entry)) = tup {
            if current_exit.selected_exit.selected_id.is_some() {
                let exit_ip = current_exit.selected_exit.selected_id.unwrap();
                let maybe_exit_route =
                    get_route_via_neigh(identity.mesh_ip, exit_ip, &route_table_sample);

                // We have a peer that is an exit, so we can't find a route
                // from them to our selected exit. Other errors can also get
                // caught here
                if maybe_exit_route.is_err() {
                    output.push(nonviable_node_info(
                        nickname,
                        neigh_route.metric,
                        identity.mesh_ip.to_string(),
                        *identity,
                        neigh.speed_limit,
                    ));
                    continue;
                }
                // we check that this is safe above
                let exit_route = maybe_exit_route.unwrap();

                output.push(NodeInfo {
                    nickname: nickname.to_string(),
                    ip: identity.mesh_ip.to_string(),
                    id: *identity,
                    route_metric_to_exit: exit_route.metric,
                    route_metric: neigh_route.metric,
                    speed_limit: neigh.speed_limit,
                    total_payments: debt_info.total_payment_received.clone(),
                    debt: debt_info.debt.clone(),
                    link_cost: exit_route.refmetric,
                    price_to_exit: exit_route.price,
                    stats: *stats_entry,
                })
            }
        } else {
            output.push(nonviable_node_info(
                nickname,
                neigh_route.metric,
                identity.mesh_ip.to_string(),
                *identity,
                neigh.speed_limit,
            ));
        }
    }
    output
}

/// Takes a list of neighbors and debts, if an entry
/// is found in the neighbors list that is not in the debts list
/// the debts list is extended to include it
fn merge_debts_and_neighbors(
    neighbors: Vec<Neighbor>,
    debts: HashMap<Identity, NodeDebtData>,
) -> HashMap<Identity, (NodeDebtData, Neighbor)> {
    let mut res = HashMap::new();
    for neighbor in neighbors.iter() {
        let id = neighbor.identity.global;
        if let Some(debts) = debts.get(&id) {
            let local_debts = (*debts).clone();
            let local_neighbor = (*neighbor).clone();
            res.insert(id, (local_debts, local_neighbor));
        }
    }
    res
}

fn nonviable_node_info(
    nickname: ArrayString<32>,
    neigh_metric: u16,
    ip: String,
    id: Identity,
    speed_limit: Option<usize>,
) -> NodeInfo {
    NodeInfo {
        nickname: nickname.to_string(),
        ip,
        id,
        total_payments: 0u32.into(),
        debt: 0.into(),
        link_cost: 0,
        price_to_exit: 0,
        route_metric_to_exit: u16::max_value(),
        route_metric: neigh_metric,
        speed_limit,
        stats: IfaceStats::default(),
    }
}
