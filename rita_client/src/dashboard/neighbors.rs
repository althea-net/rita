use crate::exit_manager::ExitManager;
use crate::RitaClientError;
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};
use althea_types::Identity;
use arrayvec::ArrayString;
use babel_monitor::parsing::get_installed_route;
use babel_monitor::parsing::get_route_via_neigh;
use babel_monitor::structs::Route;
use babel_monitor::{open_babel_stream, parse_routes};
use num256::{Int256, Uint256};
use rita_common::debt_keeper::{dump, NodeDebtData};
use rita_common::network_monitor::{get_stats, IfaceStats, Stats};
use rita_common::tunnel_manager::{tm_get_neighbors, Neighbor};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

const BABEL_TIMEOUT: Duration = Duration::from_secs(5);

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

pub async fn get_routes(_req: HttpRequest) -> HttpResponse {
    let babel_port = settings::get_rita_client().network.babel_port;
    match open_babel_stream(babel_port, Duration::from_secs(5)) {
        Ok(mut stream) => match parse_routes(&mut stream) {
            Ok(routes) => HttpResponse::Ok().json(routes),
            Err(e) => HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .json(format!("Unable to parse babel routes: {e}")),
        },
        Err(e) => HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("Unable to open babel stream to get routes: {e}")),
    }
}

/// Gets info about neighbors, including interested data about what their route
/// price is to the exit and how much we may owe them. The debt data is now legacy
/// since the /debts endpoint was introduced, and should be removed when it can be
/// coordinated with the frontend.
/// The routes info might also belong in /exits or a dedicated /routes endpoint
pub async fn get_neighbor_info(
    _req: HttpRequest,
    em_ref: web::Data<Arc<RwLock<ExitManager>>>,
) -> HttpResponse {
    let debts = dump();
    let neighbors = tm_get_neighbors();
    let combined_list = merge_debts_and_neighbors(neighbors, debts);
    let babel_port = settings::get_rita_client().network.babel_port;

    match open_babel_stream(babel_port, BABEL_TIMEOUT) {
        Ok(mut stream) => {
            let routes = parse_routes(&mut stream);
            if let Ok(routes) = routes {
                let route_table_sample = routes;
                let stats = get_stats();
                let output = generate_neighbors_list(
                    stats,
                    route_table_sample,
                    combined_list,
                    &em_ref.read().unwrap(),
                );
                HttpResponse::Ok().json(output)
            } else {
                HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!(
                    "{}",
                    RitaClientError::MiscStringError("Could not get babel routes".to_string())
                ))
            }
        }
        Err(_) => HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!(
            "{}",
            RitaClientError::MiscStringError("Could not open babel stream".to_string())
        )),
    }
}

/// generates a list of neighbors coorelated with the quality of the route to the exit they provide
fn generate_neighbors_list(
    stats: Stats,
    route_table_sample: Vec<Route>,
    debts: HashMap<Identity, (NodeDebtData, Neighbor)>,
    em_ref: &ExitManager,
) -> Vec<NodeInfo> {
    let mut output = Vec::new();

    for (identity, (debt_info, neigh)) in debts.iter() {
        let nickname = match identity.nickname {
            Some(val) => val,
            None => ArrayString::<32>::from("No Nickname").unwrap(),
        };
        let maybe_route = get_installed_route(&identity.mesh_ip, &route_table_sample);
        if maybe_route.is_err() {
            output.push(nonviable_node_info(
                nickname,
                u16::MAX,
                identity.mesh_ip.to_string(),
                *identity,
                neigh.speed_limit,
            ));
            continue;
        }
        let neigh_route = maybe_route.unwrap();

        let exit_ip = match em_ref.get_current_exit() {
            Some(exit) => exit.mesh_ip,
            None => {
                output.push(nonviable_node_info(
                    nickname,
                    neigh_route.metric,
                    identity.mesh_ip.to_string(),
                    *identity,
                    neigh.speed_limit,
                ));
                continue;
            }
        };
        if let Some(stats_entry) = stats.get(&neigh_route.iface) {
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
                total_payments: debt_info.total_payment_received,
                debt: debt_info.debt,
                link_cost: exit_route.refmetric,
                price_to_exit: exit_route.price,
                stats: *stats_entry,
            })
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
        route_metric_to_exit: u16::MAX,
        route_metric: neigh_metric,
        speed_limit,
        stats: IfaceStats::default(),
    }
}
