//! NetworkMonitor is an experimental system to apply traffic shaping to neighbors based on the neighbor rtt
//! it also monitors various network properties to display to the user and to log for later investigation
//! TODO: NetworkMonitor curently has a couple of major deficiencies, we base our throttling choices off of
//! round trip time, but that means that if the other side has been rebooted and the latency spike is due to them
//! uploading we may further limit the connection from our side without any good reason. This can be solved by
//! communcating the current throttle value in the hello seqence. The other problem is that we will respond to latency
//! spikes that are not correlated with traffic. This could lead to limiting connection throughput for reasons as mundane
//! as a bird flying through the connection rather than actual bloat. The solution here would be to also collect stats
//! on traffic over every interface and base our action off of spikes in throughput as well as spikes in latency.

use crate::rita_loop::fast_loop::FAST_LOOP_SPEED;
use crate::set_to_shape;
use crate::tunnel_manager::shaping::ShapingAdjust;
use crate::tunnel_manager::shaping::ShapingAdjustAction;
use crate::tunnel_manager::Neighbor as RitaNeighbor;
use crate::RitaCommonError;

use althea_types::monitoring::has_packet_loss;
use althea_types::monitoring::SAMPLE_PERIOD;
use althea_types::RunningLatencyStats;
use althea_types::RunningPacketLossStats;
use althea_types::WgKey;
use babel_monitor::structs::Neighbor as BabelNeighbor;
use babel_monitor::structs::Route as BabelRoute;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

lazy_static! {
    static ref NETWORK_MONITOR: Arc<RwLock<NetworkMonitor>> =
        Arc::new(RwLock::new(NetworkMonitor::default()));
}

/// 10 minutes in seconds, the amount of time we wait for an interface to be
/// 'good' before we start trying to increase it's speed
const BACK_OFF_TIME: Duration = Duration::from_secs(600);
/// We want to reset our counters every few hours to make sure they don't
/// become to insensitive to changes, currently 12 hours.
const WINDOW_TIME: Duration = Duration::from_secs(43200);

#[derive(Clone)]
pub struct NetworkMonitor {
    latency_history: HashMap<String, RunningLatencyStats>,
    packet_loss_history: HashMap<String, RunningPacketLossStats>,
    last_babel_dump: Option<NetworkInfo>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        NetworkMonitor {
            latency_history: HashMap::new(),
            packet_loss_history: HashMap::new(),
            last_babel_dump: None,
        }
    }
}

impl Default for NetworkMonitor {
    fn default() -> NetworkMonitor {
        NetworkMonitor::new()
    }
}

#[derive(Default, Serialize, Copy, Clone)]
pub struct LatencyStats {
    avg: Option<f32>,
    std_dev: Option<f32>,
}

#[derive(Default, Serialize, Copy, Clone)]
pub struct PacketLossStats {
    avg: Option<f32>,
    five_min_avg: f32,
}

pub struct GetStats {}

#[derive(Serialize, Default, Copy, Clone)]
pub struct IfaceStats {
    latency: LatencyStats,
    packet_loss: PacketLossStats,
}

pub type Stats = HashMap<String, IfaceStats>;

pub fn get_stats() -> Stats {
    let mut stats = Stats::new();
    let network_monitor = &*(NETWORK_MONITOR.write().unwrap());

    for (iface, latency_stats) in network_monitor.latency_history.iter() {
        if let Some(packet_loss_stats) = network_monitor.packet_loss_history.get(iface) {
            stats.insert(
                iface.clone(),
                IfaceStats {
                    latency: LatencyStats {
                        avg: latency_stats.get_avg(),
                        std_dev: latency_stats.get_std_dev(),
                    },
                    packet_loss: PacketLossStats {
                        avg: packet_loss_stats.get_avg(),
                        five_min_avg: packet_loss_stats.get_five_min_average(),
                    },
                },
            );
        } else {
            error!("Found entry in one that's not in the other ")
        }
    }
    stats
}

pub struct GetNetworkInfo;

pub fn get_network_info(_msg: GetNetworkInfo) -> Result<NetworkInfo, RitaCommonError> {
    match (NETWORK_MONITOR.read().unwrap()).last_babel_dump.clone() {
        Some(dump) => Ok(dump),
        None => Err(RitaCommonError::MiscStringError(
            "No babel info ready!".to_string(),
        )),
    }
}

#[derive(Clone)]
pub struct NetworkInfo {
    pub babel_neighbors: Vec<BabelNeighbor>,
    pub babel_routes: Vec<BabelRoute>,
    pub rita_neighbors: Vec<RitaNeighbor>,
}

/// updates babel neighbors, babel routes, and rita neighbors for a NetworkInfo
pub fn update_network_info(msg: NetworkInfo) {
    let network_monitor = &mut *(NETWORK_MONITOR.write().unwrap());
    let babel_neighbors = &msg.babel_neighbors;
    let babel_routes = &msg.babel_routes;
    let rita_neighbors = &msg.rita_neighbors;
    observe_network(
        babel_neighbors,
        rita_neighbors,
        &mut network_monitor.latency_history,
        &mut network_monitor.packet_loss_history,
    );
    network_stats(babel_routes, babel_neighbors);
    network_monitor.last_babel_dump = Some(msg);
}

/// Attempts to detect bufferbloat by looking at neighbor latency over time
fn observe_network(
    babel_neighbors: &[BabelNeighbor],
    rita_neighbors: &[RitaNeighbor],
    latency_history: &mut HashMap<String, RunningLatencyStats>,
    packet_loss_history: &mut HashMap<String, RunningPacketLossStats>,
) {
    // if this assertion is failing you're running this slowly enough
    // that all the sample period logic is not relevent, go disable it
    assert_eq!(SAMPLE_PERIOD as u64, FAST_LOOP_SPEED.as_secs());
    if !SAMPLE_PERIOD <= 16 {
        panic!("NetworkMonitor is running too slowly! Please adjust constants");
    }
    let mut to_shape = Vec::new();
    for neigh in babel_neighbors.iter() {
        let iface = &neigh.iface;
        if !latency_history.contains_key(iface) {
            latency_history.insert(iface.clone(), RunningLatencyStats::new());
        }
        let running_stats = latency_history.get_mut(iface).unwrap();
        match (
            get_wg_key_by_ifname(neigh, rita_neighbors),
            running_stats.get_avg(),
            running_stats.get_std_dev(),
        ) {
            (Some(key), Some(avg), Some(std_dev)) => {
                if running_stats.is_bloated() {
                    info!(
                        "Neighbor {} is defined as bloated with AVG {} STDDEV {} and CV {}!",
                        key, avg, std_dev, neigh.rtt
                    );
                    // schedule the misbehaving tunnel for shaping
                    to_shape.push(ShapingAdjust {
                        iface: iface.to_string(),
                        action: ShapingAdjustAction::ReduceSpeed,
                    });
                    // go see the comment in is_bloated() before you consider
                    // touching this, here there be dragons
                    running_stats.reset();
                } else if Instant::now() > running_stats.last_changed()
                    && Instant::now() - running_stats.last_changed() > BACK_OFF_TIME
                    && running_stats.is_good()
                {
                    info!(
                        "Neighbor {} is increasing speed with AVG {} STDDEV {} and CV {}",
                        key, avg, std_dev, neigh.rtt
                    );
                    // schedule the misbehaving tunnel for a speed increase
                    to_shape.push(ShapingAdjust {
                        iface: iface.to_string(),
                        action: ShapingAdjustAction::IncreaseSpeed,
                    });
                    running_stats.set_last_changed();
                } else {
                    info!(
                        "Neighbor {} is ok with AVG {} STDDEV {} and CV {}",
                        key, avg, std_dev, neigh.rtt
                    )
                }
            }
            (None, _, _) => error!(
                "We have a bloated connection to {} but no Rita neighbor!",
                iface
            ),
            (_, _, _) => {}
        }
        running_stats.add_sample(neigh.rtt);
        if Instant::now() > running_stats.last_changed()
            && Instant::now() - running_stats.last_changed() > WINDOW_TIME
        {
            running_stats.reset();
        }
    }

    // observe packet loss, currently not used in production to adjust anything
    // could maybe be used as a feedback for when shaping is working hard because
    // that's the only time things get dropped, you pry each packet form the cold
    // dead hands of the antennas 500ms later rather than droping them.
    for neigh in babel_neighbors.iter() {
        let iface = &neigh.iface;
        if !packet_loss_history.contains_key(iface) {
            packet_loss_history.insert(iface.clone(), RunningPacketLossStats::new());
        }
        let running_stats = packet_loss_history.get_mut(iface).unwrap();
        running_stats.add_sample(neigh.reach);
        match (
            has_packet_loss(neigh.reach),
            running_stats.get_avg(),
            get_wg_key_by_ifname(neigh, rita_neighbors),
        ) {
            (true, Some(avg), Some(key)) => {
                let five_min_average = running_stats.get_five_min_average();
                info!(
                    "Lost packets to {} {}% five min average {}% power on average",
                    key, five_min_average, avg
                );
            }
            (true, Some(_avg), None) => {
                error!(
                    "We have a packet loss event to {} but no Rita neighbor!",
                    iface
                );
            }
            (true, None, _) => {}
            (false, _, _) => {}
        }
    }

    // shape the misbehaving tunnels, we do this all at once for the sake
    // of efficiency as lots of do_sends have a high chance of getting lost
    // also there's nontrivial overhead
    set_to_shape(to_shape);
}

fn get_wg_key_by_ifname(neigh: &BabelNeighbor, rita_neighbors: &[RitaNeighbor]) -> Option<WgKey> {
    for rita_neigh in rita_neighbors.iter() {
        if rita_neigh.iface_name.contains(&neigh.iface) {
            return Some(rita_neigh.identity.global.wg_public_key);
        }
    }
    None
}

/// Gathers interesting network info
fn network_stats(babel_routes: &[BabelRoute], babel_neighbors: &[BabelNeighbor]) {
    if let Some(avg_neigh_rtt) = mean(&extract_rtt(babel_neighbors)) {
        let num_neighs = babel_neighbors.len();
        info!(
            "The average neigh RTT is {} for {} neighs",
            avg_neigh_rtt, num_neighs
        );
    }
    if let Some(avg_route_rtt) = mean(&extract_fp_rtt(babel_routes)) {
        let num_routes = babel_routes.len();
        info!(
            "The average route RTT is {} for {} routes",
            avg_route_rtt, num_routes
        );
    }
}

/// Extracts the full path rtt for Neighbors
fn extract_rtt(neighbors: &[BabelNeighbor]) -> Vec<f32> {
    neighbors.iter().map(|neigh| neigh.rtt).collect()
}

/// Extracts the full path rtt for installed routes
fn extract_fp_rtt(routes: &[BabelRoute]) -> Vec<f32> {
    routes
        .iter()
        .filter(|route| route.installed)
        .map(|route| route.full_path_rtt)
        .collect()
}

fn mean(data: &[f32]) -> Option<f32> {
    let sum = data.iter().sum::<f32>();
    let count = data.len();

    match count {
        positive if positive > 0 => Some(sum / count as f32),
        _ => None,
    }
}
