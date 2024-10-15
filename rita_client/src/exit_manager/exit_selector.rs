//! This file handles the task of selecting an exit node for the client to use. We have a list of potential exits that we can use
//! and then babeld metrics which we will track over time in an attempt to determine which is the best exit to use. This code is also
//! responsiblef or detecting when the exit is down and switching to a new one.

use super::exit_loop::EXIT_LOOP_SPEED;
use super::utils::get_babel_routes;
use crate::RitaClientError;
use althea_types::{ExitIdentity, ExitServerList};
use std::cmp::{max, min};
use std::time::Instant;
use std::{collections::HashMap, net::IpAddr, time::Duration};

/// This function selects the best exit from the exit list, it does this by getting the routes from babel
/// and then merging them with the current history of exit quality samples. It then selects the exit with the best
/// quality and sets it as the currently selected exit in the exit manager
pub fn select_best_exit(
    switcher_state: &mut ExitSwitcherState,
    exit_list: ExitServerList,
    babel_port: u16,
) {
    let current_exit = switcher_state.currently_selected.clone();
    // gets routes from babel, this blocks for some time, if we fail to get routes
    // we return the currently selected exit
    if let Err(e) = get_and_merge_routes_for_exit_list(
        &mut switcher_state.quality_history,
        exit_list,
        babel_port,
    ) {
        // in tests we won't be able to get babel routes and should just continue
        // data is being mocked into the structs
        if !cfg!(test) {
            error!("Error getting routes for exit list {:?}", e);
            return;
        }
    }
    // continue with the current exit if we can't find a better one
    let best_exit = match switcher_state.get_best_exit() {
        Some(exit) => exit,
        None => {
            error!("No exits in exit list, can't select exit");
            return;
        }
    };
    // it hasn't been long enough to initiate a switch, unless our current exit is down
    // either way once we're past this code block we're allowed to switch
    if let Some(last_switch) = switcher_state.last_switch {
        if last_switch.elapsed() < switcher_state.backoff
            && !switcher_state.exit_is_down(current_exit)
        {
            return;
        }
    }

    // switch to the best exit
    switcher_state.currently_selected = best_exit;
    switcher_state.last_switch = Some(Instant::now());
    switcher_state.backoff *= 2;
}

/// If the last update from a route is older than this, it means the exit is down and has left
/// the routing table
pub fn last_route_too_old() -> Duration {
    EXIT_LOOP_SPEED * 5
}

/// This struct keeps track of previous rate data and last switch time in order to
/// determine if we should switch exits
#[derive(Clone, Debug)]
pub struct ExitSwitcherState {
    /// When we last switched exits, none if we have never switched
    pub last_switch: Option<Instant>,
    /// If last_swtich plus backoff is less than now we can switch, meaning this represents the minimum
    /// time that must elapse before we can switch exits again. This is a variable value so that we can increase
    /// the time between switches if we are switching too often
    pub backoff: Duration,
    /// the currently selected exit starts as a random exit from the bootstrapping list
    /// and/or the last successfully selected exit if the router has been online before
    pub currently_selected: ExitIdentity,
    /// This is a history of route quality for exits on the exit list
    pub quality_history: HashMap<ExitIdentity, Vec<ExitQualitySample>>,
}

impl ExitSwitcherState {
    pub fn exit_is_down(&self, exit: ExitIdentity) -> bool {
        match self.quality_history.get(&exit) {
            Some(history) => {
                let most_recent_sample = history.iter().max_by_key(|sample| sample.time);
                match most_recent_sample {
                    Some(sample) => {
                        // if we either have not seen a route update, or that route update is u16 max the exit is down
                        // and unreachable/removed from the routing table. Routes spend quite some time as unreachable (u16 MAX)
                        // before they are removed from the routing table.
                        sample.time.elapsed() > last_route_too_old()
                            || sample.route_quality == u16::MAX
                    }
                    None => true,
                }
            }
            None => true,
        }
    }

    /// Gets the best exit from teh current history of exit quality samples, will only return none if there are no samples
    pub fn get_best_exit(&self) -> Option<ExitIdentity> {
        let mut quality_summary = HashMap::new();
        for (exit, quality_history) in self.quality_history.iter() {
            let mut total_quality = 0;
            let mut total_samples = 0;
            let mut latest_sample: Option<Instant> = None;
            for sample in quality_history {
                // redundant check
                if sample.time.elapsed() < MAX_QUALITY_SAMPLE_AGE {
                    total_quality += sample.route_quality as u128;
                    total_samples += 1;
                    match latest_sample {
                        Some(latest) => {
                            latest_sample = Some(max(sample.time, latest));
                        }
                        None => {
                            latest_sample = Some(sample.time);
                        }
                    }
                }
            }
            if let Some(last_sample) = latest_sample {
                quality_summary.insert(
                    exit,
                    ExitQualitySummary {
                        metric_sum: total_quality,
                        num_samples: total_samples,
                        last_sample,
                    },
                );
            }
        }
        // select the exit with the best quality using the ord implementation of ExitQualitySummary
        let mut best = None;
        for (exit, summary) in quality_summary {
            match best {
                Some((_, best_summary)) => {
                    // lower metric sum is better
                    if summary < best_summary {
                        best = Some((exit.clone(), summary));
                    }
                }
                None => {
                    best = Some((exit.clone(), summary));
                }
            }
        }
        best.map(|(exit, _)| exit)
    }
}

#[derive(Clone, Copy, Debug, Hash)]
pub struct ExitQualitySample {
    /// The time this sample was taken
    pub time: Instant,
    /// The quality of the exit, this is a number between 0 and 1 where 1 is the best
    pub route_quality: u16,
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
/// A simple struct representing the summary of the quality of an exit
/// exists just to implement ord
pub struct ExitQualitySummary {
    pub metric_sum: u128,
    pub num_samples: u128,
    pub last_sample: Instant,
}

impl PartialOrd for ExitQualitySummary {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExitQualitySummary {
    /// This function compares two exit quality summaries, this is used to decide what exit
    /// is the best, so if you want to modify how exits are ranked look here
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let max_last_sample = max(self.last_sample, other.last_sample);
        let min_last_sample = min(self.last_sample, other.last_sample);
        // small differences in last sample time can be tolerated but large differences
        // indicate that one of the two exits is not being updated and therefore down
        let max_last_sample_diff = last_route_too_old();
        assert!(max_last_sample_diff < MAX_QUALITY_SAMPLE_AGE);
        if max_last_sample - min_last_sample > max_last_sample_diff {
            return self.last_sample.cmp(&other.last_sample);
        }
        // otherwise we just compare the average quality
        let self_avg = self.metric_sum / self.num_samples;
        let other_avg = other.metric_sum / other.num_samples;
        self_avg.cmp(&other_avg)
    }
}

/// This function returns the maximum age of a sample that we will store in the quality history
/// and therefore consider when selecting an exit. This would be a constant but Durations are allocated
pub const MAX_QUALITY_SAMPLE_AGE: Duration = Duration::from_secs(900);

/// This function manages the babel route history for the exits, it takes the current history, gets updated routes
/// and then merges the two together. It also removes old samples from the history and removes exits that are no longer
/// in the exit list. Note that if a route does not exist for a given exit it is not added to the history. It also means
/// we can't reach that exit / it is down
pub fn get_and_merge_routes_for_exit_list(
    quality_history: &mut HashMap<ExitIdentity, Vec<ExitQualitySample>>,
    exit_list: ExitServerList,
    babel_port: u16,
) -> Result<(), RitaClientError> {
    let routes = get_babel_routes(babel_port)?;
    // hashset of all exit ip's in the exit list, used to reduce lookup time complexity
    let exit_ips: HashMap<IpAddr, ExitIdentity> = exit_list
        .exit_list
        .iter()
        .map(|exit| (exit.mesh_ip, exit.clone()))
        .collect();
    for route in routes {
        // we should ignore routes that are not installed, meaning routes
        // that are not in the routing table to be used to actually reach the node
        // there shouldn't be any ipv4 routes floating around, but we should skip them too
        if route.installed && route.prefix.is_ipv6() {
            if let Some(exit) = exit_ips.get(&route.prefix.network()) {
                // filter exits that are invalid for our selection
                if exit_is_valid_for_us(exit.clone()) {
                    match quality_history.get_mut(exit) {
                        Some(history) => {
                            // remove old samples
                            history.retain(|sample| sample.time.elapsed() < MAX_QUALITY_SAMPLE_AGE);

                            // add new sample
                            history.push(ExitQualitySample {
                                time: Instant::now(),
                                route_quality: route.metric,
                            });
                        }
                        None => {
                            quality_history.insert(
                                exit.clone(),
                                vec![ExitQualitySample {
                                    time: Instant::now(),
                                    route_quality: route.metric,
                                }],
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Checks if the exit is in a compatible region and has a compatible payment type
/// this check may be duplicated in the exit list update, but redundancy is good in this case
/// since a mistake will result in a bad exit being selected
fn exit_is_valid_for_us(exit: ExitIdentity) -> bool {
    let client_settings = settings::get_rita_client();
    let exit_accepts_our_payment_type = exit
        .payment_types
        .contains(&client_settings.payment.system_chain);
    // region matching works as follows: if we have no region set in our settings we connect to exits with no region set
    // if we have a region set we will connect to exits with that region and exits with no region set
    let exit_matches_our_region = if let Some(our_region) = client_settings.exit_client.our_region {
        exit.allowed_regions.contains(&our_region) || exit.allowed_regions.is_empty()
    } else {
        true
    };
    exit_accepts_our_payment_type && exit_matches_our_region
}

#[cfg(test)]
mod tests {
    use super::*;
    use althea_types::{ExitIdentity, ExitServerList};
    use clarity::Address;
    use std::collections::HashSet;
    use std::time::{Duration, Instant, SystemTime};

    /// generates a random identity, never use in production, your money will be stolen
    pub fn random_exit_identity() -> ExitIdentity {
        use clarity::PrivateKey;

        let secret: [u8; 32] = rand::random();
        let mut ip: [u8; 16] = [0; 16];
        ip.copy_from_slice(&secret[0..16]);

        // the starting location of the funds
        let eth_key = PrivateKey::from_bytes(secret).unwrap();
        let eth_address = eth_key.to_address();

        let payment_types = HashSet::new();
        let allowed_regions = HashSet::new();

        ExitIdentity {
            mesh_ip: ip.into(),
            eth_addr: eth_address,
            wg_key: secret.into(),
            registration_port: 0,
            wg_exit_listen_port: 0,
            allowed_regions,
            payment_types,
        }
    }

    #[test]
    fn test_select_best_exit_basic() {
        let mut state = ExitSwitcherState {
            last_switch: None,
            backoff: Duration::from_secs(10),
            currently_selected: random_exit_identity(),
            quality_history: HashMap::new(),
        };

        let exit_list = ExitServerList {
            exit_list: vec![random_exit_identity(), random_exit_identity()],
            contract: Address::default(),
            created: SystemTime::now(),
        };

        // Simulate route qualities
        state.quality_history.insert(
            state.currently_selected.clone(),
            vec![ExitQualitySample {
                time: Instant::now(),
                route_quality: 100,
            }],
        );

        let other_exit = exit_list.exit_list[1].clone();
        state.quality_history.insert(
            other_exit.clone(),
            vec![ExitQualitySample {
                time: Instant::now(),
                route_quality: 50,
            }],
        );

        // Test selection of the best exit
        select_best_exit(&mut state, exit_list, 0);

        assert_eq!(state.currently_selected.mesh_ip, other_exit.mesh_ip);
    }

    #[test]
    fn test_exit_is_down() {
        let mut state = ExitSwitcherState {
            last_switch: None,
            backoff: Duration::from_secs(10),
            currently_selected: random_exit_identity(),
            quality_history: HashMap::new(),
        };

        let exit = random_exit_identity();

        // Test when no history exists for an exit
        assert!(state.exit_is_down(exit.clone()));

        // Test when history exists but the route quality is u16::MAX
        state.quality_history.insert(
            exit.clone(),
            vec![ExitQualitySample {
                time: Instant::now(),
                route_quality: u16::MAX,
            }],
        );
        assert!(state.exit_is_down(exit));
    }

    #[test]
    fn test_get_best_exit() {
        let mut state = ExitSwitcherState {
            last_switch: None,
            backoff: Duration::from_secs(10),
            currently_selected: random_exit_identity(),
            quality_history: HashMap::new(),
        };

        // No history, so no best exit
        assert!(state.get_best_exit().is_none());

        // Add some history with varying quality
        let better_exit = random_exit_identity();
        let worse_exit = random_exit_identity();

        state.quality_history.insert(
            worse_exit.clone(),
            vec![ExitQualitySample {
                time: Instant::now(),
                route_quality: 100,
            }],
        );
        state.quality_history.insert(
            better_exit.clone(),
            vec![ExitQualitySample {
                time: Instant::now(),
                route_quality: 50,
            }],
        );

        // The best exit should be the one with the lowest route_quality (better quality)
        assert_eq!(state.get_best_exit().unwrap().mesh_ip, better_exit.mesh_ip);
    }

    #[test]
    fn test_backoff_logic() {
        let mut state = ExitSwitcherState {
            last_switch: Some(Instant::now() - Duration::from_secs(5)),
            backoff: Duration::from_secs(10),
            currently_selected: random_exit_identity(),
            quality_history: HashMap::new(),
        };

        let exit_list = ExitServerList {
            exit_list: vec![random_exit_identity(), random_exit_identity()],
            contract: Address::default(),
            created: SystemTime::now(),
        };

        // Simulate route qualities
        let current_exit = state.currently_selected.clone();
        state.quality_history.insert(
            current_exit.clone(),
            vec![ExitQualitySample {
                time: Instant::now(),
                route_quality: 100,
            }],
        );

        let better_exit = exit_list.exit_list[1].clone();
        state.quality_history.insert(
            better_exit.clone(),
            vec![ExitQualitySample {
                time: Instant::now(),
                route_quality: 50,
            }],
        );

        // It shouldn't switch because backoff hasn't passed and the current exit isn't down
        select_best_exit(&mut state, exit_list.clone(), 0);
        assert_eq!(state.currently_selected.mesh_ip, current_exit.mesh_ip);

        // It should switch now since the backoff has passed
        state.last_switch = Some(Instant::now() - Duration::from_secs(15));
        select_best_exit(&mut state, exit_list, 0);
        assert_eq!(state.currently_selected.mesh_ip, better_exit.mesh_ip);
    }
}
