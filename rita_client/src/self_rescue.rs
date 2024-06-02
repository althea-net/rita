use althea_kernel_interface::hardware_info::get_hardware_info;
use althea_kernel_interface::KI;
use rand::prelude::SliceRandom;
use rand::Rng;
use rita_common::TUNNEL_HANDSHAKE_TIMEOUT;
use settings::get_rita_common;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

pub const RESCUE_LOOP_SPEED: Duration = Duration::from_secs(60);

/// Non blocking function that spawns the client rescue loop, the client rescue loop is dedicated to detecting when the client is not running
/// properly and restarting it. This is a last resort to keep the client running and is not a replacement for proper error handling
/// By my judgement this mostly ends up running when kernel lockups and race conditions end up causing main threads to block or panic
/// on operations that otherwise should be safe.
pub fn start_rita_client_rescue_loop() {
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        let mut last_successful_ping = Instant::now();
        // when we check the last successful handshake on wireguard tunnels we are implicitly checking the system time
        // as well. If we sync the system time it is not uncommon to see tunnel handshakes more than 'one year old' for a short period
        // no more than a few minutes. Since openwrt gets the system time from the last saved file on the disk and last saved times
        // sometimes get wonky by reverting to the original firmware image build time we should wait long enough for a new handshake
        // to be computed on the new system time before we trigger a reboot
        let mut last_successful_handshake_check = Instant::now();
        loop {
            // first we check if we can reach the internet, if we can't for too long we reboot

            if run_ping_test() {
                info!("Successful ping!");
                last_successful_ping = Instant::now();
            } else {
                // If this router has been in a bad state for >10 mins, reboot
                if (Instant::now() - last_successful_ping) > REBOOT_TIMEOUT {
                    let _res = KI.run_command("reboot", &[]);
                }
            }

            // next we check for abandoned tunnels, if a tunnel has not had a handshke and the garbage collector thread
            // has not removed it we can assume that thread is in a bad state and we should reboot. Check only 3 random tunnels
            // note this relies on the observation that connection issues happen across all tuneels at once, if only one tunnel is bad
            // this will not trigger.
            //
            // If you're coming back and looking at expanding/improving this in the future, consider moving this out of a separate thread
            // and into rita_client or rita_common loops using a shared Instant that exists only in the context of those two threads rather than
            // a global lazy static Instant. This would keep us from having to make guesses around the system time
            let wg_interfaces = KI.get_list_of_wireguard_interfaces();
            info!("interfaces {:?}", wg_interfaces);
            if let Ok(interfaces) = wg_interfaces {
                let mut rng = rand::thread_rng();
                let sample = interfaces.choose_multiple(&mut rng, 3);
                for interface in sample {
                    if let Ok(times) = KI.get_last_active_handshake_time(&interface) {
                        // we grab only the first timestamps because none of these tunnels should have multiple timestamps
                        if let Some((_, time)) = times.first() {
                            if let Ok(elapsed) = time.elapsed() {
                                match (
                                    elapsed > TUNNEL_HANDSHAKE_TIMEOUT * 2,
                                    last_successful_handshake_check.elapsed() > REBOOT_TIMEOUT,
                                ) {
                                    (true, true) => {
                                        let _res = KI.run_command("reboot", &[]);
                                    }
                                    // wait
                                    (true, false) => {}
                                    // tunnels have not reached timeouts yet
                                    (false, _) => last_successful_handshake_check = Instant::now(),
                                }
                            } else {
                                // timestamp in the future, that's definately not timed out
                                last_successful_handshake_check = Instant::now();
                            }
                        }
                    }
                }
            }

            // next we check if the load average is too high for hAP specifically since they are more prone to this
            let model = get_rita_common().network.device;
            let hw_info = get_hardware_info(model.clone());
            match (model, hw_info) {
                (None, _) => error!("Model name not found?"),
                (Some(mdl), Ok(info)) => {
                    if mdl.contains("mikrotik_hap-ac2") && info.load_avg_fifteen_minute > 4.0 {
                        info!("15 minute load average > 4, rebooting!");
                        let _res = KI.run_command("reboot", &[]);
                    }
                }
                (Some(_), Err(_)) => error!("Could not get hardware info!"),
            }

            thread::sleep(RESCUE_LOOP_SPEED);
        }
    });
}

/// This list should contain as many unique public ips from as many different providers as possible
/// the larger this list the less we ping any specific provider and the less likely we are to be
/// confused by a single router being down
const PING_TEST_IPS: [Ipv4Addr; 6] = [
    // Cloudflare
    Ipv4Addr::new(1, 1, 1, 1),
    // Google
    Ipv4Addr::new(8, 8, 8, 8),
    // Quad9
    Ipv4Addr::new(9, 9, 9, 9),
    // Hurricane Electric
    Ipv4Addr::new(74, 82, 42, 42),
    // OpenDNS
    Ipv4Addr::new(208, 67, 222, 222),
    // Verisin
    Ipv4Addr::new(64, 6, 65, 6),
];
/// Verifies ipv4 connectivity by pinging a set list of external ip addresses. This check
/// comes with some risk, if the ip addresses provided are all down, the router will reboot
/// even if connectivity to the rest of the internet is fine. To avoid this we ping several
/// different common addresses
pub fn run_ping_test() -> bool {
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..PING_TEST_IPS.len());
    let target_ip = PING_TEST_IPS[index];

    let timeout = Duration::from_secs(5);
    match KI.ping_check(&target_ip.into(), timeout, None) {
        Ok(out) => out,
        Err(e) => {
            error!("ipv4 ping error: {:?}", e);
            false
        }
    }
}

const REBOOT_TIMEOUT: Duration = Duration::from_secs(600);
