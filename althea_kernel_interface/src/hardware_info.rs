use crate::file_io::get_lines;
use crate::KernelInterfaceError as Error;
use crate::KI;
use althea_types::extract_wifi_station_data;
use althea_types::extract_wifi_survey_data;
use althea_types::ConntrackInfo;
use althea_types::EthOperationMode;
use althea_types::EthernetStats;
use althea_types::HardwareInfo;
use althea_types::SensorReading;
use althea_types::WifiDevice;
use althea_types::WifiStationData;
use althea_types::WifiSurveyData;
use std::fs;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::process::Command;
use std::process::Stdio;
use std::str::from_utf8;
use std::time::Duration;
use std::u64;

/// Gets the load average and memory of the system from /proc should be plenty
/// efficient and safe to run. Requires the device name to be passed in because
/// it's stored in settings and I don't see why we should parse it here
/// things that might be interesting to add here are CPU arch and system temp sadly
/// both are rather large steps up complexity wise to parse due to the lack of consistent
/// formatting
pub fn get_hardware_info(device_name: Option<String>) -> Result<HardwareInfo, Error> {
    let (one_minute_load_avg, five_minute_load_avg, fifteen_minute_load_avg) = get_load_avg()?;
    let (mem_total, mem_free) = get_memory_info()?;

    let model = match device_name {
        Some(name) => name,
        None => "Unknown Device".to_string(),
    };

    let num_cpus = get_numcpus()?;

    let sensor_readings = get_sensor_readings();
    let allocated_memory = match mem_total.checked_sub(mem_free) {
        Some(val) => val,
        None => return Err(Error::FailedToGetMemoryUsage),
    };

    let system_uptime = get_sys_uptime()?;

    let system_kernel_version = get_kernel_version()?;
    let (entire_system_kernel_version, system_kernel_version) =
        parse_kernel_version(system_kernel_version)?;

    let ethernet_stats = get_ethernet_stats();

    let wifi_devices = get_wifi_devices();

    // This get populated later
    let extender_list = None;

    let conntrack_info = get_conntrack_info();

    Ok(HardwareInfo {
        logical_processors: num_cpus,
        load_avg_one_minute: one_minute_load_avg,
        load_avg_five_minute: five_minute_load_avg,
        load_avg_fifteen_minute: fifteen_minute_load_avg,
        system_memory: mem_total,
        allocated_memory,
        model,
        sensor_readings,
        system_uptime,
        system_kernel_version,
        entire_system_kernel_version,
        ethernet_stats,
        wifi_devices,
        extender_list,
        conntrack: conntrack_info,
    })
}

pub fn get_kernel_version() -> Result<String, Error> {
    let sys_kernel_ver_error = Err(Error::FailedToGetSystemKernelVersion);

    let lines = get_lines("/proc/version")?;
    let line = match lines.first() {
        Some(line) => line,
        None => return sys_kernel_ver_error,
    };
    Ok(line.to_string())
}

pub fn parse_kernel_version(line: String) -> Result<(String, String), Error> {
    let mut times = line.split_whitespace().peekable();

    let mut kernel_ver = "".to_string();
    let mut kernel_ver_entire = "".to_string();
    while times.peek().is_some() {
        match times.next() {
            Some(val) => {
                if val.to_string().eq("Linux") {
                    match times.next() {
                        Some(val) => {
                            if val.to_string().eq("version") {
                                match times.next() {
                                    Some(val) => kernel_ver.push_str(val),
                                    None => {
                                        info!("None value encountered");
                                        break;
                                    }
                                }
                                match times.next() {
                                    Some(val) => kernel_ver_entire.push_str(val),
                                    None => {
                                        info!("None value encountered");
                                        break;
                                    }
                                }
                            } else {
                                match times.next() {
                                    Some(val) => kernel_ver_entire.push_str(val),
                                    None => {
                                        info!("None value encountered");
                                        break;
                                    }
                                }
                            }
                        }
                        None => {
                            info!("None value encountered");
                            break;
                        }
                    }
                } else {
                    match times.next() {
                        Some(val) => kernel_ver_entire.push_str(val),
                        None => {
                            info!("None value encountered");
                            break;
                        }
                    }
                }
            }
            None => {
                info!("None value encountered");
                break;
            }
        }
    }

    Ok((kernel_ver_entire, kernel_ver))
}

fn get_sys_uptime() -> Result<Duration, Error> {
    let sys_time_error = Err(Error::FailedToGetSystemTime);

    let lines = get_lines("/proc/uptime")?;
    let line = match lines.first() {
        Some(line) => line,
        None => return sys_time_error,
    };

    let mut times = line.split_whitespace();

    //Split to convert to unsigned integer as it has a decimal
    let uptime: u64 = match times.next() {
        Some(val) => match val.split('.').next() {
            Some(val) => val.parse()?,
            None => return sys_time_error,
        },
        None => return sys_time_error,
    };

    let dur_time = Duration::new(uptime, 0);

    Ok(dur_time)
}

fn get_load_avg() -> Result<(f32, f32, f32), Error> {
    // cpu load average
    let load_average_error = Err(Error::FailedToGetLoadAverage);
    let lines = get_lines("/proc/loadavg")?;
    let load_avg = match lines.first() {
        Some(line) => line,
        None => return load_average_error,
    };
    let mut load_avg = load_avg.split_whitespace();
    let one_minute_load_avg: f32 = match load_avg.next() {
        Some(val) => val.parse()?,
        None => return load_average_error,
    };
    let five_minute_load_avg: f32 = match load_avg.next() {
        Some(val) => val.parse()?,
        None => return load_average_error,
    };
    let fifteen_minute_load_avg: f32 = match load_avg.next() {
        Some(val) => val.parse()?,
        None => return load_average_error,
    };
    Ok((
        one_minute_load_avg,
        five_minute_load_avg,
        fifteen_minute_load_avg,
    ))
}

pub fn get_memory_info() -> Result<(u64, u64), Error> {
    // memory info
    let lines = get_lines("/proc/meminfo")?;
    let mut lines = lines.iter();
    let memory_info_error = Err(Error::FailedToGetMemoryInfo);
    let mem_total: u64 = match lines.next() {
        Some(line) => match line.split_whitespace().nth(1) {
            Some(val) => val.parse()?,
            None => return memory_info_error,
        },
        None => return memory_info_error,
    };
    let mem_free: u64 = match lines.next() {
        Some(line) => match line.split_whitespace().nth(1) {
            Some(val) => val.parse()?,
            None => return memory_info_error,
        },
        None => return memory_info_error,
    };

    Ok((mem_total, mem_free))
}

/// gets the number of logical (not physical) cores
/// by parsing /proc/cpuinfo may be inaccurate
fn get_numcpus() -> Result<u32, Error> {
    // memory info
    let lines = get_lines("/proc/cpuinfo")?;
    let mut num_cpus = 0;
    for line in lines {
        if line.contains("processor") {
            num_cpus += 1;
        }
    }
    Ok(num_cpus)
}

fn maybe_get_single_line_u64(path: &str) -> Option<u64> {
    match get_lines(path) {
        Ok(line) => {
            let var_name = line.first();
            match var_name {
                Some(val) => match val.parse() {
                    Ok(res) => Some(res),
                    Err(_e) => None,
                },
                None => None,
            }
        }
        Err(_e) => None,
    }
}

pub fn maybe_get_single_line_string(path: &str) -> Option<String> {
    match get_lines(path) {
        Ok(line) => line.first().map(|val| val.to_string()),
        Err(_e) => None,
    }
}

fn get_sensor_readings() -> Option<Vec<SensorReading>> {
    // sensors are zero indexed and there will never be gaps
    let mut sensor_num = 0;
    let mut ret = Vec::new();
    let mut path = format!("/sys/class/hwmon/hwmon{sensor_num}");
    while fs::metadata(path.clone()).is_ok() {
        if let (Some(reading), Some(name)) = (
            maybe_get_single_line_u64(&format!("{path}/temp1_input")),
            maybe_get_single_line_string(&format!("{path}/name")),
        ) {
            ret.push(SensorReading {
                name,
                reading,
                min: maybe_get_single_line_u64(&format!("{path}/temp1_min")),
                crit: maybe_get_single_line_u64(&format!("{path}/temp1_crit")),
                max: maybe_get_single_line_u64(&format!("{path}/temp1_max")),
            });
        }

        sensor_num += 1;
        path = format!("/sys/class/hwmon/hwmon{sensor_num}");
    }
    if ret.is_empty() {
        None
    } else {
        Some(ret)
    }
}

fn get_ethernet_stats() -> Option<Vec<EthernetStats>> {
    let mut eth = 0;
    let mut ret = Vec::new();
    let mut path = format!("/sys/class/net/eth{eth}");
    while fs::metadata(path.clone()).is_ok() {
        if let Some(is_up) = maybe_get_single_line_string(&format!("{path}/operstate")) {
            let is_up = is_up.contains("up");
            if let (Some(speed), Some(duplex)) = (
                maybe_get_single_line_u64(&format!("{path}/speed")),
                maybe_get_single_line_string(&format!("{path}/duplex")),
            ) {
                if let (
                    Some(tx_errors),
                    Some(rx_errors),
                    Some(tx_packet_count),
                    Some(rx_packet_count),
                ) = (
                    maybe_get_single_line_u64(&format!("{path}/statistics/tx_errors")),
                    maybe_get_single_line_u64(&format!("{path}/statistics/rx_errors")),
                    maybe_get_single_line_u64(&format!("{path}/statistics/tx_packets")),
                    maybe_get_single_line_u64(&format!("{path}/statistics/rx_packets")),
                ) {
                    ret.push(EthernetStats {
                        is_up,
                        mode_of_operation: get_ethernet_operation_mode(speed, duplex),
                        tx_packet_count,
                        tx_errors,
                        rx_packet_count,
                        rx_errors,
                    })
                }
            }
        }
        eth += 1;
        path = format!("/sys/class/net/eth{eth}");
    }

    if ret.is_empty() {
        None
    } else {
        Some(ret)
    }
}

fn get_wifi_devices() -> Vec<WifiDevice> {
    match parse_wifi_device_names() {
        Ok(devices) => devices
            .into_iter()
            .map(|dev| WifiDevice {
                name: dev.clone(),
                survey_data: get_wifi_survey_info(&dev),
                station_data: get_wifi_station_info(&dev),
                ssid: get_radio_ssid(&dev),
                channel: get_radio_channel(&dev),
                enabled: get_radio_enabled(&dev),
            })
            .collect(),
        Err(err) => {
            warn!("Unable to get wifi devices: {:?}", err);
            Vec::new()
        }
    }
}

/// This function parses files in /proc that contain conntrack info to send to ops
/// MAX_PATH: /proc/sys/net/netfilter/nf_conntrack_max this file contains the max number of conns possible in the kernel
/// CURR_CONNS_PATH: /proc/net/nf_conntrack This file lists all the current connections in the kernel, we use this file to parse
/// number of lines, this gives us total number of connections
fn get_conntrack_info() -> Option<ConntrackInfo> {
    const MAX_PATH: &str = "/proc/sys/net/netfilter/nf_conntrack_max";
    const CURR_CONNS_PATH: &str = "/proc/net/nf_conntrack";

    let curr_conn_file = match File::open(CURR_CONNS_PATH) {
        Ok(a) => a,
        Err(e) => {
            error!("Unable to parse current connection conntrack file: {:?}", e);
            return None;
        }
    };

    let curr_conn: u32 = BufReader::new(curr_conn_file).lines().count() as u32;

    let max_conns = match get_lines(MAX_PATH) {
        Ok(a) => a,
        Err(e) => {
            error!("Unable to get max conntrack connections! {:?}", e);
            return None;
        }
    };
    let max_conns: u32 = match max_conns[0].parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Cant parse max conntrack conns! {:?}", e);
            return None;
        }
    };

    let ret = ConntrackInfo {
        max_conns,
        current_conns: curr_conn,
    };
    info!("Sending the Conntrack struct: {:?}", ret);
    Some(ret)
}

/// Device names are in the form wlan0, wlan1 etc
fn parse_wifi_device_names() -> Result<Vec<String>, Error> {
    // We parse /etc/config/wireless which is an openwrt config. We return an error if not openwrt
    if KI.is_openwrt() {
        let mut ret = Vec::new();

        let lines = KI.run_command("uci", &["show", "wireless"])?;
        let lines: Vec<&str> = from_utf8(&lines.stdout)?.lines().collect();

        // trying to get lines 'wireless.default_radio1.ifname='wlan1''
        for line in lines {
            if line.contains("wireless.default_radio") && line.contains("ifname") {
                let name = match line.split('=').collect::<Vec<&str>>().last() {
                    Some(a) => *a,
                    None => {
                        error!("Cannot parse wifi string {}", line);
                        continue;
                    }
                };
                let name = name.replace('\'', "");
                ret.push(name)
            }
        }
        Ok(ret)
    } else {
        // Fallback to /proc/ parsing if no openwrt
        let mut ret = Vec::new();
        let path = "/proc/net/wireless";
        let lines = get_lines(path)?;
        for line in lines {
            if line.contains(':') {
                let name: Vec<&str> = line.split(':').collect();
                let name = name[0];
                let name = name.replace(' ', "");
                ret.push(name.to_string());
            }
        }

        Ok(ret)
    }
}

fn get_wifi_survey_info(dev: &str) -> Vec<WifiSurveyData> {
    let res = Command::new("iw")
        .args([dev, "survey", "dump"])
        .stdout(Stdio::piped())
        .output();
    match res {
        Ok(a) => match String::from_utf8(a.stdout) {
            Ok(a) => extract_wifi_survey_data(&a, dev),
            Err(e) => {
                error!("Unable to parse iw survey dump {:?}", e);
                Vec::new()
            }
        },
        Err(e) => {
            error!("Unable to run survey dump {:?}", e);
            Vec::new()
        }
    }
}

fn get_wifi_station_info(dev: &str) -> Vec<WifiStationData> {
    let res = Command::new("iw")
        .args([dev, "station", "dump"])
        .stdout(Stdio::piped())
        .output();
    match res {
        Ok(a) => match String::from_utf8(a.stdout) {
            Ok(a) => extract_wifi_station_data(&a),
            Err(e) => {
                error!("Unable to parse iw station dump {:?}", e);
                Vec::new()
            }
        },
        Err(e) => {
            error!("Unable to run station dump {:?}", e);
            Vec::new()
        }
    }
}

/// Expected input wlan0, wlan1, etc
/// map this to radio0, radio1 etc
/// Append default_ to the beginning and query /etc/config/wireless for ssid
/// In the case of an unexpected input, we simply print an error and return None
pub fn get_radio_ssid(radio: &str) -> Option<String> {
    let radio = radio.replace("wlan", "radio");
    let path = format!("wireless.default_{radio}.ssid");
    match KI.get_uci_var(&path) {
        Ok(a) => Some(a),
        Err(e) => {
            error!("Unable to get radio ssid for radio: {} with {:?}", radio, e);
            None
        }
    }
}

/// Expected input wlan0, wlan1, etc
/// map this to radio0, radio1 etc
/// query /etc/config/wireless for disabled flag
/// In the case of an unexpected input, we simply print an error and return None
pub fn get_radio_enabled(radio: &str) -> Option<bool> {
    let radio = radio.replace("wlan", "radio");
    let path = format!("wireless.{radio}.disabled");
    match KI.get_uci_var(&path) {
        // if disabled flag is set to '0' in config, radio is enabled so we return true and vice versa
        Ok(a) => Some(a.contains('0')),
        Err(e) => {
            error!(
                "Unable to get radio channel for radio: {} with {:?}",
                radio, e
            );
            None
        }
    }
}

/// Expected input wlan0, wlan1, etc
/// map this to radio0, radio1 etc
/// query /etc/config/wireless for channel
/// In the case of an unexpected input, we simply print an error and return None
pub fn get_radio_channel(radio: &str) -> Option<u16> {
    let radio = radio.replace("wlan", "radio");
    let path = format!("wireless.{radio}.channel");
    match KI.get_uci_var(&path) {
        Ok(a) => match a.parse::<u16>() {
            Ok(a) => Some(a),
            Err(e) => {
                error!(
                    "Unable to get radio channel for radio: {} with {:?}",
                    radio, e
                );
                None
            }
        },
        Err(e) => {
            error!(
                "Unable to get radio channel for radio: {} with {:?}",
                radio, e
            );
            None
        }
    }
}

/// Take eth speed and duplex mode and create an enum
fn get_ethernet_operation_mode(speed: u64, duplex: String) -> EthOperationMode {
    match (speed, duplex.contains("full")) {
        (40000, _) => EthOperationMode::FullDup40GBase,
        (25000, _) => EthOperationMode::FullDup25GBase,
        (10000, _) => EthOperationMode::FullDup10GBase,
        (5000, _) => EthOperationMode::FullDup5GBase,
        (1000, true) => EthOperationMode::FullDup1000MBBase,
        (1000, false) => EthOperationMode::HalfDup1000MBBase,
        (100, true) => EthOperationMode::FullDup100MBBase,
        (100, false) => EthOperationMode::HalfDup100MBBase,
        (10, true) => EthOperationMode::FullDup10GBase,
        (10, false) => EthOperationMode::HalfDup10MBBase,
        _ => EthOperationMode::Unknown,
    }
}

// Test for kernel version
#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_read_hw_info() {
        let res = get_hardware_info(Some("test".to_string()));
        let hw_info = res.unwrap();
        assert_eq!(hw_info.model, "test");
    }

    #[test]
    fn test_numcpus() {
        let res = get_numcpus();
        let cpus = res.unwrap();
        assert!(cpus != 0);
    }

    #[test]
    fn test_sensors() {
        let res = get_sensor_readings();
        println!("{res:?}");
    }

    #[test]
    fn test_ethernet_stats() {
        let res = get_ethernet_stats();
        println!("{res:?}");
    }

    #[test]
    fn test_sys_time() {
        let res = get_sys_uptime();
        let dur: Duration = res.unwrap();

        println!("{}", dur.as_secs());

        let hours = dur.as_secs() / 3600;
        let minutes = (dur.as_secs() % 3600) / 60;
        println!(
            "Hours {}, Minutes {}, Seconds {}",
            hours,
            minutes,
            (dur.as_secs() % 3600) % 60
        );
    }
    #[test]
    fn test_kernel_version_temp() {
        let res = parse_kernel_version("Linux version 4.19.78-coreos (jenkins@ip-10-7-32-103) (gcc version 8.3.0 (Gentoo Hardened 8.3.0-r1 p1.1)) #1 SMP Mon Oct 14 22:56:39 -00 2019".to_string());
        let (str1, str2) = res.unwrap();
        println!("Entire Kernel String: {str1} \nKernel String:{str2}\n\n");

        let res = parse_kernel_version("".to_string());
        let (str1, str2) = res.unwrap();
        println!("Entire Kernel String: {str1} \nKernel String:{str2}\n\n");

        let res = parse_kernel_version("Hello world".to_string());
        let (str1, str2) = res.unwrap();
        println!("Entire Kernel String: {str1} \nKernel String:{str2}\n\n");

        let res = parse_kernel_version("ã̸͙̪̖̮͖̘̼̯̱̙̮̩̝͐ḁ̶̛̘̼̥͙̰̂͆̋̓͗́͑́͛̔̏̉̈́͌̇̓͂͊̉̄̕̕͝͝ͅş̴̢͎͕̲̙̮̻̝͔̗̥̰̝͍̳͉̗̈́̅̋́ͅͅf̴̢̡̙͙̭̪̗̯͆̊̏̒͊͋̄̂͋́͌͂̃̆̽̂͛̓̌̽̒̒̐͂͘͘͘͝͝ą̷̭̬̪̀̆̇͋̂̒̅ď̵̢̢̧̛͓̜̦̻̻̜͈͎̼͇͈̖͔̼̫̻̗͉͍̻̟̙̇̉̈͐̀̈͜͜".to_string());
        let (str1, str2) = res.unwrap();

        println!("Entire Kernel String: {str1} \nKernel String:{str2}\n\n");

        let line = get_kernel_version().unwrap();
        let res = parse_kernel_version(line);
        let (str1, str2) = res.unwrap();

        println!("Entire Kernel String: {str1} \nKernel String:{str2}\n\n");
    }

    #[test]
    fn get_conntrack_info_test() {
        const MAX_PATH: &str = "/proc/sys/net/netfilter/nf_conntrack_max";
        const TABLE_COUNT_PATH: &str = "/proc/sys/net/netfilter/nf_conntrack_count";
        //const CURR_CONNS_PATH: &str = "/proc/net/nf_conntrack";

        // Cannot parse /proc/net/nf_conntrack due to permission errors on local machine

        // let curr_conn = Command::new("wc")
        // .args(&["-l", CURR_CONNS_PATH])
        // .stdout(Stdio::piped())
        // .output();

        // if curr_conn.is_err() {
        //     panic!("Unable to parse current conntrack info: {:?}", curr_conn);
        // }
        // let curr_conn = String::from_utf8(curr_conn.unwrap().stdout).unwrap();
        // let curr_conn = curr_conn.split(' ').collect::<Vec<&str>>();
        // let curr_conn = curr_conn[0];
        // let curr_conn: u32 = match curr_conn.parse() {
        //     Ok(a) => a,
        //     Err(e) => {
        //         panic!("Unable to parse conntrack info! {:?}", e);
        //     }
        // };

        // println!("Curr connections: {:?}", curr_conn);

        let table_count = match get_lines(TABLE_COUNT_PATH) {
            Ok(a) => a,
            Err(e) => {
                panic!("Unable to get table count for conntrack info!: {:?}", e);
            }
        };
        let table_count: u32 = match table_count[0].parse() {
            Ok(a) => a,
            Err(e) => {
                panic!("Cant parse table count conntrack! {:?}", e);
            }
        };

        println!("table count: {table_count:?}");

        let max_conns = match get_lines(MAX_PATH) {
            Ok(a) => a,
            Err(e) => {
                panic!("Unable to get max conntrack connections! {:?}", e);
            }
        };
        let max_conns: u32 = match max_conns[0].parse() {
            Ok(a) => a,
            Err(e) => {
                panic!("Cant parse max conntrack conns! {:?}", e);
            }
        };

        println!("Max conns: {max_conns:?}");

        // Test read lines
        println!(
            "Lines in Max_path file (should be 1): {:?}",
            BufReader::new(File::open(MAX_PATH).unwrap())
                .lines()
                .count()
        );
    }
}
