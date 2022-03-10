use crate::file_io::get_lines;
use crate::KernelInterfaceError as Error;
use althea_types::extract_wifi_station_data;
use althea_types::extract_wifi_survey_data;
use althea_types::EthOperationMode;
use althea_types::EthernetStats;
use althea_types::HardwareInfo;
use althea_types::SensorReading;
use althea_types::WifiDevice;
use althea_types::WifiStationData;
use althea_types::WifiSurveyData;
use std::fs;
use std::process::Command;
use std::process::Stdio;
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
    })
}

fn get_kernel_version() -> Result<String, Error> {
    let sys_kernel_ver_error = Err(Error::FailedToGetSystemKernelVersion);

    let lines = get_lines("/proc/version")?;
    let line = match lines.get(0) {
        Some(line) => line,
        None => return sys_kernel_ver_error,
    };
    Ok(line.to_string())
}

fn parse_kernel_version(line: String) -> Result<(String, String), Error> {
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
    let line = match lines.get(0) {
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
    let load_avg = match lines.get(0) {
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

fn get_memory_info() -> Result<(u64, u64), Error> {
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
            let var_name = line.get(0);
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

fn maybe_get_single_line_string(path: &str) -> Option<String> {
    match get_lines(path) {
        Ok(line) => line.get(0).map(|val| val.to_string()),
        Err(_e) => None,
    }
}

fn get_sensor_readings() -> Option<Vec<SensorReading>> {
    // sensors are zero indexed and there will never be gaps
    let mut sensor_num = 0;
    let mut ret = Vec::new();
    let mut path = format!("/sys/class/hwmon/hwmon{}", sensor_num);
    while fs::metadata(path.clone()).is_ok() {
        if let (Some(reading), Some(name)) = (
            maybe_get_single_line_u64(&format!("{}/temp1_input", path)),
            maybe_get_single_line_string(&format!("{}/name", path)),
        ) {
            ret.push(SensorReading {
                name,
                reading,
                min: maybe_get_single_line_u64(&format!("{}/temp1_min", path)),
                crit: maybe_get_single_line_u64(&format!("{}/temp1_crit", path)),
                max: maybe_get_single_line_u64(&format!("{}/temp1_max", path)),
            });
        }

        sensor_num += 1;
        path = format!("/sys/class/hwmon/hwmon{}", sensor_num);
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
    let mut path = format!("/sys/class/net/eth{}", eth);
    while fs::metadata(path.clone()).is_ok() {
        if let Some(is_up) = maybe_get_single_line_string(&format!("{}/operstate", path)) {
            let is_up = is_up.contains("up");
            if let (Some(speed), Some(duplex)) = (
                maybe_get_single_line_u64(&format!("{}/speed", path)),
                maybe_get_single_line_string(&format!("{}/duplex", path)),
            ) {
                if let (
                    Some(tx_errors),
                    Some(rx_errors),
                    Some(tx_packet_count),
                    Some(rx_packet_count),
                ) = (
                    maybe_get_single_line_u64(&format!("{}/statistics/tx_errors", path)),
                    maybe_get_single_line_u64(&format!("{}/statistics/rx_errors", path)),
                    maybe_get_single_line_u64(&format!("{}/statistics/tx_packets", path)),
                    maybe_get_single_line_u64(&format!("{}/statistics/rx_packets", path)),
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
        path = format!("/sys/class/net/eth{}", eth);
    }

    if ret.is_empty() {
        None
    } else {
        Some(ret)
    }
}

fn get_wifi_devices() -> Vec<WifiDevice> {
    let mut ret: Vec<WifiDevice> = Vec::new();
    //get devices
    let devices = parse_wifi_device_names();
    if devices.is_err() {
        warn!("Unable to get wifi devices: {:?}", devices);
        return Vec::new();
    }

    for dev in devices.unwrap() {
        let device = WifiDevice {
            name: dev.clone(),
            survey_data: get_wifi_survey_info(&dev),
            station_data: get_wifi_station_info(&dev),
        };
        info!("Created the following wifi struct: {:?}", device.clone());
        ret.push(device);
    }

    ret
}

fn parse_wifi_device_names() -> Result<Vec<String>, Error> {
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

fn get_wifi_survey_info(dev: &str) -> Vec<WifiSurveyData> {
    let res = Command::new("iw")
        .args(&[dev, "survey", "dump"])
        .stdout(Stdio::piped())
        .output();

    if res.is_err() {
        error!("Unable to run survey dump {:?}", res);
        return Vec::new();
    }
    let res = String::from_utf8(res.unwrap().stdout).unwrap();
    extract_wifi_survey_data(&res, dev)
}

fn get_wifi_station_info(dev: &str) -> Vec<WifiStationData> {
    let res = Command::new("iw")
        .args(&[dev, "station", "dump"])
        .stdout(Stdio::piped())
        .output();

    if res.is_err() {
        error!("Unable to run station dump {:?}", res);
        return Vec::new();
    }

    let res = String::from_utf8(res.unwrap().stdout).unwrap();
    extract_wifi_station_data(&res)
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
        println!("{:?}", res);
    }

    #[test]
    fn test_ethernet_stats() {
        let res = get_ethernet_stats();
        println!("{:?}", res);
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
        println!(
            "Entire Kernel String: {} \nKernel String:{}\n\n",
            str1, str2
        );

        let res = parse_kernel_version("".to_string());
        let (str1, str2) = res.unwrap();
        println!(
            "Entire Kernel String: {} \nKernel String:{}\n\n",
            str1, str2
        );

        let res = parse_kernel_version("Hello world".to_string());
        let (str1, str2) = res.unwrap();
        println!(
            "Entire Kernel String: {} \nKernel String:{}\n\n",
            str1, str2
        );

        let res = parse_kernel_version("ã̸͙̪̖̮͖̘̼̯̱̙̮̩̝͐ḁ̶̛̘̼̥͙̰̂͆̋̓͗́͑́͛̔̏̉̈́͌̇̓͂͊̉̄̕̕͝͝ͅş̴̢͎͕̲̙̮̻̝͔̗̥̰̝͍̳͉̗̈́̅̋́ͅͅf̴̢̡̙͙̭̪̗̯͆̊̏̒͊͋̄̂͋́͌͂̃̆̽̂͛̓̌̽̒̒̐͂͘͘͘͝͝ą̷̭̬̪̀̆̇͋̂̒̅ď̵̢̢̧̛͓̜̦̻̻̜͈͎̼͇͈̖͔̼̫̻̗͉͍̻̟̙̇̉̈͐̀̈͜͜".to_string());
        let (str1, str2) = res.unwrap();

        println!(
            "Entire Kernel String: {} \nKernel String:{}\n\n",
            str1, str2
        );

        let line = get_kernel_version().unwrap();
        let res = parse_kernel_version(line);
        let (str1, str2) = res.unwrap();

        println!(
            "Entire Kernel String: {} \nKernel String:{}\n\n",
            str1, str2
        );
    }
}
