use crate::file_io::get_lines;
use crate::KernelInterfaceError as Error;
use althea_types::HardwareInfo;
use althea_types::SensorReading;
use std::fs;

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

    Ok(HardwareInfo {
        logical_processors: num_cpus,
        load_avg_one_minute: one_minute_load_avg,
        load_avg_five_minute: five_minute_load_avg,
        load_avg_fifteen_minute: fifteen_minute_load_avg,
        system_memory: mem_total,
        allocated_memory,
        model,
        sensor_readings,
    })
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
        Ok(line) => match line.get(0) {
            Some(val) => Some(val.to_string()),
            None => None,
        },
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
    assert!(res.is_some());
}
