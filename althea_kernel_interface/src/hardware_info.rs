use crate::file_io::get_lines;
use althea_types::HardwareInfo;
use failure::Error;

/// Gets the load average and memory of the system from /proc should be plenty
/// efficient and safe to run. Requires the device name to be passed in because
/// it's stored in settings and I don't see why we should parse it here
/// things that might be interesting to add here are CPU arch and system temp sadly
/// both are rather large steps up complexity wise to parse due to the lack of consistent
/// formatting
pub fn get_hardware_info(device_name: Option<String>) -> Result<HardwareInfo, Error> {
    // cpu load average
    let load_average_error = Err(format_err!("Failed to get load average"));
    let lines = get_lines("/proc/loadavg")?;
    let load_avg = match lines.iter().next() {
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

    // memory info
    let lines = get_lines("/proc/meminfo")?;
    let mut lines = lines.iter();
    let memory_info_error = Err(format_err!("Failed to get memory info"));
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
    let model = match device_name {
        Some(name) => name,
        None => "Unknown Device".to_string(),
    };

    Ok(HardwareInfo {
        load_avg_one_minute: one_minute_load_avg,
        load_avg_five_minute: five_minute_load_avg,
        load_avg_fifteen_minute: fifteen_minute_load_avg,
        system_memory: mem_total,
        allocated_memory: mem_free,
        model,
    })
}

#[test]
fn test_read_hw_info() {
    let res = get_hardware_info(Some("test".to_string()));
    let hw_info = res.unwrap();
    assert_eq!(hw_info.model, "test");
}
