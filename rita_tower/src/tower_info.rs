// use crate::errors::TowerError as Error;
// use crate::structs::RitaTowerInfo;

// use std::fs::File;
// use std::io::BufRead;
// use std::io::BufReader;
// use std::time::Duration;
// use std::u64;

// fn get_rita_tower_info() -> Result<RitaTowerInfo, Error> {
//     let connected_enbs = parse_connected_enbs()?;
//     let connected_ues = parse_connected_ues()?;
//     let attached_ues = parse_attached_ues()?;
//     let mme_start_time = get_mme_start_time()?;
//     let sgwc_start_time = get_sgwc_start_time()?;
//     let sgwu_start_time = get_sgwu_start_time()?;
//     let smf_start_time = get_smf_start_time()?;
//     let upf_start_time = get_upf_start_time()?;

//     Ok(RitaTowerInfo {
//         connected_enbs,
//         connected_ues,
//         attached_ues,
//         mme_start_time,
//         sgwc_start_time,
//         sgwu_start_time,
//         smf_start_time,
//         upf_start_time,
//     })
// }

// fn parse_connected_enbs() -> Result<f32, Error> {
//     let connected_enbs_error = Err(Error::FailedToGetEnbsError);

//     let lines = get_lines("/tmp/open5gs/connected_enbs")?;
//     let line = match lines.get(0) {
//         Some(line) => line,
//         None => return connected_enbs_error,
//     };

//     let mut iter = line.split_whitespace();
//     let connected_enbs: f32 = match iter.next() {
//         Some(val) => val.parse()?,
//         None => return connected_enbs_error,
//     };

//     Ok(connected_enbs)
// }
// fn parse_connected_ues() -> Result<f32, Error> {
//     let connected_ues_error = Err(Error::FailedToGetConnectedUesError);

//     let lines = get_lines("/tmp/open5gs/connected_ues")?;
//     let line = match lines.get(0) {
//         Some(line) => line,
//         None => return connected_ues_error,
//     };

//     let mut iter = line.split_whitespace();
//     let connected_ues: f32 = match iter.next() {
//         Some(val) => val.parse()?,
//         None => return connected_ues_error,
//     };

//     Ok(connected_ues)
// }
// fn parse_attached_ues() -> Result<f32, Error> {
//     let attached_ues_error = Err(Error::FailedToGetAttachedUesError);

//     let lines = get_lines("/tmp/open5gs/attached_ues")?;
//     let line = match lines.get(0) {
//         Some(line) => line,
//         None => return attached_ues_error,
//     };

//     let mut iter = line.split_whitespace();
//     let attached_ues: f32 = match iter.next() {
//         Some(val) => val.parse()?,
//         None => return attached_ues_error,
//     };

//     Ok(attached_ues)
// }

// fn parse_uptime(lines: Vec<String>) -> Result<Duration, Error> {
//     let uptime_error = Err(Error::FailedToGetUptime);

//     let line = match lines.get(1) {
//         Some(line) => line,
//         None => return uptime_error,
//     };

//     let mut iter = line.split_whitespace();

//     let uptime: u64 = match iter.next() {
//         Some(val) => val.parse()?,
//         None => return uptime_error,
//     };

//     Ok(Duration::new(uptime, 0))
// }

// fn get_mme_start_time() -> Result<Duration, Error> {
//     let lines = get_lines("/tmp/open5gs/mme_start_time")?;

//     let mme_start_time = parse_uptime(lines)?;

//     Ok(mme_start_time)
// }
// fn get_sgwc_start_time() -> Result<Duration, Error> {
//     let lines = get_lines("/tmp/open5gs/sgwc_start_time")?;

//     let sgwc_start_time = parse_uptime(lines)?;

//     Ok(sgwc_start_time)
// }
// fn get_sgwu_start_time() -> Result<Duration, Error> {
//     let lines = get_lines("/tmp/open5gs/sgwu_start_time")?;

//     let sgwu_start_time = parse_uptime(lines)?;

//     Ok(sgwu_start_time)
// }
// fn get_smf_start_time() -> Result<Duration, Error> {
//     let lines = get_lines("/tmp/open5gs/smf_start_time")?;

//     let smf_start_time = parse_uptime(lines)?;

//     Ok(smf_start_time)
// }
// fn get_upf_start_time() -> Result<Duration, Error> {
//     let lines = get_lines("/tmp/open5gs/upf_start_time")?;

//     let upf_start_time = parse_uptime(lines)?;

//     Ok(upf_start_time)
// }

// pub fn get_lines(filename: &str) -> Result<Vec<String>, Error> {
//     let f = File::open(filename)?;
//     let file = BufReader::new(&f);
//     let mut out_lines = Vec::new();
//     for line in file.lines() {
//         match line {
//             Ok(val) => out_lines.push(val),
//             Err(_) => break,
//         }
//     }

//     Ok(out_lines)
// }
// // Test for rita_tower
// #[cfg(test)]
// mod test {
//     use crate::tower_info::{
//         get_mme_start_time, get_sgwc_start_time, get_sgwu_start_time, get_smf_start_time,
//         get_upf_start_time, parse_attached_ues, parse_connected_enbs, parse_connected_ues,
//     };

//     //use super::get_rita_tower_info;
//     // #[test]
//     // fn test_get_rita_tower_info() {
//     //     let res = get_rita_tower_info();
//     //     println!("{:?}", res)
//     // }
//     #[test]
//     fn test_parse_connected_enbs() {
//         let res = parse_connected_enbs();
//         println!("{:?}", res)
//     }
//     #[test]
//     fn test_connected_ues() {
//         let res = parse_connected_ues();
//         println!("{:?}", res)
//     }
//     #[test]
//     fn test_attached_ues() {
//         let res = parse_attached_ues();
//         println!("{:?}", res)
//     }

//     #[test]
//     fn test_all_uptime() {
//         test_mme_start_time();
//         test_sgwc_start_time();
//         test_sgwu_start_time();
//         test_smf_start_time();
//         test_upf_start_time();
//     }
//     fn test_mme_start_time() {
//         let res = get_mme_start_time().unwrap();
//         println!("{:?}", res.as_secs());
//     }
//     fn test_sgwc_start_time() {
//         let res = get_sgwc_start_time().unwrap();
//         println!("{:?}", res.as_secs());
//     }
//     fn test_sgwu_start_time() {
//         let res = get_sgwu_start_time().unwrap();
//         println!("{:?}", res.as_secs());
//     }
//     fn test_smf_start_time() {
//         let res = get_smf_start_time().unwrap();
//         println!("{:?}", res.as_secs());
//     }
//     fn test_upf_start_time() {
//         let res = get_upf_start_time().unwrap();
//         println!("{:?}", res.as_secs());
//     }
// }
