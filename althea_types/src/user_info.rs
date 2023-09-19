use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::SystemTime;

/// Contains all the data you need for an American mailing address
/// hopefully also compatible with a few other countries
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MailingAddress {
    /// full string country name including spaces
    pub country: String,
    /// postal code, in whatever the local format is
    pub postal_code: String,
    /// State, country may not contain states so optional
    pub state: Option<String>,
    pub city: String,
    pub street: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
/// This struct contains details about the users billing address
/// name, etc. It does not duplicate ContactType and does not store
/// direct contact info like phone or email
pub struct BillingDetails {
    /// The users first name
    pub user_first_name: String,
    /// The users last name
    pub user_last_name: String,
    /// The mailing address of this installation, assumed to be in whatever
    /// format the local nation has for addresses. Optional as this install
    /// may not have a formal mailing address
    pub mailing_address: MailingAddress,
    #[serde(default)]
    pub sequence_number: u32,
}

/// Struct for storing details about this user installation. This particular
/// struct exists in the settings on the router because it has to be persisted
/// long enough to make it to the operator tools, once it's been uploaded though
/// it has no reason to hand around and is mostly dead weight in the config. The
/// question is if we want to delete it or manage it somehow.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct InstallationDetails {
    /// The CPE ip of this client. This field seems straightforward but actually
    /// has quite a bit of optionality. What if the user is connected via l2 bridge
    /// (for example a cable, or fiber) in that case this could be None. If the client
    /// is multihomed which ip is the client antenna and which one is the relay antenna?
    /// That can be decided randomly without any problems I think.
    pub client_antenna_ip: Option<Ipv4Addr>,
    /// A list of addresses for relay antennas, this could include sectors and/or
    /// point to point links going downstream. If the vec is empty there are no
    /// relay antennas
    pub relay_antennas: Vec<Ipv4Addr>,
    /// The address of this installation, this has no structure and should
    /// simply be displayed. Depending on the country address formats will
    /// be very different and we might even only have GPS points
    /// will only exist if mailing address over in contact info is blank
    pub physical_address: Option<String>,
    /// Description of the installation and equipment at the
    /// location
    pub equipment_details: String,
    /// Time of install, this is set by the operator tools when it accepts
    /// the value because the router system clocks may be problematic.
    pub install_date: Option<SystemTime>,
}

/// The old storage method for usage tracker data that stores flat data
/// in arrays and does not index the data via hashmap this format was abandoned
/// as error prone but is still used so legacy routers can send data
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageTrackerFlat {
    pub last_save_hour: u64,
    pub client_bandwidth: VecDeque<IndexedUsageHour>,
    pub relay_bandwidth: VecDeque<IndexedUsageHour>,
}

/// A struct for tracking each hour of usage, indexed by time in hours since
/// the unix epoch.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct IndexedUsageHour {
    pub index: u64,
    pub up: u64,
    pub down: u64,
    pub price: u32,
}

/// A struct used to store data usage over an arbitrary period the length of time
/// is implied by the code that is handling this struct. Do not transfer without considering
/// that you may be changing units
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Usage {
    pub up: u64,
    pub down: u64,
    pub price: u32,
}

/// The main actor that holds the usage state for the duration of operations
/// to be sent up to ops tools.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageTrackerTransfer {
    /// client bandwidth usage per hour indexd by unix timestamp in hours
    pub client_bandwidth: HashMap<u64, Usage>,
    /// relay bandwidth usage per hour indexd by unix timestamp in hours
    pub relay_bandwidth: HashMap<u64, Usage>,
    /// exit bandwidth usage per hour indexd by unix timestamp in hours
    pub exit_bandwidth: HashMap<u64, Usage>,
}

impl UsageTrackerTransfer {
    /// gets the greatest index currently stored in this struct which represents
    /// the last saved usage hour
    pub fn last_save_hour(&self) -> u64 {
        let mut highest = 0;
        let iter = vec![
            &self.client_bandwidth,
            &self.relay_bandwidth,
            &self.exit_bandwidth,
        ];
        for data in iter {
            for i in data.keys() {
                highest = highest.max(*i);
            }
        }
        highest
    }
}

impl From<UsageTrackerFlat> for UsageTrackerTransfer {
    fn from(value: UsageTrackerFlat) -> Self {
        UsageTrackerTransfer {
            client_bandwidth: convert_flat_to_map_usage_data(value.client_bandwidth),
            relay_bandwidth: convert_flat_to_map_usage_data(value.relay_bandwidth),
            exit_bandwidth: HashMap::new(),
        }
    }
}

/// Used to convert between usage tracker storage formats
pub fn convert_flat_to_map_usage_data(input: VecDeque<IndexedUsageHour>) -> HashMap<u64, Usage> {
    let mut out = HashMap::new();
    for hour in input {
        match out.get_mut(&hour.index) {
            // we have a duplicate entry which we must correct, pick the higher data usage and keep that
            Some(to_edit) => {
                let duplicate_usage: Usage = *to_edit;
                to_edit.up = std::cmp::max(duplicate_usage.up, hour.up);
                to_edit.down = std::cmp::max(duplicate_usage.down, hour.down);
                to_edit.price = std::cmp::max(duplicate_usage.price, hour.price);
            }
            None => {
                out.insert(
                    hour.index,
                    Usage {
                        up: hour.up,
                        down: hour.down,
                        price: hour.price,
                    },
                );
            }
        }
    }
    out
}

/// Used to convert between usage tracker storage formats
pub fn convert_map_to_flat_usage_data(input: HashMap<u64, Usage>) -> VecDeque<IndexedUsageHour> {
    let mut out = VecDeque::new();
    for (hour, usage) in input {
        out.push_back(IndexedUsageHour {
            index: hour,
            up: usage.up,
            down: usage.down,
            price: usage.price,
        })
    }
    // we want this sorted from greatest to least so we do the cmp in reverse order
    out.make_contiguous().sort_by(|a, b| b.index.cmp(&a.index));
    out
}
