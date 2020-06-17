use std::time::Instant;
use std::time::SystemTime;

pub const SAMPLE_PERIOD: u8 = 5u8;
const SAMPLES_IN_FIVE_MINUTES: usize = 300 / SAMPLE_PERIOD as usize;

/// This is a helper struct for measuring the round trip time over the exit tunnel independently
/// from Babel. In the future, `RTTimestamps` should aid in RTT-related overadvertisement detection.
#[derive(Serialize, Deserialize, Debug)]
pub struct RTTimestamps {
    pub exit_rx: SystemTime,
    pub exit_tx: SystemTime,
}

/// Implements https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
/// to keep track of neighbor latency in an online fashion for a specific interface
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct RunningLatencyStats {
    count: u32,
    mean: f32,
    m2: f32,
    /// the lowest value we have ever seen on this link used to determine roughly what
    /// we should be expecting
    lowest: Option<f32>,
    last_value: Option<f32>,
    /// the last time this counters interface was invalidated by a change
    #[serde(skip_serializing, skip_deserializing)]
    last_changed: Option<Instant>,
}

impl RunningLatencyStats {
    pub fn new() -> RunningLatencyStats {
        RunningLatencyStats {
            count: 0u32,
            mean: 0f32,
            m2: 0f32,
            lowest: None,
            last_value: None,
            last_changed: Some(Instant::now()),
        }
    }
    pub fn get_avg(&self) -> Option<f32> {
        if self.count > 2 {
            Some(self.mean)
        } else {
            None
        }
    }
    pub fn get_std_dev(&self) -> Option<f32> {
        if self.count > 2 {
            Some(self.m2 / self.count as f32)
        } else {
            None
        }
    }
    pub fn add_sample(&mut self, sample: f32) {
        match self.count.checked_add(1) {
            Some(val) => self.count = val,
            None => self.reset(),
        }
        let delta = sample - self.mean;
        self.mean += delta / self.count as f32;
        let delta2 = sample - self.mean;
        self.m2 += delta * delta2;
        self.last_value = Some(sample);
        match self.lowest {
            Some(lowest) => {
                // fix for bad "default" where some lowest as zero's slipped in
                // TODO remove operator tools fixing hack
                if sample < lowest || lowest == 0.0 {
                    self.lowest = Some(sample)
                }
            }
            None => self.lowest = Some(sample),
        }
    }
    /// A hand tuned heuristic used to determine if a connection is bloated
    pub fn is_bloated(&self) -> bool {
        let std_dev = self.get_std_dev();
        let avg = self.get_avg();
        match (std_dev, avg) {
            // you probably don't want to touch this, yes I know it doesn't make
            // much sense from a stats perspective but here's why it works. Often
            // when links start you get a lot of transient bad states, like 2000ms
            // latency and the like. Because the history is reset in network_monitor after
            // this is triggered it doesn't immediately trigger again. The std_dev and average
            // are both high and this protects connections from rapid excessive down shaping.
            // the other key is that as things run longer the average goes down so spikes in
            // std-dev are properly responded to. This is *not* a good metric for up-shaping
            // it's too subject to not being positive when it should be whereas those false
            // negatives are probably better here.
            //
            // If for some reason you feel the need to edit this you should probably not
            // do anything until you have more than 100 or so samples and then carve out
            // exceptions for conditions like average latency under 10ms because fiber lines
            // are a different beast than the wireless connections. Do remember that exits can
            // be a lot more than 50ms away so you need to account for distant but stable connections
            // as well. This somehow does all of that at once, so here it stands
            (Some(std_dev), Some(avg)) => std_dev > 10f32 * avg && avg > 10f32,
            (_, _) => false,
        }
    }
    /// A hand tuned heuristic used to determine if a connection is good this works differently than
    /// is_bloated because false positives are less damaging. We can rate limit speed increases to once
    /// every few minutes. While making the connection stable needs to be done right away, making it faster
    /// can be done more slowly. We use a combined average and std-dev measure specifically for fiber connections
    /// lets say you have a fiber connection and it has a 2ms normal latency and then one 2 second spike, that's
    /// going throw off your std-dev essentially forever. Which is why we have the out when the average is near the
    /// lowest. On wireless links the lowest you ever see will almost always be much lower than the average, on fiber
    /// it happens all the time. Over on the wireless link side we have a much less clustered distribution so the std-dev
    /// is more stable and a good metric. With the exception of ultra-short distance wireless links, which have their own
    /// exception at <10ms
    pub fn is_good(&self) -> bool {
        let std_dev = self.get_std_dev();
        let avg = self.get_avg();
        let lowest = self.lowest;
        match (std_dev, avg, lowest) {
            (Some(std_dev), Some(avg), Some(lowest)) => {
                std_dev < 100f32 || avg < 2f32 * lowest || avg < 10f32
            }
            (_, _, _) => false,
        }
    }
    /// resets the welfords algorithm average
    pub fn reset(&mut self) {
        self.count = 0u32;
        self.mean = 0f32;
        self.m2 = 0f32;
        self.last_changed = Some(Instant::now());
    }
    pub fn set_last_changed(&mut self) {
        self.last_changed = Some(Instant::now());
    }
    pub fn last_changed(&self) -> Instant {
        self.last_changed
            .expect("Tried to get changed on a serialized counter!")
    }
    pub fn samples(&self) -> u32 {
        self.count
    }
    pub fn get_lowest(&self) -> Option<f32> {
        self.lowest
    }
}

/// Due to the way babel communicates packet loss the functions here require slightly
/// more data processing to get correct values. 'Reach' is a 16 second bitvector of hello/IHU
/// outcomes, but we're sampling every 5 seconds, in order to keep samples from interfering with
/// each other we take the top 5 bits and use that to compute packet loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningPacketLossStats {
    /// the number of packets lost during each 5 second sample period over the last five minutes
    five_minute_loss: Vec<u8>,
    /// the 'front' of the looping five minute sample queue
    front: usize,
    /// Total packets observed since the system was started
    total_packets: u32,
    /// Total packets observed to be lost since the system was started
    total_lost: u32,
}

impl Default for RunningPacketLossStats {
    fn default() -> Self {
        let mut new = Vec::with_capacity(SAMPLES_IN_FIVE_MINUTES);
        new.extend_from_slice(&[0; SAMPLES_IN_FIVE_MINUTES]);
        RunningPacketLossStats {
            five_minute_loss: new,
            front: 0usize,
            total_packets: 0u32,
            total_lost: 0u32,
        }
    }
}

impl RunningPacketLossStats {
    pub fn new() -> RunningPacketLossStats {
        RunningPacketLossStats::default()
    }
    pub fn add_sample(&mut self, sample: u16) {
        // handles when 'default' was miscalled, this should be safe to remove
        // TODO remove operator tools fixing hack
        if self.five_minute_loss.is_empty() {
            let mut new = Vec::with_capacity(SAMPLES_IN_FIVE_MINUTES);
            new.extend_from_slice(&[0; SAMPLES_IN_FIVE_MINUTES]);
            self.five_minute_loss = new;
        }

        // babel displays a 16 second window of hellos, so adjust this based on
        // any changes in run rate of this function
        let lost_packets = SAMPLE_PERIOD - get_first_n_set_bits(sample, SAMPLE_PERIOD);
        match self.total_lost.checked_add(u32::from(lost_packets)) {
            Some(val) => self.total_lost = val,
            None => {
                self.total_packets = 0;
                self.total_lost = 0;
            }
        }
        match self.total_packets.checked_add(u32::from(SAMPLE_PERIOD)) {
            Some(val) => self.total_packets = val,
            None => {
                self.total_packets = 0;
                self.total_lost = 0;
            }
        }
        self.five_minute_loss[self.front] = lost_packets;
        self.front = (self.front + 1) % SAMPLES_IN_FIVE_MINUTES;
    }
    pub fn get_avg(&self) -> Option<f32> {
        if self.total_packets > 0 {
            Some(self.total_lost as f32 / self.total_packets as f32)
        } else {
            None
        }
    }
    pub fn get_five_min_average(&self) -> f32 {
        let total_packets = SAMPLES_IN_FIVE_MINUTES * SAMPLE_PERIOD as usize;
        if total_packets > 0 {
            let sum_loss: usize = self.five_minute_loss.iter().map(|i| *i as usize).sum();
            sum_loss as f32 / total_packets as f32
        } else {
            0.0
        }
    }
    pub fn get_count(&self) -> u32 {
        self.total_packets
    }
    pub fn get_lost(&self) -> u32 {
        self.total_lost
    }
}

/// Counts the number of bits set to 1 in the first n bits (reading left to right so MSB first) of
/// the 16 bit bitvector
fn get_first_n_set_bits(sample: u16, n: u8) -> u8 {
    assert!(n <= 16);
    let mut mask = 0b1000_0000_0000_0000;
    let mut total_set_bits = 0u8;
    for i in ((16 - n)..16).rev() {
        // println!(
        //     "{:#b} {:#b} >> {} {:#b}",
        //     mask,
        //     sample & mask,
        //     i,
        //     ((sample & mask) >> i)
        // );
        total_set_bits += ((sample & mask) >> i) as u8;
        mask >>= 1;
    }
    total_set_bits
}

pub fn has_packet_loss(sample: u16) -> bool {
    let lost_packets = SAMPLE_PERIOD - get_first_n_set_bits(sample, SAMPLE_PERIOD);
    lost_packets > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_first_n_set_bits() {
        let count = get_first_n_set_bits(0b1110_0000_0000_0000, 5);
        assert_eq!(count, 3);
    }
    #[test]
    fn test_get_first_n_set_bits_limit() {
        let count = get_first_n_set_bits(0b1111_1100_0000_0000, 5);
        assert_eq!(count, 5);
    }
    #[test]
    fn test_get_first_n_set_bits_lower_bits() {
        let count = get_first_n_set_bits(0b1110_0000_0000_1100, 5);
        assert_eq!(count, 3);
    }
    #[test]
    fn test_get_first_n_set_bits_lower_longer_range() {
        let count = get_first_n_set_bits(0b1110_0000_0000_1100, 16);
        assert_eq!(count, 5);
    }
    #[test]
    fn test_all_set() {
        let count = get_first_n_set_bits(0b1111_1111_1111_1111, 16);
        assert_eq!(count, 16);
    }
    #[test]
    #[should_panic]
    fn test_get_first_n_set_bits_impossible() {
        let _count = get_first_n_set_bits(0b1110_0000_0000_1100, 32);
    }

    #[test]
    fn test_rtt_increment() {
        let mut stats = RunningLatencyStats::new();
        stats.add_sample(0.12);
        assert_eq!(stats.samples(), 1);
    }

    #[test]
    fn test_packet_loss_increment() {
        let mut stats = RunningPacketLossStats::new();
        stats.add_sample(0);
        assert_eq!(stats.get_count(), SAMPLE_PERIOD as u32);
        assert_eq!(stats.get_lost(), SAMPLE_PERIOD as u32);
    }
}
