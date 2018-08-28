use super::KernelInterface;

impl KernelInterface {
    /// Returns a bool based on device state, "UP" or "DOWN", "UNKNOWN" is
    /// interpreted as DOWN
    pub fn is_iface_up(&self, dev: &str) -> Option<bool> {
        let output = self
            .run_command("ip", &["addr", "show", "dev", dev])
            .unwrap();

        // Get the first line, check if it has state "UP"
        match String::from_utf8(output.stdout) {
            Ok(stdout) => match stdout.lines().next() {
                Some(line) => Some(line.contains("state UP")),
                _ => None,
            },
            _ => None,
        }
    }
}
