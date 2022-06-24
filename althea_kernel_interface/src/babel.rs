use crate::KernelInterface;

impl dyn KernelInterface {
    pub fn restart_babel(&self) {
        let _res = self.run_command("/etc/init.d/babeld", &["restart"]);
    }
}
