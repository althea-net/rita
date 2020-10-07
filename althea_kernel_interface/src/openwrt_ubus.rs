use crate::KernelInterface;
use crate::KernelInterfaceError;

impl dyn KernelInterface {
    /// calls a ubus rpc
    pub fn ubus_call(
        &self,
        namespace: &str,
        function: &str,
        argument: &str,
    ) -> Result<String, KernelInterfaceError> {
        let output = String::from_utf8(
            self.run_command("ubus", &["call", namespace, function, argument])?
                .stdout,
        )?;
        Ok(output)
    }
}
