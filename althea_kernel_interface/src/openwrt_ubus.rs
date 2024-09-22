use crate::{run_command, KernelInterfaceError};

/// calls a ubus rpc
pub fn ubus_call(
    namespace: &str,
    function: &str,
    argument: &str,
) -> Result<String, KernelInterfaceError> {
    let output =
        String::from_utf8(run_command("ubus", &["call", namespace, function, argument])?.stdout)?;
    Ok(output)
}
