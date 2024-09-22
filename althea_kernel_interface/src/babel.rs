use crate::run_command;

pub fn restart_babel() {
    let _res = run_command("/etc/init.d/babeld", &["restart"]);
}
