use althea_kernel_interface::run_command;
use log::info;
use std::{fs::remove_file, path::Path, thread, time::Duration};

/// Spawn a thread for rita given a NamespaceInfo which will be assigned to the namespace given
pub fn spawn_babel(ns: String, babelconf_path: String, babeld_path: String) {
    // create a thread, set the namespace of that thread, spawn babel, then join the thread
    // so that we don't move on until babel is started
    let _babel_handler = thread::spawn(move || {
        let pid_path = format!("/var/run/babeld-{ns}.pid");
        // if babel has previously been running in this container it won't start
        // unless the pid file is deleted since that will indicate another instance
        // of babel is running
        let _ = remove_file(pid_path.clone());
        let babeld_pid = pid_path;
        let babeld_log = format!("/var/log/babeld-{ns}.log");
        // 1 here is for log
        let res = run_command(
            "ip",
            &[
                "netns",
                "exec",
                &ns,
                &babeld_path,
                "-I",
                &babeld_pid,
                "-d",
                "1",
                "-r",
                "-L",
                &babeld_log,
                "-H",
                "1",
                "-G",
                "6872",
                "-w",
                "lo",
                "-c",
                &babelconf_path,
                "-D",
            ],
        );
        info!("res of babel {res:?}");
        // waits for babel to finish starting up and create it's pid file
        while !Path::new(&babeld_pid).exists() {
            thread::sleep(Duration::from_millis(100));
        }
    })
    .join();
}
