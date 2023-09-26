use althea_kernel_interface::KI;
use diesel::{Connection, PgConnection};
use log::{error, warn};
use std::io::Write;
use std::{
    fs::File,
    io::stdout,
    path::Path,
    thread,
    time::{Duration, Instant},
};

/// Starts the exit postgres instance in the native system namespace, TODO insert plumbing so that exits can reach it
pub fn start_postgres() {
    const POSTGRES_USER: &str = "postgres";
    const POSTGRES_BIN: &str = "/usr/lib/postgresql/16/bin/postgres";
    const INITDB_BIN: &str = "/usr/lib/postgresql/16/bin/initdb";
    // for this test script
    const DB_URL_LOCAL: &str = "postgres://postgres@127.0.0.1/test";
    // for the rita exit instances
    const POSTGRES_DATABASE_LOCATION: &str = "/var/lib/postgresql/data";
    let migration_directory = Path::new("/althea_rs/integration_tests/src/setup_utils/migrations/");
    let postgres_pid_path: String = format!("{}/postmaster.pid", POSTGRES_DATABASE_LOCATION);

    // only init and launch if postgres has not already been started
    if !Path::new(&postgres_pid_path).exists() {
        // initialize the db datadir
        KI.run_command(
            "sudo",
            &[
                "-u",
                POSTGRES_USER,
                INITDB_BIN,
                "-D",
                POSTGRES_DATABASE_LOCATION,
            ],
        )
        .unwrap();

        // create the pg_hba.conf with auth for the 10.0.0.1 routers
        let pg_hba_path = format!("{}/pg_hba.conf", POSTGRES_DATABASE_LOCATION);
        let mut pg_hba = File::create(pg_hba_path).unwrap();
        let pb_hba_lines: [&str; 3] = [
            "local   all all trust",
            "host   all all 10.0.0.1/16 trust",
            "host   all all 127.0.0.1/32 trust",
        ];
        for line in pb_hba_lines {
            writeln!(pg_hba, "{}", line).unwrap()
        }
    }
    // start postgres in it's own thread, we kill it every time we startup
    // so it's spawned in this context
    thread::spawn(move || {
        let res = KI
            .run_command(
                "sudo",
                &[
                    "-u",
                    POSTGRES_USER,
                    POSTGRES_BIN,
                    "-D",
                    POSTGRES_DATABASE_LOCATION,
                ],
            )
            .unwrap();
        error!("Postgres has crashed {:?}", res);
    });

    // create connection to the now started database
    let mut conn = PgConnection::establish(DB_URL_LOCAL);
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
    let start = Instant::now();
    while let Err(e) = conn {
        warn!("Waiting for db to start {:?}", e);
        if Instant::now() - start > STARTUP_TIMEOUT {
            panic!("Postgres did not start! {:?}", e);
        }

        // reset database contents for every run, this is in the loop becuase it too must wait until the db has started
        KI.run_command("psql", &["-c", "drop database test;", "-U", POSTGRES_USER])
            .unwrap();
        KI.run_command(
            "psql",
            &["-c", "create database test;", "-U", POSTGRES_USER],
        )
        .unwrap();

        conn = PgConnection::establish(DB_URL_LOCAL);
        thread::sleep(Duration::from_millis(1000));
    }
    let conn = conn.unwrap();

    // run diesel migrations
    diesel_migrations::run_pending_migrations_in_directory(
        &conn,
        migration_directory,
        &mut stdout(),
    )
    .unwrap();
}
