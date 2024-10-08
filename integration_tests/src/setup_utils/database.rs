use althea_kernel_interface::run_command;
use diesel::{Connection, PgConnection};
use log::warn;
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
    const POSTGRES_14_BIN: &str = "/usr/lib/postgresql/14/bin/postgres";
    const POSTGRES_16_BIN: &str = "/usr/lib/postgresql/16/bin/postgres";
    const INITDB_14_BIN: &str = "/usr/lib/postgresql/14/bin/initdb";
    const INITDB_16_BIN: &str = "/usr/lib/postgresql/16/bin/initdb";
    let postgres_bin = if Path::new(POSTGRES_14_BIN).exists() {
        POSTGRES_14_BIN
    } else if Path::new(POSTGRES_16_BIN).exists() {
        POSTGRES_16_BIN
    } else {
        panic!("Could not find postgres binary")
    };
    let initdb_bin = if Path::new(INITDB_14_BIN).exists() {
        INITDB_14_BIN
    } else if Path::new(INITDB_16_BIN).exists() {
        INITDB_16_BIN
    } else {
        panic!("Could not find initdb binary")
    };

    // for this test script
    const DB_URL_LOCAL: &str = "postgres://postgres@127.0.0.1/test";
    // for the rita exit instances
    const POSTGRES_DATABASE_LOCATION: &str = "/var/lib/postgresql/data";
    let migration_directory_a =
        Path::new("/althea_rs/integration_tests/src/setup_utils/migrations/");
    let migration_directory_b = Path::new("integration_tests/src/setup_utils/migrations/");
    let migration_directory = if migration_directory_a.exists() {
        migration_directory_a
    } else if migration_directory_b.exists() {
        migration_directory_b
    } else {
        panic!("Could not find migrations directory")
    };
    let postgres_pid_path: String = format!("{}/postmaster.pid", POSTGRES_DATABASE_LOCATION);

    // only init and launch if postgres has not already been started
    if !Path::new(&postgres_pid_path).exists() {
        // initialize the db datadir
        let res = run_command(
            "sudo",
            &[
                "-u",
                POSTGRES_USER,
                initdb_bin,
                "-D",
                POSTGRES_DATABASE_LOCATION,
            ],
        )
        .unwrap();
        if !res.status.success() {
            panic!("Failed to init postgres {:?}", res);
        }

        // create the pg_hba.conf with auth for the 10.0.0.1 routers
        let pg_hba_path = format!("{}/pg_hba.conf", POSTGRES_DATABASE_LOCATION);
        let mut pg_hba = File::create(pg_hba_path).unwrap();
        let pb_hba_lines: [&str; 4] = [
            "local   all all trust",
            "host   all all 10.0.0.1/16 trust",
            "host   all all 127.0.0.1/32 trust",
            "host   all all ::1/128 trust",
        ];
        for line in pb_hba_lines {
            writeln!(pg_hba, "{}", line).unwrap()
        }
    }
    info!("Starting postgres");
    // start postgres in it's own thread, we kill it every time we startup
    // so it's spawned in this context
    thread::spawn(move || {
        let res = run_command(
            "sudo",
            &[
                "-u",
                POSTGRES_USER,
                postgres_bin,
                "-D",
                POSTGRES_DATABASE_LOCATION,
            ],
        )
        .unwrap();
        panic!("Postgres has crashed {:?}", res);
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
        run_command("psql", &["-c", "drop database test;", "-U", POSTGRES_USER]).unwrap();
        run_command(
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
