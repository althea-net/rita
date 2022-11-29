use diesel::dsl::delete;
use diesel::*;
use exit_db::schema;

use crate::database::database_tools::get_database_connection;
use crate::RitaExitError;

pub fn truncate_db_tables() -> Result<(), Box<RitaExitError>> {
    use self::schema::clients::dsl::*;
    info!("Deleting all clients in database");
    let connection = get_database_connection()?;
    (delete(clients).execute(&connection).unwrap());

    Ok(())
}
