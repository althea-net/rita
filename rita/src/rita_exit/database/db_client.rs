use crate::rita_exit::database::get_database_connection;
use ::actix::prelude::SystemService;
use ::actix_web::Result;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Supervised;
use diesel;
use diesel::dsl::*;
use diesel::prelude::*;
use exit_db::schema;
use failure::Error;

#[derive(Default)]
pub struct DbClient;

impl Actor for DbClient {
    type Context = Context<Self>;
}

impl Supervised for DbClient {}
impl SystemService for DbClient {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("DB Client started");
    }
}

pub struct TruncateTables;
impl Message for TruncateTables {
    type Result = Result<(), Error>;
}

impl Handler<TruncateTables> for DbClient {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: TruncateTables, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::*;
        info!("Deleting all clients in database");
        let connection = get_database_connection()?;
        r#try!(delete(clients).execute(&connection));
        Ok(())
    }
}
