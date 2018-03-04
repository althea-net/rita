use diesel;
use actix_web::*;
use actix::prelude::*;
use diesel::prelude::*;

use exit_db::{models, schema};

use SETTING;

use failure::Error;

#[derive(Default)]
pub struct DbClient;

pub struct ListClients;

impl Message for ListClients {
    type Result = Result<Vec<models::Client>, Error>;
}

impl Actor for DbClient {
    type Context = Context<Self>;
}

impl Supervised for DbClient {}
impl SystemService for DbClient {
    fn service_started(&mut self, ctx: &mut Context<Self>) {
        info!("DB Client started");
    }
}

impl Handler<ListClients> for DbClient {
    type Result = Result<Vec<models::Client>, Error>;

    fn handle(&mut self, _: ListClients, _: &mut Self::Context) -> Self::Result {
        use self::schema::client::dsl::*;
        let connection = SqliteConnection::establish(&SETTING.db_file).unwrap();

        let res = client.load::<models::Client>(&connection)?;
        trace!("Got clients list {:?}", res);
        Ok(res)
    }
}
