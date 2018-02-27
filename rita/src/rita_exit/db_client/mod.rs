use diesel;
use actix_web::*;
use actix::prelude::*;
use diesel::prelude::*;

mod models;
mod schema;

use failure::Error;

pub struct DbExecutor(pub SqliteConnection);

pub struct ListClients;

impl Message for ListClients {
    type Result = Result<Vec<models::Client>, Error>;
}

impl Actor for DbExecutor {
    type Context = SyncContext<Self>;
}

impl Handler<ListClients> for DbExecutor {
    type Result = Result<Vec<models::Client>, Error>;

    fn handle(&mut self, _: ListClients, _: &mut Self::Context) -> Self::Result {
        use self::schema::client::dsl::*;
        let res = client.load::<models::Client>(&self.0)?;
        trace!("Got clients list {:?}", res);
        Ok(res)
    }
}
