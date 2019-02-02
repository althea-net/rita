use super::{
    to_exit_client, DbClient, DeleteClient, Future, ListClients, RitaExitSettings,
    SetClientTimestamp, SystemService, SETTING,
};
use crate::rita_exit::db_client::secs_since_unix_epoch;

/// Iterates over the the database of clients, if a client's last_seen value
/// is zero it is set to now if a clients last_seen value is older than
/// the client timeout it is deleted
pub fn cleanup_exit_clients() -> Box<Future<Item = (), Error = ()>> {
    trace!("Running exit client cleanup");
    Box::new(
        DbClient::from_registry()
            .send(ListClients {})
            .then(move |res| {
                let clients = res.unwrap().unwrap();
                for client in clients {
                    trace!("Checking client {:?}", client);
                    match to_exit_client(client.clone()) {
                        Ok(client_id) => {
                            let time_delta = secs_since_unix_epoch() - client.last_seen;
                            let entry_timeout = SETTING.get_exit_network().entry_timeout;
                            if client.last_seen == 0 {
                                info!(
                                    "{} does not have a last seen timestamp, adding one now ",
                                    client.mesh_ip
                                );
                                DbClient::from_registry().do_send(SetClientTimestamp(client_id));
                            }
                            // a entry_timeout value of 0 means the feature is disabled
                            else if entry_timeout != 0 && time_delta > entry_timeout {
                                warn!(
                                    "{} has been inactive for too long, deleting! ",
                                    client.mesh_ip
                                );
                                DbClient::from_registry().do_send(DeleteClient(client_id));
                            }
                        }
                        Err(e) => error!("Invalid database entry! {:?}", e),
                    }
                }

                Ok(())
            }),
    )
}
