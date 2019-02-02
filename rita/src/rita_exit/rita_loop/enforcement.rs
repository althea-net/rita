use super::{
    future, to_identity, DbClient, DebtAction, DebtKeeper, Either, Future, GetDebtsList, HashMap,
    IpAddr, ListClients, RitaCommonSettings, SystemService, KI, SETTING,
};

/// Performs enforcement actions on clients by requesting a list of clients from debt keeper
/// if they are also a exit client they are limited to the free tier level of bandwidth by
/// setting the htb class they are assigned to to a maximum speed of the free tier value.
/// Unlike intermediary enforcement we do not need to subdivide the free tier to prevent
/// ourselves from exceeding the upstream free tier. As an exit we are the upstream.
pub fn enforce_exit_clients() -> Box<Future<Item = (), Error = ()>> {
    Box::new(
        DebtKeeper::from_registry()
            .send(GetDebtsList)
            .and_then(|debts_list| match debts_list {
                Ok(list) => Either::A(DbClient::from_registry().send(ListClients {}).and_then(
                    move |res| {
                        let clients = res.unwrap();
                        let mut clients_by_id = HashMap::new();
                        let free_tier_limit = SETTING.get_payment().free_tier_throughput;
                        for client in clients.iter() {
                            if let Ok(id) = to_identity(client) {
                                clients_by_id.insert(id, client);
                            }
                        }

                        for debt_entry in list.iter() {
                            match clients_by_id.get(&debt_entry.identity) {
                                Some(client) => {
                                    match client.internal_ip.parse() {
                                        Ok(IpAddr::V4(ip)) => {
                                            let res = if debt_entry.payment_details.action
                                                == DebtAction::SuspendTunnel
                                            {
                                                KI.set_class_limit(
                                                    "wg_exit",
                                                    free_tier_limit,
                                                    free_tier_limit,
                                                    &ip,
                                                )
                                            } else {
                                                // set to 1gbps garunteed bandwidth and 5gbps
                                                // absolute max
                                                KI.set_class_limit(
                                                    "wg_exit", 1_000_000, 5_000_000, &ip,
                                                )
                                            };
                                            if res.is_err() {
                                                warn!("Failed to limit {} with {:?}", ip, res);
                                            }
                                        }
                                        _ => warn!("Can't parse Ipv4Addr to create limit!"),
                                    };
                                }
                                None => {
                                    warn!("Could not find {:?} to suspend!", debt_entry.identity);
                                }
                            }
                        }

                        Ok(())
                    },
                )),
                Err(e) => {
                    warn!("Failed to get debts from DebtKeeper! {:?}", e);
                    Either::B(future::ok(()))
                }
            })
            .then(|_| Ok(())),
    )
}
