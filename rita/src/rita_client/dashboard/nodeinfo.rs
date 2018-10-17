/*
The nodeinfo endpoint gathers info about neighbors for the dashbaord
*/

use actix::prelude::*;
use failure::Error;
use futures::Future;
use serde_json;
use std::net::{SocketAddr, TcpStream};

use babel_monitor::Babel;
use num256::Int256;
use rita_common::dashboard::Dashboard;
use rita_common::debt_keeper::{DebtKeeper, Dump};
use settings::RitaClientSettings;
use settings::RitaCommonSettings;
use SETTING;

#[derive(Serialize)]
pub struct NodeInfo {
    pub nickname: String,
    pub route_metric_to_exit: u16,
    pub total_payments: Int256,
    pub debt: i64,
    pub link_cost: u16,
    pub price_to_exit: u32,
}

pub struct GetNodeInfo;

impl Message for GetNodeInfo {
    type Result = Result<Vec<NodeInfo>, Error>;
}

impl Handler<GetNodeInfo> for Dashboard {
    type Result = ResponseFuture<Vec<NodeInfo>, Error>;

    fn handle(&mut self, _msg: GetNodeInfo, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            DebtKeeper::from_registry()
                .send(Dump {})
                .from_err()
                .and_then(|res| {
                    let res = res?;
                    let stream = TcpStream::connect::<SocketAddr>(
                        format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
                    )?;
                    let mut babel = Babel::new(stream);
                    babel.start_connection()?;
                    let route_table_sample = babel.parse_routes()?;

                    let mut output = Vec::new();

                    let exit_client = SETTING.get_exit_client();
                    let current_exit = exit_client.get_current_exit();

                    for (identity, debt_info) in res.iter() {
                        if current_exit.is_some() {
                            let exit_ip = current_exit.unwrap().id.mesh_ip;
                            let maybe_route = babel.get_route_via_neigh(
                                identity.mesh_ip,
                                exit_ip,
                                &route_table_sample,
                            );

                            // We have a peer that is an exit, so we can't find a route
                            // from them to our selected exit. Other errors can also get
                            // caught here
                            if maybe_route.is_err() {
                                output.push(NodeInfo {
                                    nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                    route_metric_to_exit: u16::max_value(),
                                    total_payments: debt_info.total_payment_received.clone().into(),
                                    debt: debt_info.debt.clone().into(),
                                    link_cost: u16::max_value(),
                                    price_to_exit: u32::max_value(),
                                });
                                continue;
                            }
                            // we check that this is safe above
                            let route = maybe_route.unwrap();

                            output.push(NodeInfo {
                                nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                route_metric_to_exit: route.metric,
                                total_payments: debt_info.total_payment_received.clone().into(),
                                debt: debt_info.debt.clone().into(),
                                link_cost: route.refmetric,
                                price_to_exit: route.price,
                            })
                        } else {
                            output.push(NodeInfo {
                                nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                route_metric_to_exit: u16::max_value(),
                                total_payments: debt_info.total_payment_received.clone().into(),
                                debt: debt_info.debt.clone().into(),
                                link_cost: u16::max_value(),
                                price_to_exit: u32::max_value(),
                            })
                        }
                    }

                    Ok(output)
                }),
        )
    }
}
