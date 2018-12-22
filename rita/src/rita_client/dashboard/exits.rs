//! The Exit info endpoint gathers infromation about exit status and presents it to the dashbaord.

use super::*;

#[derive(Serialize)]
pub struct ExitInfo {
    nickname: String,
    exit_settings: ExitServer,
    is_selected: bool,
    have_route: bool,
    is_reachable: bool,
    is_tunnel_working: bool,
}

pub struct GetExitInfo;

impl Message for GetExitInfo {
    type Result = Result<Vec<ExitInfo>, Error>;
}

/// Checks if the provided exit is selected
fn is_selected(exit: &ExitServer, current_exit: Option<&ExitServer>) -> bool {
    match current_exit {
        None => false,
        Some(i) => i == exit,
    }
}

/// Determines if the provided exit is currently selected, if it's setup, and then if it can be reached over
/// the exit tunnel via a ping
fn is_tunnel_working(exit: &ExitServer, current_exit: Option<&ExitServer>) -> bool {
    match (current_exit, is_selected(exit, current_exit)) {
        (Some(exit), true) => match exit.info.general_details() {
            Some(details) => match KI.ping_check_v4(&details.server_internal_ip) {
                Ok(ping_result) => ping_result,
                Err(_) => false,
            },
            None => false,
        },
        (_, _) => false,
    }
}

impl Handler<GetExitInfo> for Dashboard {
    type Result = Result<Vec<ExitInfo>, Error>;

    fn handle(&mut self, _msg: GetExitInfo, _ctx: &mut Self::Context) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;
        let mut babel = Babel::new(stream);
        babel.start_connection()?;
        let route_table_sample = babel.parse_routes()?;

        let mut output = Vec::new();

        let exit_client = SETTING.get_exit_client();
        let current_exit = exit_client.get_current_exit();

        for exit in exit_client.exits.clone().into_iter() {
            let selected = is_selected(&exit.1, current_exit);
            let have_route = babel.do_we_have_route(&exit.1.id.mesh_ip, &route_table_sample)?;

            // failed pings block for one second, so we should be sure it's at least reasonable
            // to expect the pings to work before issuing them.
            let reachable = if have_route {
                KI.ping_check_v6(&exit.1.id.mesh_ip)?
            } else {
                false
            };
            let tunnel_working = match (have_route, selected) {
                (true, true) => is_tunnel_working(&exit.1, current_exit),
                _ => false,
            };

            output.push(ExitInfo {
                nickname: exit.0,
                exit_settings: exit.1.clone(),
                is_selected: selected,
                have_route: have_route,
                is_reachable: reachable,
                is_tunnel_working: tunnel_working,
            })
        }

        Ok(output)
    }
}

pub fn add_exits(
    new_exits: Json<HashMap<String, ExitServer>>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    debug!("/exits POST hit with {:?}", new_exits);
    let exits = &mut SETTING.get_exit_client_mut().exits;
    exits.extend(new_exits.into_inner());

    Box::new(future::ok(HttpResponse::Ok().json(exits.clone())))
}

pub fn exits_sync(
    list_url_json: Json<HashMap<String, String>>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    debug!("/exits/sync hit with {:?}", list_url_json);

    let list_url = match list_url_json.get("url") {
        Some(url) if url.starts_with("https://") => url,
        Some(_unsafe_url) => {
            let mut ret = HashMap::new();
            ret.insert(
                "error".to_owned(),
                "Attempted to use a non-HTTPS url".to_owned(),
            );
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::BAD_REQUEST)
                    .into_builder()
                    .json(ret),
            ));
        }
        None => {
            let mut ret = HashMap::new();

            ret.insert(
                "error".to_owned(),
                "Could not find a \"url\" key in supplied JSON".to_owned(),
            );
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::BAD_REQUEST)
                    .into_builder()
                    .json(ret),
            ));
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let mut new_exits: HashMap<String, ExitServer> = match client.get(list_url).send() {
        Ok(mut response) => match response.json() {
            Ok(deserialized) => deserialized,
            Err(e) => {
                let mut ret = HashMap::<String, String>::new();

                error!(
                    "Could not deserialize exit list at {:?} because of error: {:?}",
                    list_url, e
                );
                ret.insert(
                    "error".to_owned(),
                    format!(
                        "Could not deserialize exit list at URL {:?} because of error {:?}",
                        list_url, e
                    ),
                );

                return Box::new(future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                ));
            }
        },
        Err(e) => {
            let mut ret = HashMap::new();

            error!(
                "Could not make GET request vor URL {:?}, Rust error: {:?}",
                list_url, e
            );
            ret.insert(
                "error".to_owned(),
                format!("Could not make GET request for URL {:?}", list_url),
            );
            ret.insert("rust_error".to_owned(), format!("{:?}", e));
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(ret),
            ));
        }
    };

    info!("exit_sync list: {:#?}", new_exits);

    let exits = &mut SETTING.get_exit_client_mut().exits;

    // if the entry already exists copy the registration info over
    for new_exit in new_exits.iter_mut() {
        let nick = new_exit.0;
        let new_settings = new_exit.1;
        if let Some(old_exit) = exits.get(nick) {
            new_settings.info = old_exit.info.clone();
        }
    }
    exits.extend(new_exits);

    Box::new(future::ok(HttpResponse::Ok().json(exits.clone())))
}

pub fn get_exit_info(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<Vec<ExitInfo>>, Error = Error>> {
    debug!("Exit endpoint hit!");
    Dashboard::from_registry()
        .send(GetExitInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn reset_exit(path: Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/reset hit", exit_name);

    let mut exits = SETTING.get_exits_mut();
    let mut ret = HashMap::new();

    if let Some(exit) = exits.get_mut(&exit_name) {
        info!("Changing exit {:?} state to New", exit_name);
        exit.info = ExitState::New;
        return Box::new(future::ok(HttpResponse::Ok().json(ret)));
    } else {
        error!("Requested a reset on unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested reset on unknown exit {:?}", exit_name),
        );
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }
}

pub fn select_exit(path: Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/select hit", exit_name);

    let mut exit_client = SETTING.get_exit_client_mut();
    let mut ret = HashMap::new();

    if exit_client.exits.contains_key(&exit_name) {
        info!("Selecting exit {:?}", exit_name);
        exit_client.current_exit = Some(exit_name);
        Box::new(future::ok(HttpResponse::Ok().json(ret)))
    } else {
        error!("Requested selection of an unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested selection of an unknown exit {:?}", exit_name),
        );
        Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ))
    }
}

pub fn register_to_exit(path: Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/register hit", exit_name);

    debug!("Attempting to register on exit {:?}", exit_name);

    Box::new(exit_setup_request(exit_name, None).then(|res| {
        let mut ret = HashMap::new();
        match res {
            Ok(_) => future::ok(HttpResponse::Ok().json(ret)),
            Err(e) => {
                error!("exit_setup_request() failed with: {:?}", e);
                ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
                ret.insert("rust_error".to_owned(), format!("{:?}", e));
                future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                )
            }
        }
    }))
}

pub fn verify_on_exit_with_code(
    path: Path<(String, String)>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let (exit_name, code) = path.into_inner();
    debug!("/exits/{}/verify/{} hit", exit_name, code);

    Box::new(exit_setup_request(exit_name, Some(code)).then(|res| {
        let mut ret = HashMap::new();
        match res {
            Ok(_) => future::ok(HttpResponse::Ok().json(ret)),
            Err(e) => {
                error!("exit_setup_request() failed with: {:?}", e);
                ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
                ret.insert("rust_error".to_owned(), format!("{:?}", e));
                future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                )
            }
        }
    }))
}
