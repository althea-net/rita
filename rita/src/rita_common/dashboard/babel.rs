use super::*;

pub fn get_local_fee(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("local_fee", SETTING.get_payment().local_fee);

    Ok(HttpResponse::Ok().json(ret))
}

pub fn get_metric_factor(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("metric_factor", SETTING.get_network().metric_factor);

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_local_fee(path: Path<u32>) -> Result<HttpResponse, Error> {
    let new_fee = path.into_inner();
    debug!("/local_fee/{} POST hit", new_fee);
    let mut ret = HashMap::<String, String>::new();

    let stream = match TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", SETTING.get_network().babel_port)
            .parse()
            .unwrap(),
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to set local fee! {:?}", e);
            ret.insert(
                "error".to_owned(),
                "Could not create a socket for connecting to Babel".to_owned(),
            );
            ret.insert("rust_error".to_owned(), format!("{:?}", e));

            return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                .into_builder()
                .json(ret));
        }
    };

    let mut babel = Babel::new(stream);

    if let Err(e) = babel.start_connection() {
        error!("Failed to set local fee! {:?}", e);
        ret.insert("error".to_owned(), "Could not connect to Babel".to_owned());
        ret.insert("rust_error".to_owned(), format!("{:?}", e));

        return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
            .into_builder()
            .json(ret));
    }

    if let Err(e) = babel.set_local_fee(new_fee) {
        error!("Failed to set local fee! {:?}", e);
        ret.insert(
            "error".to_owned(),
            "Failed to ask Babel to set the proposed fee".to_owned(),
        );
        ret.insert("rust_error".to_owned(), format!("{:?}", e));

        return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
            .into_builder()
            .json(ret));
    };

    // Set the value in settings only after Babel successfuly accepts the passed value
    SETTING.get_payment_mut().local_fee = new_fee;

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }

    if new_fee == 0 {
        warn!("THIS NODE IS GIVING BANDWIDTH AWAY FOR FREE. PLEASE SET local_fee TO A NON-ZERO VALUE TO DISABLE THIS WARNING.");
        ret.insert("warning".to_owned(), "THIS NODE IS GIVING BANDWIDTH AWAY FOR FREE. PLEASE SET local_fee TO A NON-ZERO VALUE TO DISABLE THIS WARNING.".to_owned());
    }

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_metric_factor(path: Path<u32>) -> Result<HttpResponse, Error> {
    let new_factor = path.into_inner();
    debug!("/metric_factor/{} POST hit", new_factor);
    let mut ret = HashMap::<String, String>::new();

    let stream = match TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", SETTING.get_network().babel_port)
            .parse()
            .unwrap(),
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to set metric factor! {:?}", e);
            ret.insert(
                "error".to_owned(),
                "Could not create a socket for connecting to Babel".to_owned(),
            );
            ret.insert("rust_error".to_owned(), format!("{:?}", e));

            return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                .into_builder()
                .json(ret));
        }
    };

    let mut babel = Babel::new(stream);

    if let Err(e) = babel.start_connection() {
        error!("Failed to set metric factor! {:?}", e);
        ret.insert("error".to_owned(), "Could not connect to Babel".to_owned());
        ret.insert("rust_error".to_owned(), format!("{:?}", e));

        return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
            .into_builder()
            .json(ret));
    }

    if let Err(e) = babel.set_metric_factor(new_factor) {
        error!("Failed to set metric factor! {:?}", e);
        ret.insert(
            "error".to_owned(),
            "Failed to ask Babel to set the proposed factor".to_owned(),
        );
        ret.insert("rust_error".to_owned(), format!("{:?}", e));

        return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
            .into_builder()
            .json(ret));
    };

    // Set the value in settings only after Babel successfuly accepts the passed value
    SETTING.get_network_mut().metric_factor = new_factor;

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }

    if new_factor == 0 {
        warn!("THIS NODE DOESN'T PAY ATTENTION TO ROUTE QUALITY - IT'LL CHOOSE THE CHEAPEST ROUTE EVEN IF IT'S THE WORST LINK AROUND. PLEASE SET metric_factor TO A NON-ZERO VALUE TO DISABLE THIS WARNING.");
        ret.insert("warning".to_owned(), "THIS NODE DOESN'T PAY ATTENTION TO ROUTE QUALITY - IT'LL CHOOSE THE CHEAPEST ROUTE EVEN IF IT'S THE WORST LINK AROUND. PLEASE SET metric_factor TO A NON-ZERO VALUE TO DISABLE THIS WARNING.".to_owned());
    }

    Ok(HttpResponse::Ok().json(ret))
}
