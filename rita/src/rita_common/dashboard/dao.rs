use super::*;

pub fn get_dao_list(_req: HttpRequest) -> Result<Json<Vec<Address>>, Error> {
    trace!("get dao list: Hit");
    Ok(Json(SETTING.get_dao().dao_addresses.clone()))
}

pub fn add_to_dao_list(path: Path<(Address)>) -> Result<Json<()>, Error> {
    trace!("Add to dao list: Hit");
    let provided_address = path.into_inner();
    for address in SETTING.get_dao().dao_addresses.iter() {
        if *address == provided_address {
            return Ok(Json(()));
        }
    }
    SETTING.get_dao_mut().dao_addresses.push(provided_address);

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(Json(()))
}

pub fn remove_from_dao_list(path: Path<(Address)>) -> Result<Json<()>, Error> {
    trace!("Remove from dao list: Hit");
    let provided_address = path.into_inner();
    let mut iter = 0;
    let mut found = false;
    for address in SETTING.get_dao().dao_addresses.iter() {
        if *address == provided_address {
            found = true;
            break;
        }
        iter += 1;
    }
    if found {
        SETTING.get_dao_mut().dao_addresses.remove(iter);
    }

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(Json(()))
}
