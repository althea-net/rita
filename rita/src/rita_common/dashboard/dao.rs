use crate::ARGS;
use crate::SETTING;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Json, Result};
use clarity::Address;
use failure::Error;
use num256::Uint256;
use settings::FileWrite;
use settings::RitaCommonSettings;
use std::collections::HashMap;

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
    let mut dao_settings = SETTING.get_dao_mut();
    dao_settings.dao_addresses.push(provided_address);

    // So the concept of devices like exits being on multiple DAO's is a bit confusing
    // in the context of the oracle url, which we set for a single DAO because merging the oracle
    // data is difficult and doesn't really make logical sense. Therefore we're going to set our
    // oracle url based on the last added DAO address, for clients there will only ever be one
    // and for exits or large nodes operating on many dao's they are intended to disable it.
    dao_settings.oracle_url = Some(format!("https://updates.althea.net/{}", provided_address));

    drop(dao_settings);
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

pub fn get_dao_fee(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/dao_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("dao_fee", SETTING.get_dao().dao_fee.to_string());

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_dao_fee(path: Path<Uint256>) -> Result<Json<()>, Error> {
    let new_fee = path.into_inner();
    debug!("/dao_fee/{} POST hit", new_fee);
    SETTING.get_dao_mut().dao_fee = new_fee;

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(Json(()))
}
