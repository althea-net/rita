use crate::operator_update::updater::update_system;
use actix_web::{http::StatusCode, HttpRequest, HttpResponse};
use althea_kernel_interface::{is_openwrt::is_openwrt, run_command};
use althea_types::UpdateType;
use std::sync::{Arc, RwLock};

lazy_static! {
    pub static ref UPDATE_INSTRUCTION: Arc<RwLock<Option<UpdateType>>> =
        Arc::new(RwLock::new(None));
}

pub async fn reboot_router(_req: HttpRequest) -> HttpResponse {
    if is_openwrt() {
        if let Err(e) = run_command("reboot", &[]) {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .json(format!("Cannot run reboot: {e}"));
        }
        HttpResponse::Ok().json(())
    } else {
        HttpResponse::Ok().json("This isn't an OpenWRT device, doing nothing")
    }
}

/// This function is triggered by the user from the router dashboard. Retrive the firmware image from
/// the lazy static variable and use this to perform a sysupgrade. If device is not openwrt or no image
/// link is available, do nothing
pub async fn update_router(_req: HttpRequest) -> HttpResponse {
    if is_openwrt() {
        let reader = &*UPDATE_INSTRUCTION.read().unwrap();
        if reader.is_none() {
            return HttpResponse::Ok().json("No update instructions set, doing nothing");
        }
        if let Err(e) = update_system(reader.as_ref().unwrap().clone()) {
            return HttpResponse::Ok().json(format!("Retrieved Error while performing update {e}"));
        }
        HttpResponse::Ok().json(())
    } else {
        HttpResponse::Ok().json("This isn't an OpenWRT device, doing nothing")
    }
}

/// Every tick, retrieve the most stable (or latest/prefered) fimaware image to store it locally. When the user chooses to update router from the
/// local dashboard, use this download link to perform the sysupgrade
pub fn set_router_update_instruction(instruction: Option<UpdateType>) {
    let writer = &mut *UPDATE_INSTRUCTION.write().unwrap();
    *writer = instruction;
}

#[test]
fn test_set_router_update_instruction() {
    use althea_types::SysupgradeCommand;
    let test = UpdateType::Sysupgrade(SysupgradeCommand {
        url: "dummyurl.com".to_string(),
        flags: None,
    });
    set_router_update_instruction(Some(test.clone()));
    let str = &*UPDATE_INSTRUCTION.read().unwrap();
    assert_eq!(Some(test), *str);
}
