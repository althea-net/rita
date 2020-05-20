//! This is the Actix-web middleware that attaches the content headers we need for
//! the client dashboard

use crate::http::{header, HttpTryFrom, Method, StatusCode};
use crate::SETTING;
use actix_web::middleware::{Middleware, Response, Started};
use actix_web::{FromRequest, HttpRequest, HttpResponse, Result};
use actix_web_httpauth::extractors::basic::{BasicAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use regex::Regex;
use settings::RitaCommonSettings;

pub struct Headers;

impl<S> Middleware<S> for Headers {
    fn start(&self, _req: &HttpRequest<S>) -> Result<Started> {
        Ok(Started::Done)
    }

    fn response(&self, req: &HttpRequest<S>, mut resp: HttpResponse) -> Result<Response> {
        let url = req.connection_info().host().to_owned();
        let re = Regex::new(r"^(.*):").unwrap();
        let url_no_port = re.captures(&url).unwrap()[1].to_string();

        let origin = match req.headers().get("origin") {
            Some(origin) => {
                if origin == "http://althea.net" {
                    "althea.net".to_string()
                } else if origin == "http://althearouter.net" {
                    "althearouter.net".to_string()
                } else {
                    url_no_port
                }
            }
            None => url_no_port,
        };

        if req.method() == Method::OPTIONS {
            *resp.status_mut() = StatusCode::OK;
        }

        if origin != "" {
            #[cfg(not(feature = "dash_debug"))]
            resp.headers_mut().insert(
                header::HeaderName::try_from("Access-Control-Allow-Origin").unwrap(),
                header::HeaderValue::from_str(&format!("http://{}", origin)).unwrap(),
            );
            #[cfg(feature = "dash_debug")]
            resp.headers_mut().insert(
                header::HeaderName::try_from("Access-Control-Allow-Origin").unwrap(),
                header::HeaderValue::from_str("*").unwrap(),
            );
        }
        resp.headers_mut().insert(
            header::HeaderName::try_from("Access-Control-Allow-Headers").unwrap(),
            header::HeaderValue::from_static("authorization, content-type"),
        );
        Ok(Response::Done(resp))
    }
}

// for some reason the Headers struct doesn't get this
#[allow(dead_code)]
pub struct Auth;

impl<S> Middleware<S> for Auth {
    fn start(&self, req: &HttpRequest<S>) -> Result<Started> {
        let password = SETTING.get_network().rita_dashboard_password.clone();
        let mut config = Config::default();

        // the /exits path is exempted from authenticaiton so that the
        // checkup.ash cron script can continue to query it without issue
        if password.is_none() || req.request().path() == "/exits" {
            return Ok(Started::Done);
        }

        config.realm("Admin");
        let auth = BasicAuth::from_request(&req, &config)?;
        // hardcoded username since we don't have a user system
        if auth.username() == "rita"
            && auth.password().is_some()
            && auth.password().unwrap() == password.unwrap()
        {
            Ok(Started::Done)
        } else {
            Err(AuthenticationError::from(config).into())
        }
    }
}
