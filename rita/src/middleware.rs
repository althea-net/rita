//! This is the Actix-web middleware that attaches the content headers we need for
//! the client dashboard

use actix_web::middleware::{Middleware, Response, Started};
use actix_web::{HttpRequest, HttpResponse, Result};
use http::{header, HttpTryFrom, Method, StatusCode};
use regex::Regex;

use std::path;

use settings::RitaCommonSettings;

use SETTING;

pub struct Headers;

impl<S> Middleware<S> for Headers {
    fn start(&self, _req: &HttpRequest<S>) -> Result<Started> {
        Ok(Started::Done)
    }

    fn response(&self, req: &HttpRequest<S>, mut resp: HttpResponse) -> Result<Response> {
        let url = req.connection_info().host().to_owned();
        let re = Regex::new(r"^(.*):").unwrap();
        let url_no_port = re.captures(&url).unwrap()[1].to_string();
        if req.method() == &Method::OPTIONS {
            *resp.status_mut() = StatusCode::OK;
        }

        let (key, cert) = {
            let settings = SETTING.get_network();
            (settings.key_path.clone(), settings.cert_path.clone())
        };

        if key.is_some()
            && cert.is_some()
            // The unwraps are safe because we know for a fact that the values are Some()
            && path::Path::new(&key.unwrap()).exists()
            && path::Path::new(&cert.unwrap()).exists()
        {
            resp.headers_mut().insert(
                header::HeaderName::try_from("Access-Control-Allow-Origin").unwrap(),
                header::HeaderValue::from_str(&format!("https://{}", url_no_port)).unwrap(),
            );
        } else {
            resp.headers_mut().insert(
                header::HeaderName::try_from("Access-Control-Allow-Origin").unwrap(),
                header::HeaderValue::from_str(&format!("http://{}", url_no_port)).unwrap(),
            );
        }
        resp.headers_mut().insert(
            header::HeaderName::try_from("Access-Control-Allow-Headers").unwrap(),
            header::HeaderValue::from_static("content-type"),
        );
        Ok(Response::Done(resp))
    }
}
