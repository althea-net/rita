use actix_web::middleware::{Middleware, Response, Started};
use actix_web::{HttpRequest, HttpResponse, Result};
use http::{header, HttpTryFrom, Method, StatusCode};
use regex::Regex;

pub struct Headers; // <- Our middleware

impl<S> Middleware<S> for Headers {
    fn start(&self, _req: &mut HttpRequest<S>) -> Result<Started> {
        Ok(Started::Done)
    }

    //Used to control the headers to OPTIONS requests and set the Access-Control
    //property to only pages hosted on this machine.
    fn response(&self, req: &mut HttpRequest<S>, mut resp: HttpResponse) -> Result<Response> {
        let url = req.connection_info().host();
        let re = Regex::new(r"^(.*):").unwrap();
        let url_no_port = re.captures(url).unwrap()[1].to_string();
        if req.method() == &Method::OPTIONS {
            *resp.status_mut() = StatusCode::OK;
        }
        resp.headers_mut().insert(
            header::HeaderName::try_from("Access-Control-Allow-Origin").unwrap(),
            header::HeaderValue::from_str(&format!("http://{}", url_no_port)).unwrap(),
        );
        resp.headers_mut().insert(
            header::HeaderName::try_from("Access-Control-Allow-Headers").unwrap(),
            header::HeaderValue::from_static("content-type"),
        );
        Ok(Response::Done(resp))
    }
}
