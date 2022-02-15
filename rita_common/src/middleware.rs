//! This is the Actix-web middleware that attaches the content headers we need for
//! the client dashboard
//!
//! This middleware was setup using the example here: https://actix.rs/docs/middleware/
//! Two middleware are setup, HttpAuthentication and Header middleware
//! To setup middleware we implement two traits, Service and Transform for the struct in question
//! The service trait has a fn 'call', which where we are able to take the req, modify it
//! as necessary and convert it into a response, modify it as necessary and then return that
//! response

use actix_web_async::dev::{Service, Transform};
use actix_web_async::http::header::{
    Header, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_ORIGIN,
};
use actix_web_async::http::{header, Method, StatusCode};
use actix_web_httpauth_async::extractors::basic::Config;
use actix_web_httpauth_async::extractors::AuthenticationError;

use actix_web_async::{dev::ServiceRequest, dev::ServiceResponse, Error};
use actix_web_httpauth_async::headers::authorization::{Authorization, Basic};
use futures::future::{ok, LocalBoxFuture, Ready};
use futures::FutureExt;
use regex::Regex;

pub struct HeadersMiddlewareFactory;

impl<S, B> Transform<S, ServiceRequest> for HeadersMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = HeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(HeadersMiddleware { service })
    }
}

pub struct HeadersMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for HeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let conn = req.connection_info().clone();
        let url = conn.host();
        let re = Regex::new(r"^(.*):").unwrap();
        let url_no_port = re.captures(url).unwrap()[1].to_string();

        let origin = match req.headers().clone().get("origin") {
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

        let req_method = req.method().clone();

        let fut = self.service.call(req);

        async move {
            //Convert the request into a response
            let mut resp = fut.await?;

            if req_method == Method::OPTIONS {
                *resp.response_mut().status_mut() = StatusCode::OK;
            }

            if !origin.is_empty() {
                #[cfg(not(feature = "dash_debug"))]
                resp.headers_mut().insert(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    header::HeaderValue::from_str(&format!("http://{}", origin)).unwrap(),
                );
                #[cfg(feature = "dash_debug")]
                resp.headers_mut().insert(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    header::HeaderValue::from_str("*").unwrap(),
                );
            }
            resp.headers_mut().insert(
                ACCESS_CONTROL_ALLOW_HEADERS,
                header::HeaderValue::from_static("authorization, content-type"),
            );

            Ok(resp)
        }
        .boxed_local()
    }
}

pub struct AuthMiddlewareFactory;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddleware { service })
    }
}

pub struct AuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let password = settings::get_rita_client().network.rita_dashboard_password;

        let req_path = req.path().to_string();

        let auth = Authorization::<Basic>::parse(&req);

        let fut = self.service.call(req);

        async move {
            // the /exits path is exempted from authenticaiton so that the
            // checkup.ash cron script can continue to query it without issue
            if password.is_none() || req_path == "/exits" {
                let resp = fut.await?;
                return Ok(resp);
            }

            let auth = match auth {
                Ok(auth) => auth,
                Err(_) => {
                    let config = Config::default();
                    return Err(AuthenticationError::from(config.realm("Admin")).into());
                }
            };

            // If the user is authenticated, convert request -> response and return, else return Authenticaiton error
            if auth.as_ref().user_id() == "rita"
                && auth.as_ref().password().is_some()
                && auth.as_ref().password().unwrap().clone() == password.unwrap()
            {
                let resp = fut.await?;
                Ok(resp)
            } else {
                let config = Config::default();
                Err(AuthenticationError::from(config.realm("Admin")).into())
            }
        }
        .boxed_local()
    }
}
