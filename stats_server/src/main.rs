extern crate actix;
extern crate actix_web;
extern crate althea_types;
extern crate docopt;
extern crate env_logger;
extern crate futures;

#[macro_use]
extern crate log;

use actix_web::*;
use futures::Future;

use docopt::Docopt;

use althea_types::interop::Stats;

const USAGE: &str = "
Usage: stats_server --es-url <es_url> --index <index> --bind-url <bind_url>
Options:
    --es-url   URL of elasticsearch server to insert data into e.g. 127.0.0.1:1234
    --bind-url   URL to bind to
    --indes   index name to insert data into
";

struct ProxyState {
    insert_url: String,
}

fn index(
    data: Json<Stats>,
    req: HttpRequest<ProxyState>,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    info!("got data {:?}", data);
    client::ClientRequest::post(&req.state().insert_url)
        .json(data.into_inner())
        .unwrap()
        .send()
        .map_err(Error::from)
        .and_then(|resp| {
            resp.body()
                .from_err()
                .and_then(|body| Ok(HttpResponse::Ok().body(body)))
        })
        .responder()
}

fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|d| d.parse())
        .unwrap_or_else(|e| e.exit());

    let insert_url = format!(
        "{}/{}/data/",
        args.get_str("<es_url>"),
        args.get_str("<index>")
    );

    env_logger::init();
    let sys = actix::System::new("es-proxy");

    server::new(move || {
        App::with_state(ProxyState {
            insert_url: insert_url.clone(),
        }).middleware(middleware::Logger::default())
            .resource("/stats/", |r| r.method(http::Method::POST).with2(index))
    }).bind(args.get_str("<bind_url>"))
        .unwrap()
        .start();

    info!(
        "Started stats server at server: {}",
        args.get_str("<bind_url>")
    );
    let _ = sys.run();
}
