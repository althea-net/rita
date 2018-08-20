extern crate actix;
extern crate actix_web;
extern crate althea_types;
extern crate docopt;
extern crate env_logger;
extern crate futures;
extern crate serde;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

use actix_web::*;
use futures::Future;

use docopt::Docopt;

use althea_types::interop::Stats;

const USAGE: &str = "
Usage: stats_server --es-url=<es_url> --index=<index> --bind-url=<bind_url>
Options:
    --es_url=<es_url>   URL of elasticsearch server to insert data into e.g. 127.0.0.1:1234
    --bind_url=<bind_url>   URL to bind to
    --index=<index>   index name to insert data into
";

struct ProxyState {
    insert_url: String,
}

#[derive(Debug, Deserialize)]
struct Args {
    flag_bind_url: String,
    flag_es_url: String,
    flag_index: String,
}

fn index(
    data: (Json<Stats>, HttpRequest<ProxyState>),
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let stats = data.0.clone();
    info!("got data {:?}", data);
    client::ClientRequest::post(&data.1.state().insert_url)
        .json(stats)
        .expect("Failed to build post request!")
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
    let args: Args = Docopt::new(USAGE.to_string())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    assert!(args.flag_es_url.starts_with("http"));
    let insert_url = format!("{}/{}/data/", args.flag_es_url, args.flag_index);

    env_logger::init();
    let sys = actix::System::new("es-proxy");

    info!("Started stats server at server: {}", args.flag_bind_url);
    server::new(move || {
        App::with_state(ProxyState {
            insert_url: insert_url.clone(),
        }).middleware(middleware::Logger::default())
            .resource("/stats/", |r| r.method(http::Method::POST).with(index))
    }).bind(args.flag_bind_url)
        .unwrap()
        .start();

    let _ = sys.run();
}
