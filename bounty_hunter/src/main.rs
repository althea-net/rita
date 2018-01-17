#[macro_use] extern crate log;

#[macro_use] extern crate rouille;

fn main() {
    simple_logger::init().unwrap();
    trace!("Starting");

    rouille::start_server("[::0]:8080", move |request| { // TODO: fix the port
        router!(request,
            (POST) (/update) => {
                process_updates
                rouille::Response::text(format!("hello, {}", id))
            },
            _ => rouille::Response::empty_404()
        )
    });
}

fn process_updates() {

}