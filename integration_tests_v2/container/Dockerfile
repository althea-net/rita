FROM postgres
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y sudo iputils-ping iproute2 jq vim netcat default-libmysqlclient-dev libsqlite3-dev postgresql-client-11 postgresql-server-dev-11 libpq-dev python3-pip bridge-utils wireguard linux-source curl git libssl-dev pkg-config build-essential ipset python3-setuptools python3-wheel dh-autoreconf procps iperf3 babeld make
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN PATH=$PATH:$HOME/.cargo/bin cargo install diesel_cli --force
RUN rm -rf /var/babeld
RUN mkdir /var/babeld && cd /var/babeld && git clone -b master https://github.com/althea-mesh/babeld.git
RUN cd /var/babeld/babeld && make install
# we pull in the git tar instead of the local folder becuase the raw code is much much smaller
# note that changes have to be checked in to be pulled in and tested! we pull this in near
# the bottom to maximize caching of earlier containers
ADD rita.tar.gz /
CMD RUST_LOG=INFO RUST_BACKTRACE=FULL PATH=$PATH:$HOME/.cargo/bin cargo run --manifest-path /althea_rs/test_runner/Cargo.toml --features "load_from_disk"
