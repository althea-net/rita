FROM postgres
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y sudo iputils-ping iproute2 jq vim netcat-traditional default-libmysqlclient-dev libsqlite3-dev postgresql-client-11 postgresql-server-dev-11 libpq-dev python3-pip bridge-utils wireguard linux-source curl git libssl-dev pkg-config build-essential ipset python3-setuptools python3-wheel dh-autoreconf procps net-tools iperf3 babeld make locales-all npm
# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH=$PATH:/root/.cargo/bin/
# Setup postgres db for Althea exits
RUN cargo install diesel_cli --force
# Install Babeld for Althea routing
RUN rm -rf /var/babeld
RUN mkdir /var/babeld && cd /var/babeld && git clone -b master https://github.com/althea-mesh/babeld.git
RUN cd /var/babeld/babeld && make install
# Install Althea for Althea blockchain operations, also used to test eth blockchain operations
# but in that case the test runs entierly on the evm environment contained in the althea chain
ADD https://github.com/althea-net/althea-L1/releases/download/v0.5.5/althea-linux-amd64 /usr/bin/althea
RUN chmod +x /usr/bin/althea
# we pull in the git tar instead of the local folder becuase the raw code is much much smaller
# note that changes have to be checked in to be pulled in and tested! we pull this in near
# the bottom to maximize caching of earlier containers
ADD rita.tar.gz /
# Build the code as a caching step before running the test scenario. this dramatically reduces the total
# runtime when running many test scenarios since the container image can be shared with pre-built rust artifacts
RUN cargo build --profile testrunner --manifest-path /althea_rs/test_runner/Cargo.toml

