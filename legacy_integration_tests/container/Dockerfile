FROM postgres
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y sudo iputils-ping iproute2 jq vim netcat-traditional default-libmysqlclient-dev libsqlite3-dev postgresql-client-11 postgresql-server-dev-11 libpq-dev python3-pip bridge-utils wireguard linux-source curl git libssl-dev pkg-config build-essential ipset python3-setuptools python3-wheel dh-autoreconf procps iperf3
RUN apt-get install -y python3-termcolor python3-toml python3-networkx python3-matplotlib python3-joblib
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN PATH=$PATH:$HOME/.cargo/bin cargo install diesel_cli --force
ENV POSTGRES_USER=postgres
ENV POSTGRES_BIN=/usr/lib/postgresql/16/bin/postgres
ENV INITDB_BIN=/usr/lib/postgresql/16/bin/initdb
ARG NODES
ENV SPEEDTEST_THROUGHPUT=$SPEEDTEST_THROUGHPUT
ENV SPEEDTEST_DURATION=$SPEEDTEST_DURATION
ENV VERBOSE=$VERBOSE
ENV NODES=$NODES
# we pull in the git tar instead of the local folder becuase the raw code is much much smaller
# note that changes have to be checked in to be pulled in and tested! we pull this in near
# the bottom to maximize caching of earlier containers
ADD rita.tar.gz /
CMD PATH=$PATH:$HOME/.cargo/bin SPEEDTEST_THROUGHPUT="200" SPEEDTEST_DURATION="15" INITIAL_POLL_INTERVAL=5 BACKOFF_FACTOR="1.5" VERBOSE=1 /althea_rs/legacy_integration_tests/rita.sh
