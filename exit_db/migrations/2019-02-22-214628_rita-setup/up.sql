CREATE TABLE clients
(
    mesh_ip varchar(40) CONSTRAINT firstkey PRIMARY KEY,
    wg_pubkey varchar(44) NOT NULL,
    wg_port integer NOT NULL,
    eth_address varchar(64) NOT NULL,
    internal_ip varchar(42) NOT NULL,
    nickname varchar(32) NOT NULL,
    email varchar(512) NOT NULL,
    phone varchar(32) NOT NULL,
    country varchar(8) NOT NULL,
    email_code varchar(16) NOT NULL,
    verified boolean DEFAULT FALSE NOT NULL,
    email_sent_time bigint DEFAULT 0 NOT NULL,
    text_sent integer DEFAULT 0 NOT NULL,
    last_seen bigint DEFAULT 0 NOT NULL,
    last_balance_warning_time bigint DEFAULT 0 NOT NULL
);