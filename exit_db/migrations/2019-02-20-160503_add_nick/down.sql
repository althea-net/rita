-- This file should undo anything in `up.sql`
ALTER TABLE clients RENAME TO clients_old;

CREATE TABLE clients
(
    mesh_ip VARCHAR NOT NULL PRIMARY KEY,
    wg_pubkey VARCHAR NOT NULL,
    wg_port VARCHAR NOT NULL,
    internal_ip VARCHAR NOT NULL,
    eth_address VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    country VARCHAR NOT NULL,
    email_code VARCHAR DEFAULT "0" NOT NULL,
    verified bool DEFAULT TRUE NOT NULL,
    email_sent_time INTEGER DEFAULT 0 NOT NULL
);

INSERT INTO clients
    (mesh_ip, wg_pubkey, wg_port, internal_ip, email, country, email_code, verified, email_sent_time)
SELECT mesh_ip, wg_pubkey, wg_port, internal_ip, email, country, email_code, verified, email_sent_time
FROM clients_old;

DROP TABLE clients_old;