ALTER TABLE clients RENAME TO clients_old;

CREATE TABLE clients
(   mesh_ip VARCHAR NOT NULL PRIMARY KEY,
    wg_pubkey VARCHAR NOT NULL,
    wg_port VARCHAR NOT NULL,
    luci_pass VARCHAR NOT NULL,
    internal_ip VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    zip VARCHAR NOT NULL,
    country VARCHAR NOT NULL
);

INSERT INTO clients (mesh_ip, wg_pubkey, wg_port, luci_pass, internal_ip, email, zip, country)
  SELECT mesh_ip, wg_pubkey, wg_port, luci_pass, internal_ip, email, zip, country
  FROM clients_old;

DROP TABLE clients_old;