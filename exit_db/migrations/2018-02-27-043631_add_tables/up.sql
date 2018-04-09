-- Your SQL goes here
CREATE TABLE clients (
  mesh_ip VARCHAR NOT NULL PRIMARY KEY,
  wg_pubkey VARCHAR NOT NULL,
  wg_port VARCHAR NOT NULL,
  luci_pass VARCHAR NOT NULL,
  internal_ip VARCHAR NOT NULL,
  email VARCHAR NOT NULL,
  zip VARCHAR NOT NULL
)