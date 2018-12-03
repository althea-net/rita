-- Your SQL goes here
CREATE TABLE states (
  id INTEGER NOT NULL PRIMARY KEY,
  channel_id BLOB NOT NULL UNIQUE,
  address_a BLOB NOT NULL,
  address_b BLOB NOT NULL,
  nonce BLOB NOT NULL,
  balance_a BLOB NOT NULL,
  balance_b BLOB NOT NULL,
  sig_a_v BLOB,
  sig_a_r BLOB,
  sig_a_s BLOB,
  sig_b_v BLOB,
  sig_b_r BLOB,
  sig_b_s BLOB
);

CREATE INDEX addresses_idx ON states (address_a, address_b);
