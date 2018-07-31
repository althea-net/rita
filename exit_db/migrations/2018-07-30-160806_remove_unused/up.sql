BEGIN TRANSACTION;
CREATE TEMPORARY TABLE clients_backup(mesh_ip, wg_pubkey, wg_port, internal_ip, email, country);
INSERT INTO clients_backup SELECT mesh_ip, wg_pubkey, wg_port, internal_ip, email, country FROM clients;
DROP TABLE clients;
CREATE TABLE clients(mesh_ip, wg_pubkey, wg_port, internal_ip, email, country);
INSERT INTO clients SELECT mesh_ip, wg_pubkey, wg_port, internal_ip, email, country FROM clients_backup;
DROP TABLE clients_backup;
COMMIT;
