-- Your SQL goes here
ALTER TABLE clients
    ADD COLUMN internet_ipv6 varchar(132) NOT NULL DEFAULT ''
;
CREATE TABLE assigned_ips
(
    subnet varchar(132) CONSTRAINT secondkey PRIMARY KEY,
    available_subnets varchar(512) NOT NULL,
    iterative_index bigint DEFAULT 0 NOT NULL
); 