-- This file should undo anything in `up.sql`
ALTER TABLE clients
    DROP COLUMN internet_ipv6
;
DROP TABLE assigned_ips; 