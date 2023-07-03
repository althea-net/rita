-- This file should undo anything in `up.sql`
ALTER TABLE assigned_ips
    ALTER COLUMN available_subnets type varchar(512)
;
