table! {
    clients (mesh_ip) {
        mesh_ip -> Varchar,
        wg_pubkey -> Varchar,
        wg_port -> Int4,
        eth_address -> Varchar,
        internal_ip -> Varchar,
        internet_ipv6 -> Varchar,
        nickname -> Varchar,
        email -> Varchar,
        phone -> Varchar,
        country -> Varchar,
        email_code -> Varchar,
        verified -> Bool,
        email_sent_time -> Int8,
        text_sent -> Int4,
        last_seen -> Int8,
        last_balance_warning_time -> Int8,
    }
}

table! {
    assigned_ips (subnet) {
        subnet -> Varchar,
        available_subnets -> Varchar,
        iterative_index -> Int8,
    }
}
