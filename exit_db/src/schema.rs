table! {
    clients (mesh_ip) {
        mesh_ip -> Text,
        wg_pubkey -> Text,
        wg_port -> Text,
        eth_address -> Text,
        internal_ip -> Text,
        email -> Text,
        country -> Text,
        email_code -> Text,
        verified -> Bool,
        email_sent_time -> Integer,
    }
}
