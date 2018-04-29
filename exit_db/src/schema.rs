table! {
    clients (mesh_ip) {
        mesh_ip -> Text,
        wg_pubkey -> Text,
        wg_port -> Text,
        luci_pass -> Text,
        internal_ip -> Text,
        email -> Text,
        zip -> Text,
        country -> Text,
    }
}
