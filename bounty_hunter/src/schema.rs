// If you're experiencing issues with wrong values in wrong record fields make sure that field
// order below coincides with the channel state structs in models.rs. More info:
// http://docs.diesel.rs/diesel/deserialize/trait.Queryable.html
table! {
    states (id) {
        id -> Bigint,
        address_a -> Binary,
        address_b -> Binary,
        channel_id -> Binary,
        nonce -> Binary,
        balance_a -> Binary,
        balance_b -> Binary,
        sig_a_v -> Nullable<Binary>,
        sig_a_r -> Nullable<Binary>,
        sig_a_s -> Nullable<Binary>,
        sig_b_v -> Nullable<Binary>,
        sig_b_r -> Nullable<Binary>,
        sig_b_s -> Nullable<Binary>,
    }
}
