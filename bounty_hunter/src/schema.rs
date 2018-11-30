table! {
    states (id) {
        id -> Bigint,
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
