# Bounty Hunter

## Motivation

Bounty hunter is a binary crate designed to be used with Rita and the [Guac_rs](https://github.com/althea-mesh/guac_rs) blockchain light channel client. The goal of bounty hunters  to act as online watchdogs for bad channel behavior that a device out in the field may not be able to catch.

In payment channels parties exchange 'updates' offline by creating a series of messages containing the agreed upon channel balance and an incrementing seqence number. By looking at the highest seqence number and balances signed by both parties the on chain code can eventually take an update and use to to settle the balance on the blockchain.

In the ideal situation Alice and and Bob open a payment channel, both of them call out to the blockchain and make a deposit into the payment channel. They then make an arbitrary number of updates in which they agree on a new set of balances where Alice may pay Bob some of the money she has deposited in the channel and vice versa. At the end of this exchange the blockchain will be updated with the last agreed on channel state and that will become the new balance.

If Bob where to act in bad faith he may at some point notice that Alice has dropped offline and during that period when Alice can not monitor the blockchain herself Bob may submit a channel state that is _not_ the last agreed on state but instead an earlier one where Bob has more money. If Alice where online she would observe this behavior and send the later channel update, preventing Bob from getting away with it.

But since Alice is running on a consumer router out in the field and not a datacenter it's unreasonable to expect her to be online all the time. As a solution to this we present Bounty hunters.

Bounty hunters are servers that Alice sends copies of her channel updates to. The bounty hunters observe the blockchain and submit these channel updates if they discover that Bob for example has submited an earlier update than they have.

Bounty hunters will also perform the the task of handing out stored channel updates to devices that may have lost them during a storage failure or unexpected reboot. Since channel states are not private and don't need to be secured this can be done easily.

## Expected Behavior

Bounty hunter should provide two endpoints

### /upload_channel_state

- URL: `<bounty_hunter_ip>:<bounty_hunter_port>/upload_channel_state`
- Method: `POST`
- URL Params: `None`
- Data Params: `Channel update JSON object`
- Success Response:
  - Code: 200 OK
  - Contents:

```
{
}
```

- Error Response: `500 Server Error`

- Sample Call:

```
curl -XPOST 127.0.0.1:<bounty_hunter_port>/upload_channel_state -H 'Content-Type: application/json' -i -d '{JSON object representing a Guac contract channel update}'
```

The JSON object submitted to this endpoint is not specified here, please refer to the [Guac payment channel contract update function](https://github.com/althea-mesh/guac/blob/master/contracts/PaymentChannels.sol#L172). For the members of this struct. For the sake of consistency this data should be represented using types from [Clarity](https://github.com/althea-mesh/clarirty) or [Rust Web3](https://github.com/tomusdrw/rust-web3) where appropriate.

---

### /get_channel_states

- URL: `<bounty_hunter_ip>:<bounty_hunter_port>/get_channel_state`
- Method: `GET`
- URL Params: `Channel ID`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents:

```
{
    [
        {JSON object representing a Guac contract channel update}
    ],
    .....
}
```

- Error Response: `500 Server Error`

- Sample Call:

```
curl -XGET 127.0.0.1:<bounty_hunter_port>/get_channel_states/<channel_id_decimal_or_big_endian_hex>
```

The JSON object submitted recieved from this endpoint is not specified here, please refer to the [Guac payment channel contract update function](https://github.com/althea-mesh/guac/blob/master/contracts/PaymentChannels.sol#L172). For the members of this struct. For the sake of consistency this data should be represented using types from [Clarity](https://github.com/althea-mesh/clarirty) or [Rust Web3](https://github.com/tomusdrw/rust-web3) where appropriate.

Channel updates are not private infromation, you can think of them like the transaction history of a super fast blockchain. Therefore there's no concern with simply handing out full channel state copies to anyone who knows your public key. Just like that some person could have downloaded and read a blockchain to get the same info with our hypothetical infinite speed blockchain.

---
