# Guac light client daemon

This is a light client for the [Guac](https://github.com/althea-mesh/guac) channel token. Guac is an Ethereum multihop payment channel capable ERC20 token. This light client is able to send and verify channel opening, updating, and ending transactions. It relies on one or several Guac full nodes to relay transactions onto the blockchain. The Guac full nodes are not able to spend any money without the permission of this light client, but they could censor its transactions, in the worst case leading to the loss of some funds stored in the channel. For this reason it is advisable to connect to several full nodes.

## APIs

This daemon communicates with the outside world with two apis. These APIs are implemented with the JSON-RPC specification, currently over an http transport.

### Caller API

This is an API for the application making use of the channel for payments. We include a simple CLI application for manual administration of the light client. This could also be called by, for example, a graphical wallet or an incentivized mesh routing protocol.

#### `propose_channel`
- **`channelId`**: The id of the proposed channel.
- **`counterpartyURL`**: How to reach the counterparty to this channel proposal and future updates.
- **`myAddress`**: The payment address to use to sign this proposal and future updates. The corresponding private key must be in memory, this is supplied when starting the program.
- **`theirAddress`**: The payment address of the counterparty.
- **`myBalance`**: How many coins to lock in the channel.
- **`theirBalance`**: How many coins the counterparty will lock in the channel.
- **`settlingPeriod`**: How long funds will be locked in the channel after the channel is ended.

Propose a new channel to the counterparty. This method creates and signs a `newChannel` transaction.

#### `view_proposed_channels`
View all proposed channels.

#### `accept_proposed_channel`
- **`channelId`**: The id of the channel to be accepted.

Manually accept a proposed channel. This method signs a `newChannel` transaction and sends it back to the counterparty.

#### `make_payment`
- **`channelId`**: Id of the channel to update.
- **`amount`**: Amount to decrease my balance and increase their balance.

Pay some money to the counterparty. This method calls `propose_update`, adjusting `myBalance` and `theirBalance` by `amount`.

#### `make_hashlocked_payment`
- **`channelId`**: Id of the channel to update.
- **`hash`**: Hash whose preimage must be revealed to release the payment.
- **`amount`**: Amount to decrease my balance and increase their balance.

Pay some money to the counterparty which they can only unlock by revealing the hash. This method calls `propose_update`, adding a hashlocked payment of `amount` to the haslock array.

#### `propose_update`
- **`channelId`**: Id of the channel to update.
- **`myBalance`**: My balance.
- **`theirBalance`**: Counterparty balance.
- **`hashlocks`**: Array of objects with properties:
  - **`hash`**: Hash whose preimage must be found to unlock this hashlock.
  - **`amount`**: Amount to decrease my balance and increase their balance by.

This is called by `make_payment` and `make_hashlocked_payment`.

#### `open_hashlock`
- **`channelId`**: Id of the channel to update.
- **`preimage`**: Preimage to reveal.

This method finds the hashlock corresponding to the given preimage, removes it from the hashlock list and signs a new `updateChannel` transaction and sends it and the preimage to the counterparty.

#### `end_channel`
- **`channelId`**: Id of the channel to update.

This sends an endChannel transaction to connected full nodes, who will put it onto the blockchain.

#### `close_channel`
- **`channelId`**: Id of the channel to update.

This instructs connected full nodes to send a closeChannel transaction onto the blockchain.
