#!/bin/bash
set -eux
# your gaiad binary name
BIN=althea

CHAIN_ID="althea_417834-1"

NODES=$1

STAKING_TOKEN="aalthea"
ALLOCATION="1000000000000000000000000${STAKING_TOKEN},1000000000000ufootoken"
 DELEGATION="500000000000000000000000${STAKING_TOKEN}"

# Static EVM addresses (Ethermint keys) which will receive enough althea token for EVM operations
# These will be duplicated in the solidity directory and the integration_tests lib so that tests and CLI tools
EVM_MINER_ALLOCATION="5000000000000000000000000${STAKING_TOKEN}"
EVM_MINER_ETH_PRIVKEY="b1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7"
EVM_MINER_ADDRESS="althea1hanqss6jsq66tfyjz56wz44z0ejtyv0768q8r4"
EVM_MINER_ETH_ADDRESS="bf660843528035a5a4921534e156a27e64b231fe"
EVM_USER_ALLOCATION="500000000000000000000000${STAKING_TOKEN}"
EVM_USER_MNEMONICS=( \
    "dial point debris employ position cheap inmate nominee crisp grow hello body meadow clever cloth strike agree include dirt tenant hello pattern tattoo option" \
    "poverty inside weasel way rabbit staff initial fire near machine icon favorite simple address skill couple embark acquire asthma deny census flush ensure shiver" \
    "potato apart credit boy canyon walnut mirror inherit note market increase gentle ostrich siege verify clown grab blur rifle inner diagram filter absurd believe" \
    "talent rib law noble clog stamp avocado key skull ritual urge metal decorate exist lizard wide section census broken recipe expand unhappy razor small" \
    "party normal injury water lecture rude civil disorder hawk split wonder dizzy immense humor couple toilet seed there flip animal lyrics shift give cotton" \
)
EVM_USER_ADDRESSES=("althea1xlcvjwhpku7slrdue6s4zng5xj5dwzemfs0lxj" "althea1v5lygpttvvfdksdnrvjuxqv98enut6x83zpu2e" "althea1czdncnejmxe2fkw7z7huk6ckh5g0arnp5ts4l3" "althea17gv9tajr3dv35h0ah57mxtg9q2epmq6f5zxsxl" "althea17aq8r2a92m4kq82z7mnvt8dpcnndks4ezrk3ec")
# output of `althea debug addr` on the "althea1..." EVM_USER_ADDRESSES, these likely need a 0x in front of them for most interfaces to accept them
EVM_USER_ETH_ADDRESSES=("37f0c93ae1b73d0f8dbccea1514d1434a8d70b3b" "653e44056b6312db41b31b25c301853e67c5e8c7" "c09b3c4f32d9b2a4d9de17afcb6b16bd10fe8e61" "f21855f6438b591a5dfdbd3db32d0502b21d8349" "f74071aba556eb601d42f6e6c59da1c4e6db42b9")
# output of `althea keys unsafe-export-eth-key` on the EVM users, these likely need a 0x in front of them for most interfaces to accept them
EVM_USER_ETH_PRIVKEYS=("3b23c86080c9abc8870936b2eb17ecb808f5ad3b318018b3e23873013379e4d6" "a9c7120f7a13a0bb0b0c513e6145bc1e4c55a126a055da53c5e7612d25aca8c7" "3f4eeb27124d1fcf9bffa1bc2bfa4660f75777dbfc268f0349636e429105aa7f" "5791240cd5798ecf4862be2c1c1ae882b80a804e7a3fc615a93910c554b23115" "34d97aaf58b1a81d3ed3068a870d8093c6341cf5d1ef7e6efa03fe7f7fc2c3a8")

# first we start a genesis.json with validator 1
# validator 1 will also collect the gentx's once gnerated
STARTING_VALIDATOR=1
STARTING_VALIDATOR_HOME="--home /validator$STARTING_VALIDATOR"
# todo add git hash to chain name
$BIN init $STARTING_VALIDATOR_HOME --chain-id=$CHAIN_ID validator$STARTING_VALIDATOR


## Modify generated genesis.json to our liking by editing fields using jq
## we could keep a hardcoded genesis file around but that would prevent us from
## testing the generated one with the default values provided by the module.

# add in denom metadata for both native tokens
jq '.app_state.bank.denom_metadata += [{"name": "althea", "symbol": "althea", "base": "aalthea", display: "althea", "description": "The native staking token of Althea-Chain (18 decimals)", "denom_units": [{"denom": "aalthea", "exponent": 0, "aliases": ["attoalthea", "althea-wei"]}, {"denom": "nalthea", "exponent": 9, "aliases": ["nanoalthea", "althea-gwei"]}, {"denom": "althea", "exponent": 18}]}]' /validator$STARTING_VALIDATOR/config/genesis.json > /staking-token-genesis.json
jq '.app_state.bank.denom_metadata += [{"name": "FOO", "symbol": "FOO", "base": "ufootoken", display: "footoken", "description": "A non-staking native test token (6 decimals)", "denom_units": [{"denom": "ufootoken", "exponent": 0}, {"denom": "footoken", "exponent": 6}]}]' /staking-token-genesis.json > /foo-token-genesis.json
# Link the native coin to the EVM
jq ".app_state.evm.params.evm_denom=\"${STAKING_TOKEN}\"" /foo-token-genesis.json > /evm-denom-genesis.json
# Unset the base fee in feemarket
jq '.app_state.feemarket.params.min_gas_price = "0.000000000000000000"' /evm-denom-genesis.json > /feemarket-gas-price-genesis.json


# a 120 second voting period to allow us to pass governance proposals in the tests
jq '.app_state.gov.voting_params.voting_period = "120s"' /feemarket-gas-price-genesis.json > /edited-genesis.json

# rename base denom to aalthea
sed -i 's/stake/aalthea/g' /edited-genesis.json

mv /edited-genesis.json /genesis.json


# Sets up an arbitrary number of validators on a single machine by manipulating
# the --home parameter on gaiad
for i in $(seq 1 $NODES);
do
    GAIA_HOME="--home /validator$i"
    GENTX_HOME="--home-client /validator$i"
    ARGS="$GAIA_HOME --keyring-backend test"
    KEY_ARGS="--algo secp256k1 --coin-type 118"

    $BIN keys add $ARGS $KEY_ARGS validator$i 2>> /validator-phrases

    VALIDATOR_KEY=$($BIN keys show validator$i -a $ARGS)
    # move the genesis in
    mkdir -p /validator$i/config/
    mv /genesis.json /validator$i/config/genesis.json
    $BIN add-genesis-account $ARGS $VALIDATOR_KEY $ALLOCATION
    # Initialize a genesis allocation for the EVM users and the miner after we set up the first validator
    # these genesis allocations will be carried through to the final genesis file
    if [ $i -eq  1 ]; then 
        $BIN add-genesis-account $ARGS $EVM_MINER_ADDRESS $EVM_MINER_ALLOCATION
        # Loop through all the EVM_USER_ADDRESSES, addr gets the "althea1..." value
        for addr in ${EVM_USER_ADDRESSES[@]}; do
            # Do NOT provide $KEY_ARGS here, we want Ethermint style keys with hd path "m/44'/60'/0'/0"
            $BIN add-genesis-account $ARGS $addr $EVM_USER_ALLOCATION
        done
    fi
    # move the genesis back out
    mv /validator$i/config/genesis.json /genesis.json
done


for i in $(seq 1 $NODES);
do
    cp /genesis.json /validator$i/config/genesis.json
    GAIA_HOME="--home /validator$i"
    ARGS="$GAIA_HOME --keyring-backend test --chain-id=$CHAIN_ID --ip 7.7.7.$i"
    GENTX_FLAGS="--moniker validator$i --commission-rate 0.05 --commission-max-rate 0.05"
    # the /8 containing 7.7.7.7 is assigned to the DOD and never routable on the public internet
    # we're using it in private to prevent gaia from blacklisting it as unroutable
    # and allow local pex
    $BIN gentx $ARGS $GENTX_FLAGS validator$i $DELEGATION
    # obviously we don't need to copy validator1's gentx to itself
    if [ $i -gt 1 ]; then
        cp /validator$i/config/gentx/* /validator1/config/gentx/
    fi
done


$BIN collect-gentxs $STARTING_VALIDATOR_HOME
GENTXS=$(ls /validator1/config/gentx | wc -l)
cp /validator1/config/genesis.json /genesis.json
echo "Collected $GENTXS gentx"

# put the now final genesis.json into the correct folders
for i in $(seq 1 $NODES);
do
    cp /genesis.json /validator$i/config/genesis.json
done
