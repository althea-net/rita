# Solidity (Blockchain Contracts for Althea-L1)

This folder is the home of Rita's Solidity contracts which run on Althea-L1.

The contract source files live in `contracts/`. The tests live in `test/` and may use `test-utils/` for reusable testing components.
Testing requires a running instance of Althea-L1 (e.g. in the integration test container) and pointing `contract-deployer.ts` at that chain, which is called via `scripts/contract-deployer.sh`.

## Compiling the contracts

1. [Install Node.js and npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
1. Run `npm install`
1. Run `npm run typechain`
1. The compiled files are all placed in artifacts/contracts/\<Contract Name\>.sol/\<Contract Name\>.json, these are directly usable with libraries like ethers.js.

## Testing the contracts

For unit testing basic functions of the contracts, this repo uses [HardHat](https://hardhat.org/) to operate a dummy EVM blockchain. Note that HardHat is incapable of performing exactly how Althea-L1 does, so the tests in this folder will never be as thorough as an integration test can be.

The tests should use [Chai](https://www.chaijs.com/) with the [ethereum-waffle extensions](https://ethereum-waffle.readthedocs.io/en/latest/).

Define tests in the `test/` folder and then run `npm run test` to run them.

## Integration testing

In the scripts directory `contract-deployer.sh` can be used to deploy contracts on the local EVM node (via http://localhost:8545) as the well-funded MINER account set up in the integration tests.
Add whatever contracts need deployment to `contract-deployer.ts` and add an integration testing startup execution to make these tests available before your tests execute.

## TODO

* Update solidity version in hardhat.config.ts (Justin what version do we want? Latest is v0.8.21)