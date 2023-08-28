import chai from "chai";
import { ethers } from "hardhat";
import { solidity } from "ethereum-waffle";

import { deployContracts } from "../test-utils";

chai.use(solidity);
const { expect } = chai;

// This is a sample test to demonstrate how tests could be written for new contracts
//
// Important test details:
// Contract interactions happen via hardhat-ethers: https://hardhat.org/hardhat-runner/plugins/nomiclabs-hardhat-ethers
// Chai is used to make assertions https://www.chaijs.com/api/bdd/
// Ethereum-waffle is used to extend chai and add ethereum matchers: https://ethereum-waffle.readthedocs.io/en/latest/matchers.html
//
// This test has a complicated context: The actual chain running is HardHat, a EVM testing & development layer with nice features
// like block auto-mining, account hijacking, start from an historical block height, and balance setup. This differs significantly
// from Althea-L1 since it's not a fully representative environment. In particular, anything that relies on the CosmosSDK side of
// of the blockchain (e.g. Liquid Infrastructure) will not work and must be tested in an integration test
async function runTest(opts: {}) {
  // hardhat.config.ts set up several Signers with the native token (aka aalthea), these users are also granted ERC20s in the contract
  // constructors, see contracts/ for examples
  const signers = await ethers.getSigners();
  const sender = signers[0];
  const receiver = signers[1];
  console.log("sender", sender.address, "receiver", receiver.address);

  // Deploy several ERC20 tokens
  const { testERC20A, testERC20B, testERC20C, althea_db } = await deployContracts(sender);

  const amount = 100;
  // Expect is a chai test that monitors side effects and makes them available with ethereum-waffle features like .to.emit()
  // So this next call will execute testERC20A.transfer (defined in the openzeppelin ERC20 source contract here:
  // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol#L110-L122)
  // and expect a "Transfer" Event to be emitted and have the parameters sender, receiver, and amount in that event.
  //
  // When using these expect.to.whatever() functions be careful the syntax is tricky so make sure await
  // is placed inside of expect like so:
  expect(
    await testERC20A.transfer(receiver.address, 100)
  ).to
    .emit(testERC20A, 'Transfer')
    .withArgs(sender.address, receiver.address, amount);

  althea_db.add_registered_user({
    mesh_ip: "fd00::1337",
    wg_key: "asfsdf",
    eth_addr: "0x054CA202089D58efB56a2B11ce812Ae3882fE1f3",
  })

  althea_db.add_registered_user({
    mesh_ip: "fd00::1447",
    wg_key: "lkjalsdjfl",
    eth_addr: "0x76a884Fb9cCbA3C97b04Fc50c01c6E7b0ec54e30",
  })

  console.log(await althea_db.get_all_registered_users())
}

describe("ERC20Transfer tests", function () {
  it("emits Transfer events correctly", async function () {
    await runTest({})
  });
});