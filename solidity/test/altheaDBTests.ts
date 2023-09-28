import chai from "chai";
import { ethers } from "hardhat";
import { solidity } from "ethereum-waffle";

import { deployContracts } from "../test-utils";

chai.use(solidity);
const { expect } = chai;

async function runTest(opts: {}) {
  const signers = await ethers.getSigners();
  const sender = signers[0];
  const exit_admin = signers[1];
  const user_admin = signers[2];

  // Deploy several ERC20 tokens
  const { althea_db } = await deployContracts(sender)





}

describe("ERC20Transfer tests", function () {
  it("emits Transfer events correctly", async function () {
    await runTest({})
  });
});