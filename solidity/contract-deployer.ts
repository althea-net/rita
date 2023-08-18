// Contract deployer reads the compiled source contract code from disk and deploys several
// ERC20 contracts and one ERC721 contract used for testing
import { TestERC20A } from "./typechain/TestERC20A";
import { TestERC20B } from "./typechain/TestERC20B";
import { TestERC20C } from "./typechain/TestERC20C";
import { TestERC721A } from "./typechain/TestERC721A";
import { ethers } from "ethers";
import fs from "fs";
import commandLineArgs from "command-line-args";
import { exit } from "process";

// These are the expected keyword arguments from the command line, e.g. --eth-privkey=0xabcdefg...
const args = commandLineArgs([
  // the EVM node used to deploy the contract
  { name: "eth-node", type: String },
  // the EVM private key that will contain the gas required to pay for the contact deployment
  { name: "eth-privkey", type: String },
]);

// uncomment this to set the gas price for all contract deployments
const overrides = {
  //gasPrice: 100000000000
}

// deploy will initialize an EVM client (ethers.js' Provider) that communicates over JSONRPC
// A "wallet" holds a private key and a provider and is used to interact with the blockchain as the private key account
// The contracts are then located in the filesystem and deployed with an ethers.js ContractFactory
async function deploy() {
  var startTime = new Date();
  const provider = await new ethers.providers.JsonRpcProvider(args["eth-node"]);
  let wallet = new ethers.Wallet(args["eth-privkey"], provider);

  var success = false;
  while (!success) {
    var present = new Date();
    var timeDiff: number = present.getTime() - startTime.getTime();
    timeDiff = timeDiff / 1000
    provider.getBlockNumber().then(_ => success = true).catch(_ => console.log("Ethereum RPC error, trying again"))

    if (timeDiff > 600) {
      console.log("Could not contact Ethereum RPC after 10 minutes, check the URL!")
      exit(1)
    }
    await sleep(1000);
  }

  console.log("Test mode, deploying ERC20 contracts");

  // this handles several possible locations for the ERC20 artifacts
  var erc20_a_path: string
  var erc20_b_path: string
  var erc20_c_path: string
  var erc721_a_path: string
  const main_location_a = "/althea/solidity/artifacts/contracts/TestERC20A.sol/TestERC20A.json"
  const main_location_b = "/althea/solidity/artifacts/contracts/TestERC20B.sol/TestERC20B.json"
  const main_location_c = "/althea/solidity/artifacts/contracts/TestERC20C.sol/TestERC20C.json"
  const main_location_721_a = "/althea/solidity/artifacts/contracts/TestERC721A.sol/TestERC721A.json"

  const alt_location_1_a = "/solidity/TestERC20A.json"
  const alt_location_1_b = "/solidity/TestERC20B.json"
  const alt_location_1_c = "/solidity/TestERC20C.json"
  const alt_location_1_721a = "/solidity/TestERC721A.json"

  const alt_location_2_a = "TestERC20A.json"
  const alt_location_2_b = "TestERC20B.json"
  const alt_location_2_c = "TestERC20C.json"
  const alt_location_2_721a = "TestERC721A.json"

  if (fs.existsSync(main_location_a)) {
    erc20_a_path = main_location_a
    erc20_b_path = main_location_b
    erc20_c_path = main_location_c
    erc721_a_path = main_location_721_a
  } else if (fs.existsSync(alt_location_1_a)) {
    erc20_a_path = alt_location_1_a
    erc20_b_path = alt_location_1_b
    erc20_c_path = alt_location_1_c
    erc721_a_path = alt_location_1_721a
  } else if (fs.existsSync(alt_location_2_a)) {
    erc20_a_path = alt_location_2_a
    erc20_b_path = alt_location_2_b
    erc20_c_path = alt_location_2_c
    erc721_a_path = alt_location_2_721a
  } else {
    console.log("Test mode was enabled but the ERC20 contracts can't be found!")
    exit(1)
  }

  // Finally the source for each contract is known
  // The bytecode can be deployed to the chain via ContractFactory and
  // with the contract ABI JavaScript functions can be generated to interact with the contracts

  // To deploy a new contract here first run `npm run typechain` and then locate the
  // TypeScript type declaration file in typechain/ for your contract, the goal being to deploy the contract
  // and cast it to the generated Class in that <contract>.d.ts file

  // Read ABI (blockchain API) and bytecode from disk
  const { abi, bytecode } = getContractArtifacts(erc20_a_path);
  // Create a contract deployer factory
  const erc20Factory = new ethers.ContractFactory(abi, bytecode, wallet);
  // Deploy the contract and cast to the typechain generated class
  const testERC20 = (await erc20Factory.deploy(overrides)) as TestERC20A;
  await testERC20.deployed(); // Wait
  const erc20TestAddress = testERC20.address;
  console.log("ERC20 deployed at Address - ", erc20TestAddress);
  // Now testERC20 is ready to use, e.g. testERC20.transfer(from, to, amount)

  const { abi: abi1, bytecode: bytecode1 } = getContractArtifacts(erc20_b_path);
  const erc20Factory1 = new ethers.ContractFactory(abi1, bytecode1, wallet);
  const testERC201 = (await erc20Factory1.deploy(overrides)) as TestERC20B;
  await testERC201.deployed();
  const erc20TestAddress1 = testERC201.address;
  console.log("ERC20 deployed at Address - ", erc20TestAddress1);

  const { abi: abi2, bytecode: bytecode2 } = getContractArtifacts(erc20_c_path);
  const erc20Factory2 = new ethers.ContractFactory(abi2, bytecode2, wallet);
  const testERC202 = (await erc20Factory2.deploy(overrides)) as TestERC20C;
  await testERC202.deployed();
  const erc20TestAddress2 = testERC202.address;
  console.log("ERC20 deployed at Address - ", erc20TestAddress2);

  const { abi: abi3, bytecode: bytecode3 } = getContractArtifacts(erc721_a_path);
  const erc721Factory1 = new ethers.ContractFactory(abi3, bytecode3, wallet);
  const testERC721 = (await erc721Factory1.deploy(overrides)) as TestERC721A;
  await testERC721.deployed();
  const erc721TestAddress = testERC721.address;
  console.log("ERC721 deployed at Address - ", erc721TestAddress);
}

function getContractArtifacts(path: string): { bytecode: string; abi: string } {
  var { bytecode, abi } = JSON.parse(fs.readFileSync(path, "utf8").toString());
  return { bytecode, abi };
}

async function main() {
  await deploy();
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

main();
