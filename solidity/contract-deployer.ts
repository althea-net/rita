// Contract deployer reads the compiled source contract code from disk and deploys several
// ERC20 contracts and one ERC721 contract used for testing
// import { TestERC20A } from "./typechain/TestERC20A";
// import { TestERC20B } from "./typechain/TestERC20B";
// import { TestERC20C } from "./typechain/TestERC20C";
// import { TestERC721A } from "./typechain/TestERC721A";
import { AltheaDB } from "./typechain/AltheaDB";
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
  console.log(args["eth-node"]);
  const provider = await new ethers.providers.JsonRpcProvider(args["eth-node"]);
  let wallet = new ethers.Wallet(args["eth-privkey"], provider);

  var success = false;
  while (!success) {
    var present = new Date();
    var timeDiff: number = present.getTime() - startTime.getTime();
    timeDiff = timeDiff / 1000
    provider.getBlockNumber().then(e => { console.log(e); success = true; }).catch(e => { console.log(e); console.log("Ethereum RPC error, trying again"); })

    if (timeDiff > 600) {
      console.log("Could not contact Ethereum RPC after 10 minutes, check the URL!")
      exit(1)
    }
    await sleep(1000);
  }

  var althea_db_path: string
  const main_location_altheadb = "/althea_rs/solidity/artifacts/contracts/AltheaDB.sol/AltheaDB.json"

  const alt_location_1_altheadb = "solidity/artifacts/contracts/AltheaDB.sol/AltheaDB.json"

  const alt_location_2_altheadb = "AltheaDB.json"

  const alt_location_3_altheadb = "artifacts/contracts/AltheaDB.sol/AltheaDB.json"

  if (fs.existsSync(main_location_altheadb)) {
    althea_db_path = main_location_altheadb
  } else if (fs.existsSync(alt_location_1_altheadb)) {
    althea_db_path = alt_location_1_altheadb
  } else if (fs.existsSync(alt_location_2_altheadb)) {
    althea_db_path = alt_location_2_altheadb
  } else if (fs.existsSync(alt_location_3_altheadb)) {
    althea_db_path = alt_location_3_altheadb
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


  const { abi: abi4, bytecode: bytecode4 } = getContractArtifacts(althea_db_path);
  const altheadbFactory1 = new ethers.ContractFactory(abi4, bytecode4, wallet);
  const testAltheaDB = (await altheadbFactory1.deploy(wallet.address)) as AltheaDB;
  await testAltheaDB.deployed();
  const altheaDBTestAddress = testAltheaDB.address;
  console.log("Althea_DB_addr: ", altheaDBTestAddress);
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
