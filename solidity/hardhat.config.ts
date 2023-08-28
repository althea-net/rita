import "@nomiclabs/hardhat-waffle";
import "hardhat-gas-reporter";
import "hardhat-typechain";
import { task } from "hardhat/config";

task("accounts", "Prints the list of accounts", async (args, hre) => {
  const accounts = await hre.ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

// // This is a sample Buidler task. To learn how to create your own go to
// // https://buidler.dev/guides/create-task.html
// task("accounts", "Prints the list of accounts", async (taskArgs, bre) => {
//   const accounts = await bre.ethers.getSigners();

//   for (const account of accounts) {
//     console.log(await account.getAddress());
//   }
// });

// You have to export an object to set up your config
// This object can have the following optional entries:
// defaultNetwork, networks, solc, and paths.
// Go to https://buidler.dev/config/ to learn more
module.exports = {
  // This is a sample solc configuration that specifies which version of solc to use
  solidity: {
    version: "0.8.21",
    settings: {
      optimizer: {
        enabled: true,
      },
      evmVersion: "paris"
    }
  },
  networks: {
    althea: {
      url: "http://localhost:8545",
      accounts: [
        "0x3b23c86080c9abc8870936b2eb17ecb808f5ad3b318018b3e23873013379e4d6",
        "0xa9c7120f7a13a0bb0b0c513e6145bc1e4c55a126a055da53c5e7612d25aca8c7",
        "0x3f4eeb27124d1fcf9bffa1bc2bfa4660f75777dbfc268f0349636e429105aa7f",
        "0x5791240cd5798ecf4862be2c1c1ae882b80a804e7a3fc615a93910c554b23115",
        "0x34d97aaf58b1a81d3ed3068a870d8093c6341cf5d1ef7e6efa03fe7f7fc2c3a8",
      ]
    }
  },
  typechain: {
    outDir: "typechain",
    target: "ethers-v5",
    runOnCompile: true
  },
  gasReporter: {
    enabled: true
  },
  mocha: {
    timeout: 2000000
  }
};
