import { TestERC20A } from "../typechain/TestERC20A";
import { TestERC20B } from "../typechain/TestERC20B";
import { TestERC20C } from "../typechain/TestERC20C";
import { AltheaDB } from "../typechain/AltheaDB";
import { ethers } from "hardhat";
import { Signer } from "ethers";

export async function deployContracts(signer?: Signer | undefined) {

  const AltheaDB = await ethers.getContractFactory("AltheaDB", signer);
  const althea_db = (await AltheaDB.deploy(signer?.getAddress())) as AltheaDB;

  return { althea_db };
}