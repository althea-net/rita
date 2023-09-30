import chai from "chai";
import { ethers } from "hardhat";
import { solidity } from "ethereum-waffle";

import { deployContracts } from "../test-utils";
import { assert } from "console";

chai.use(solidity);
const { expect } = chai;

function expectId(a: any, b: any) {
  expect(a.mesh_ip).to.equal(b.mesh_ip)
  expect(a.eth_addr).to.equal(b.eth_addr)
  expect(a.wg_key).to.equal(b.wg_key)
}

async function addUser(opts: {
  with_admin: boolean,
  try_duplicate: boolean,
  try_partial_dup: boolean,
}) {
  const signers = await ethers.getSigners();
  const sender = signers[0];
  let user1 = {
    mesh_ip: "0xfd001337",
    wg_key: "0xAFEDB",
    eth_addr: "0x054CA202089D58efB56a2B11ce812Ae3882fE1f3",
  };
  let user2 = {
    mesh_ip: "0xfd001329",
    wg_key: "0xAFEDD",
    eth_addr: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
  };
  let partialDup = {
    mesh_ip: "0xfd001338",
    wg_key: "0xAFEDB",
    eth_addr: "0x154CB202089D58efB56a2B11ce812Ae3882fE1f3",
  };
  let nullUser = {
    mesh_ip: "0x0",
    wg_key: "0x0",
    eth_addr: "0x0000000000000000000000000000000000000000",
  };
  const { althea_db } = await deployContracts(sender);
  if (opts.with_admin) {
    await althea_db.add_user_admin(await sender?.getAddress());
  }
  await althea_db.add_registered_user(user1)
  expectId(await althea_db.get_registered_client_with_eth_addr(user1.eth_addr), user1)
  expectId(await althea_db.get_registered_client_with_wg_key(user1.wg_key), user1)
  expectId(await althea_db.get_registered_client_with_mesh_ip(user1.mesh_ip), user1)
  await althea_db.add_registered_user(user2)
  expectId(await althea_db.get_registered_client_with_eth_addr(user2.eth_addr), user2)
  expectId(await althea_db.get_registered_client_with_wg_key(user2.wg_key), user2)
  expectId(await althea_db.get_registered_client_with_mesh_ip(user2.mesh_ip), user2)

  if (opts.try_duplicate) {
    await althea_db.add_registered_user(user1)
  }
  if (opts.try_partial_dup) {
    await althea_db.add_registered_user(partialDup)
  }

  await althea_db.remove_registered_user(user1)
  expectId(await althea_db.get_registered_client_with_eth_addr(user1.eth_addr), nullUser)
  expectId(await althea_db.get_registered_client_with_wg_key(user1.wg_key), nullUser)
  expectId(await althea_db.get_registered_client_with_mesh_ip(user1.mesh_ip), nullUser)
  expectId(await althea_db.get_registered_client_with_eth_addr(user2.eth_addr), user2)
  expectId(await althea_db.get_registered_client_with_wg_key(user2.wg_key), user2)
  expectId(await althea_db.get_registered_client_with_mesh_ip(user2.mesh_ip), user2)
}

async function addExit(opts: {
  with_admin: boolean,
  try_duplicate: boolean,
  try_partial_dup: boolean,
}) {
  const signers = await ethers.getSigners();
  const sender = signers[0];
  let user1 = {
    mesh_ip: "0xfd001337",
    wg_key: "0xAFEDB",
    eth_addr: "0x054CA202089D58efB56a2B11ce812Ae3882fE1f3",
    allowed_regions: [1, 3]
  };
  let user1ButDifferentRegions = {
    mesh_ip: "0xfd001337",
    wg_key: "0xAFEDB",
    eth_addr: "0x054CA202089D58efB56a2B11ce812Ae3882fE1f3",
    allowed_regions: [16, 25]
  };
  let user2 = {
    mesh_ip: "0xfd001329",
    wg_key: "0xAFEDD",
    eth_addr: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    allowed_regions: []
  };
  let partialDup = {
    mesh_ip: "0xfd001338",
    wg_key: "0xAFEDB",
    eth_addr: "0x154CB202089D58efB56a2B11ce812Ae3882fE1f3",
    allowed_regions: []
  };
  let nullUser = {
    mesh_ip: "0x0",
    wg_key: "0x0",
    eth_addr: "0x0000000000000000000000000000000000000000",
    allowed_regions: []
  };
  const { althea_db } = await deployContracts(sender);
  if (opts.with_admin) {
    await althea_db.add_exit_admin(await sender?.getAddress());
  }
  await althea_db.add_registered_exit(user1)
  expectId(await althea_db.get_registered_exit_with_eth_addr(user1.eth_addr), user1)
  expectId(await althea_db.get_registered_exit_with_wg_key(user1.wg_key), user1)
  expectId(await althea_db.get_registered_exit_with_mesh_ip(user1.mesh_ip), user1)
  await althea_db.add_registered_exit(user2)
  expectId(await althea_db.get_registered_exit_with_eth_addr(user2.eth_addr), user2)
  expectId(await althea_db.get_registered_exit_with_wg_key(user2.wg_key), user2)
  expectId(await althea_db.get_registered_exit_with_mesh_ip(user2.mesh_ip), user2)

  if (opts.try_duplicate) {
    await althea_db.add_registered_exit(user1)
  }
  if (opts.try_partial_dup) {
    await althea_db.add_registered_exit(partialDup)
  }

  await althea_db.remove_registered_exit(user1ButDifferentRegions)
  expectId(await althea_db.get_registered_exit_with_eth_addr(user1.eth_addr), nullUser)
  expectId(await althea_db.get_registered_exit_with_wg_key(user1.wg_key), nullUser)
  expectId(await althea_db.get_registered_exit_with_mesh_ip(user1.mesh_ip), nullUser)
  expectId(await althea_db.get_registered_exit_with_eth_addr(user2.eth_addr), user2)
  expectId(await althea_db.get_registered_exit_with_wg_key(user2.wg_key), user2)
  expectId(await althea_db.get_registered_exit_with_mesh_ip(user2.mesh_ip), user2)
}



describe("Althea exit DB tests", function () {
  it("throws on unauthorized caller", async function () {
    await expect(addUser({ with_admin: false, try_duplicate: false, try_partial_dup: false })
    ).to.be.revertedWith(
      "UnathorizedCaller()"
    );
  });
  it("User registration happy path", async function () {
    addUser({ with_admin: true, try_duplicate: false, try_partial_dup: false })
  });
  it("throws on User duplicate", async function () {
    await expect(addUser({ with_admin: true, try_duplicate: true, try_partial_dup: false })
    ).to.be.revertedWith(
      "DuplicateUser()"
    );
  });
  it("throws on User partial duplicate", async function () {
    await expect(addUser({ with_admin: true, try_duplicate: true, try_partial_dup: true })
    ).to.be.revertedWith(
      "DuplicateUser()"
    );
  });
  it("throws on unauthorized caller", async function () {
    await expect(addExit({ with_admin: false, try_duplicate: false, try_partial_dup: false })
    ).to.be.revertedWith(
      "UnathorizedCaller()"
    );
  });
  it("Exit registration happy path", async function () {
    addExit({ with_admin: true, try_duplicate: false, try_partial_dup: false })
  });
  it("throws on Exit duplicate", async function () {
    await expect(addExit({ with_admin: true, try_duplicate: true, try_partial_dup: false })
    ).to.be.revertedWith(
      "DuplicateUser()"
    );
  });
  it("throws on Exit partial duplicate", async function () {
    await expect(addExit({ with_admin: true, try_duplicate: true, try_partial_dup: true })
    ).to.be.revertedWith(
      "DuplicateUser()"
    );
  });
});
