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
  remove_admin: boolean,
  cross_dup: boolean,
  dup_admin: boolean,
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
  let user3 = {
    mesh_ip: "0xfd001901",
    wg_key: "0xEEEBD",
    eth_addr: "0x640FF2f8bdFf5C5557EdE687CEe71f6afB187f89",
  };
  let user4 = {
    mesh_ip: "0xfd001981",
    wg_key: "0xAAABD",
    eth_addr: "0xF7b6E038c24b9d71977Adc8334c296CaD3E5a4dC",
  };
  let user5 = {
    mesh_ip: "0xfd001081",
    wg_key: "0xAFFFD",
    eth_addr: "0xa19F0E22B2A2A7756F3964D0018f70dbf9657c9f",
  };
  let partialDup = {
    mesh_ip: "0xfd001338",
    wg_key: "0xAFEDB",
    eth_addr: "0x154CB202089D58efB56a2B11ce812Ae3882fE1f3",
  };
  let crossDup = {
    mesh_ip: "0xfd001338",
    wg_key: "0xAFEDB",
    eth_addr: "0x154CB202089D58efB56a2B11ce812Ae3882fE1f3",
    registration_port: "0xFF",
    wg_exit_listen_port: "0xEE",
    allowed_regions: [],
    payment_types: []
  };
  let nullUser = {
    mesh_ip: "0x0",
    wg_key: "0x0",
    eth_addr: "0x0000000000000000000000000000000000000000",
  };
  const { althea_db } = await deployContracts(sender);
  if (opts.with_admin) {
    await althea_db.addUserAdmin(await sender?.getAddress());

    if (opts.dup_admin) {
      await althea_db.addUserAdmin(await sender?.getAddress());
    }
  }
  // add a bunch of admins to make sure we delete the right one
  await althea_db.addUserAdmin(await signers[1].getAddress());
  await althea_db.addUserAdmin(await signers[2].getAddress());
  await althea_db.addUserAdmin(await signers[3].getAddress());

  await althea_db.addRegisteredUser(user1)
  expectId(await althea_db.getRegisteredClientWithEthAddr(user1.eth_addr), user1)
  expectId(await althea_db.getRegisteredClientWithWgKey(user1.wg_key), user1)
  expectId(await althea_db.getRegisteredClientWithMeshIp(user1.mesh_ip), user1)
  await althea_db.addRegisteredUser(user2)
  expectId(await althea_db.getRegisteredClientWithEthAddr(user2.eth_addr), user2)
  expectId(await althea_db.getRegisteredClientWithWgKey(user2.wg_key), user2)
  expectId(await althea_db.getRegisteredClientWithMeshIp(user2.mesh_ip), user2)
  await althea_db.addRegisteredUser(user3)
  expectId(await althea_db.getRegisteredClientWithEthAddr(user3.eth_addr), user3)
  expectId(await althea_db.getRegisteredClientWithWgKey(user3.wg_key), user3)
  expectId(await althea_db.getRegisteredClientWithMeshIp(user3.mesh_ip), user3)
  await althea_db.addRegisteredUser(user4)
  expectId(await althea_db.getRegisteredClientWithEthAddr(user4.eth_addr), user4)
  expectId(await althea_db.getRegisteredClientWithWgKey(user4.wg_key), user4)
  expectId(await althea_db.getRegisteredClientWithMeshIp(user4.mesh_ip), user4)
  await althea_db.addRegisteredUser(user5)
  expectId(await althea_db.getRegisteredClientWithEthAddr(user5.eth_addr), user5)
  expectId(await althea_db.getRegisteredClientWithWgKey(user5.wg_key), user5)
  expectId(await althea_db.getRegisteredClientWithMeshIp(user5.mesh_ip), user5)
  expect((await althea_db.getAllRegisteredUsers()).length).to.equal(5)


  if (opts.try_duplicate) {
    await althea_db.addRegisteredUser(user1)
  }
  if (opts.try_partial_dup) {
    await althea_db.addRegisteredUser(partialDup)
  }
  if (opts.remove_admin) {
    await althea_db.removeUserAdmin(await sender?.getAddress());

    // make sure the other admins are still there
    assert(await althea_db.isUserAdmin(await signers[1].getAddress()));
  }
  if (opts.cross_dup) {
    await althea_db.addExitAdmin(await sender?.getAddress());
    await althea_db.addRegisteredExit(crossDup)
  }

  await althea_db.removeRegisteredUser(user1)
  expectId(await althea_db.getRegisteredClientWithEthAddr(user1.eth_addr), nullUser)
  expectId(await althea_db.getRegisteredClientWithWgKey(user1.wg_key), nullUser)
  expectId(await althea_db.getRegisteredClientWithMeshIp(user1.mesh_ip), nullUser)
  expectId(await althea_db.getRegisteredClientWithEthAddr(user2.eth_addr), user2)
  expectId(await althea_db.getRegisteredClientWithWgKey(user2.wg_key), user2)
  expectId(await althea_db.getRegisteredClientWithMeshIp(user2.mesh_ip), user2)
}

async function addExit(opts: {
  with_admin: boolean,
  try_duplicate: boolean,
  try_partial_dup: boolean,
  remove_admin: boolean,
  cross_dup: boolean,
  dup_admin: boolean
}) {
  const signers = await ethers.getSigners();
  const sender = signers[0];
  let user1 = {
    mesh_ip: "0xfd001337",
    wg_key: "0xAFEDB",
    eth_addr: "0x054CA202089D58efB56a2B11ce812Ae3882fE1f3",
    registration_port: "0xFF",
    wg_exit_listen_port: "0xEE",
    allowed_regions: [1, 3],
    payment_types: [5, 6],
  };
  let user1ButDifferentRegions = {
    mesh_ip: "0xfd001337",
    wg_key: "0xAFEDB",
    eth_addr: "0x054CA202089D58efB56a2B11ce812Ae3882fE1f3",
    registration_port: "0xFF",
    wg_exit_listen_port: "0xEE",
    allowed_regions: [16, 25],
    payment_types: [8, 9],
  };
  let user2 = {
    mesh_ip: "0xfd001329",
    wg_key: "0xAFEDD",
    eth_addr: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    registration_port: "0xFF",
    wg_exit_listen_port: "0xEE",
    allowed_regions: [],
    payment_types: []
  };
  let partialDup = {
    mesh_ip: "0xfd001338",
    wg_key: "0xAFEDB",
    eth_addr: "0x154CB202089D58efB56a2B11ce812Ae3882fE1f3",
    registration_port: "0xFF",
    wg_exit_listen_port: "0xEE",
    allowed_regions: [],
    payment_types: []
  };
  let crossDup = {
    mesh_ip: "0xfd001338",
    wg_key: "0xAFEDB",
    eth_addr: "0x154CB202089D58efB56a2B11ce812Ae3882fE1f3",
  };
  let nullUser = {
    mesh_ip: "0x0",
    wg_key: "0x0",
    eth_addr: "0x0000000000000000000000000000000000000000",
    registration_port: "0xFF",
    wg_exit_listen_port: "0xEE",
    allowed_regions: [],
    payment_types: []
  };
  const { althea_db } = await deployContracts(sender);
  if (opts.with_admin) {
    await althea_db.addExitAdmin(await sender?.getAddress());

    if (opts.dup_admin) {
      await althea_db.addExitAdmin(await sender?.getAddress());
    }
  }
  await althea_db.addExitAdmin(await signers[1].getAddress());
  await althea_db.addExitAdmin(await signers[2].getAddress());
  await althea_db.addExitAdmin(await signers[3].getAddress());

  await althea_db.addRegisteredExit(user1)
  expectId(await althea_db.getRegisteredExitWithEthAddr(user1.eth_addr), user1)
  expectId(await althea_db.getRegisteredExitWithWgKey(user1.wg_key), user1)
  expectId(await althea_db.getRegisteredExitWithMeshIp(user1.mesh_ip), user1)
  await althea_db.addRegisteredExit(user2)
  expectId(await althea_db.getRegisteredExitWithEthAddr(user2.eth_addr), user2)
  expectId(await althea_db.getRegisteredExitWithWgKey(user2.wg_key), user2)
  expectId(await althea_db.getRegisteredExitWithMeshIp(user2.mesh_ip), user2)

  if (opts.try_duplicate) {
    await althea_db.addRegisteredExit(user1)
  }
  if (opts.try_partial_dup) {
    await althea_db.addRegisteredExit(partialDup)
  }
  if (opts.remove_admin) {
    await althea_db.removeExitAdmin(await sender?.getAddress());

    // make sure the other admins are still there
    assert(await althea_db.isExitAdmin(await signers[1].getAddress()));
  }
  if (opts.cross_dup) {
    await althea_db.addUserAdmin(await sender?.getAddress());
    await althea_db.addRegisteredUser(crossDup)
  }

  await althea_db.removeRegisteredExit(user1ButDifferentRegions)
  expectId(await althea_db.getRegisteredExitWithEthAddr(user1.eth_addr), nullUser)
  expectId(await althea_db.getRegisteredExitWithWgKey(user1.wg_key), nullUser)
  expectId(await althea_db.getRegisteredExitWithMeshIp(user1.mesh_ip), nullUser)
  expectId(await althea_db.getRegisteredExitWithEthAddr(user2.eth_addr), user2)
  expectId(await althea_db.getRegisteredExitWithWgKey(user2.wg_key), user2)
  expectId(await althea_db.getRegisteredExitWithMeshIp(user2.mesh_ip), user2)
}



describe("Althea exit DB tests", function () {
  it("throws on Client unauthorized caller", async function () {
    await expect(addUser({ with_admin: false, try_duplicate: false, try_partial_dup: false, remove_admin: false, cross_dup: false, dup_admin: false })
    ).to.be.revertedWith(
      "unauthorized"
    );
  });
  it("throws on Client admin removed", async function () {
    await expect(addUser({ with_admin: true, try_duplicate: false, try_partial_dup: false, remove_admin: true, cross_dup: false, dup_admin: false })
    ).to.be.revertedWith(
      "unauthorized"
    );
  });
  it("throws on Dup Client admin", async function () {
    await expect(addUser({ with_admin: true, try_duplicate: false, try_partial_dup: false, remove_admin: true, cross_dup: false, dup_admin: true })
    ).to.be.revertedWith(
      "duplicate"
    );
  });
  it("User registration happy path", async function () {
    addUser({ with_admin: true, try_duplicate: false, try_partial_dup: false, remove_admin: false, cross_dup: false, dup_admin: false })
  });
  it("throws on User duplicate", async function () {
    await expect(addUser({ with_admin: true, try_duplicate: true, try_partial_dup: false, remove_admin: false, cross_dup: false, dup_admin: false })
    ).to.be.revertedWith(
      "duplicate"
    );
  });
  it("throws on User cross duplicate", async function () {
    await expect(addUser({ with_admin: true, try_duplicate: true, try_partial_dup: false, remove_admin: false, cross_dup: true, dup_admin: false })
    ).to.be.revertedWith(
      "duplicate"
    );
  });
  it("throws on User partial duplicate", async function () {
    await expect(addUser({ with_admin: true, try_duplicate: true, try_partial_dup: true, remove_admin: false, cross_dup: false, dup_admin: false })
    ).to.be.revertedWith(
      "duplicate"
    );
  });
  it("throws on Exit unauthorized caller", async function () {
    await expect(addExit({ with_admin: false, try_duplicate: false, try_partial_dup: false, remove_admin: false, cross_dup: false, dup_admin: false })
    ).to.be.revertedWith(
      "unauthorized"
    );
  });
  it("throws on Exit admin removed", async function () {
    await expect(addExit({ with_admin: true, try_duplicate: false, try_partial_dup: false, remove_admin: true, cross_dup: false, dup_admin: false })
    ).to.be.revertedWith(
      "unauthorized"
    );
  });
  it("throws on Dup Exit admin", async function () {
    await expect(addExit({ with_admin: true, try_duplicate: false, try_partial_dup: false, remove_admin: true, cross_dup: false, dup_admin: true })
    ).to.be.revertedWith(
      "duplicate"
    );
  });
  it("Exit registration happy path", async function () {
    addExit({ with_admin: true, try_duplicate: false, try_partial_dup: false, remove_admin: false, cross_dup: false, dup_admin: false })
  });
  it("throws on Exit duplicate", async function () {
    await expect(addExit({ with_admin: true, try_duplicate: true, try_partial_dup: false, remove_admin: false, cross_dup: false, dup_admin: false })
    ).to.be.revertedWith(
      "duplicate"
    );
  });
  it("throws on Exit cross duplicate", async function () {
    await expect(addExit({ with_admin: true, try_duplicate: true, try_partial_dup: false, remove_admin: false, cross_dup: true, dup_admin: false })
    ).to.be.revertedWith(
      "duplicate"
    );
  });
  it("throws on Exit partial duplicate", async function () {
    await expect(addExit({ with_admin: true, try_duplicate: true, try_partial_dup: true, remove_admin: false, cross_dup: false, dup_admin: false })
    ).to.be.revertedWith(
      "duplicate"
    );
  });
});
