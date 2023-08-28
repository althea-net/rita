//SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21; // Force solidity compliance

contract AltheaDB {
    constructor() {}

    // Identity struct
    struct Identity {
        string mesh_ip;
        string wg_key;
        address eth_addr;
    }

    // Mappings to regsitered clients
    Identity[] private registered_users;
    mapping(string => Identity) private wg_key_to_reg_users_map;
    mapping(string => Identity) private mesh_ip_to_reg_users_map;
    mapping(address => Identity) private eth_addr_to_reg_users_map;

    // Add a new registered user
    function add_registered_user(Identity memory entry) public {
        registered_users.push(entry);
        wg_key_to_reg_users_map[entry.wg_key] = entry;
        mesh_ip_to_reg_users_map[entry.mesh_ip] = entry;
        eth_addr_to_reg_users_map[entry.eth_addr] = entry;
    }

    // Get all registered users
    function get_all_registered_users()
        public
        view
        returns (Identity[] memory)
    {
        return registered_users;
    }

    function get_registered_client_with_wg_key(
        string memory wg_key
    ) public view returns (Identity memory) {
        return wg_key_to_reg_users_map[wg_key];
    }

    function get_registered_client_with_mesh_ip(
        string memory mesh_ip
    ) public view returns (Identity memory) {
        return mesh_ip_to_reg_users_map[mesh_ip];
    }

    function get_registered_client_with_eth_addr(
        address eth_addr
    ) public view returns (Identity memory) {
        return eth_addr_to_reg_users_map[eth_addr];
    }
}
