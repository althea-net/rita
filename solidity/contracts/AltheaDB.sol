//SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21; // Force solidity compliance

/// Identity struct
struct Identity {
    uint128 mesh_ip;
    uint256 wg_key;
    address eth_addr;
}

/// Thrown when the caller is not authorized to register users
error UnathorizedCaller();
error DuplicateUser();
error DuplicateAdmin();
error IdentityNotFound();
error AdminNotFound();

contract AltheaDB {
    /// The admin address that is allowed to update who is on the
    /// user admin and exit admin lists. This could be an individual
    /// account or a multisig
    address public immutable state_admin;
    /// A list of addresses allowed to add and remove users from the list of users
    address[] public state_UserAdmins;
    /// A list of addresses allowed to add and remove exits from the list of exits
    address[] public state_ExitAdmins;

    // Mappings to regsitered clients
    Identity[] public state_registeredUsers;
    // Mappings to regsitered exits
    Identity[] public state_registeredExits;

    event UserRegisteredEvent(Identity indexed _user);
    event UserRemovedEvent(Identity indexed _user);
    event ExitRegisteredEvent(Identity indexed _user);
    event ExitRemovedEvent(Identity indexed _user);
    event UserAdminAddedEvent(address indexed _admin);
    event UserAdminRemovedEvent(address indexed _admin);
    event ExitAdminAddedEvent(address indexed _admin);
    event ExitAdminRemovedEvent(address indexed _admin);

    constructor(address _admin) {
        state_admin = _admin;
    }

    // start utility function 

    function get_null_identity() public pure returns (Identity memory) {
        return Identity({mesh_ip: 0, wg_key: 0, eth_addr: address(0)});
    }

    function is_null_identity(
        Identity calldata input
    ) public pure returns (bool) {
        return identities_are_equal(input, get_null_identity());
    }

    function identities_are_equal(
        Identity memory a,
        Identity memory b
    ) public pure returns (bool) {
        if (a.mesh_ip != b.mesh_ip) {
            return false;
        }
        if (a.wg_key != b.wg_key) {
            return false;
        }
        if (a.eth_addr != b.eth_addr) {
            return false;
        }
        return true;
    }

    function is_user_admin(address potential_admin) public view returns (bool) {
        for (uint256 i = 0; i < state_UserAdmins.length; i++) {
            if (potential_admin == state_UserAdmins[i]) {
                return true;
            }
        }
        return false;
    }

    function is_exit_admin(address potential_admin) public view returns (bool) {
        for (uint256 i = 0; i < state_ExitAdmins.length; i++) {
            if (potential_admin == state_ExitAdmins[i]) {
                return true;
            }
        }
        return false;
    }

    /// Deletes an entry of the provided array
    function delete_array_entry(uint index, Identity[] storage array) private {
        require(index < array.length);
        // copy the last element into the index that we want to delete
        // in the case that we want to delete the last element, just skip this
        if (index != array.length -1) {
            array[index] = array[array.length - 1];
        }
        // drop the new duplicated end element effectively deleting the originally
        // specified index
        array.pop();
    }

    /// Deletes an entry of the provided array
    function delete_array_entry(uint index, address[] storage array) private {
        require(index < array.length);
        // copy the last element into the index that we want to delete
        // in the case that we want to delete the last element, just skip this
        if (index != array.length -1) {
            array[index] = array[array.length - 1];
        }
        // drop the new duplicated end element effectively deleting the originally
        // specified index
        array.pop();
    }

    function get_index_of_id(Identity memory id, Identity[] memory array) private pure returns (uint256) {
        for (uint256 i = 0; i < array.length; i++) {
            if (identities_are_equal(array[i], id)) {
                return i;
            }
        }
        revert IdentityNotFound();
    }

    function get_index_of_admin(address admin, address[] memory array) private pure returns (uint256) {
        for (uint256 i = 0; i < array.length; i++) {
            if (admin == array[i]) {
                return i;
            }
        }
        revert AdminNotFound();
    }

    /// Checks both the exit and the client lists for any entry with any
    /// sort of duplicate ID component
    function check_for_any_duplicates(
        Identity calldata entry
    ) public view returns (bool) {
        if (
            !identities_are_equal(
                get_registered_exit_with_eth_addr(entry.eth_addr),
                get_null_identity()
            )
        ) {
            return true;
        }
        if (
            !identities_are_equal(
                get_registered_exit_with_mesh_ip(entry.mesh_ip),
                get_null_identity()
            )
        ) {
            return true;
        }
        if (
            !identities_are_equal(
                get_registered_exit_with_wg_key(entry.wg_key),
                get_null_identity()
            )
        ) {
            return true;
        }

        if (
            !identities_are_equal(
                get_registered_client_with_eth_addr(entry.eth_addr),
                get_null_identity()
            )
        ) {
            return true;
        }
        if (
            !identities_are_equal(
                get_registered_client_with_mesh_ip(entry.mesh_ip),
                get_null_identity()
            )
        ) {
            return true;
        }
        if (
            !identities_are_equal(
                get_registered_client_with_wg_key(entry.wg_key),
                get_null_identity()
            )
        ) {
            return true;
        }
        return false;
    }

    // start user and exit management functions

    // Add a new registered user
    function add_registered_user(Identity calldata entry) public {
        if (is_user_admin(msg.sender)) {
            // if any client or exit currently registered has overlapping data, do not allow the
            // registration to continue
            if (check_for_any_duplicates(entry)) {
                revert DuplicateUser();
            }

            state_registeredUsers.push(entry);
            emit UserRegisteredEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Remove a new registered user
    function remove_registered_user(Identity calldata entry) public {
        if (is_user_admin(msg.sender)) {
            uint256 index = get_index_of_id(entry, state_registeredUsers);
            delete_array_entry(index, state_registeredUsers);
            emit UserRemovedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Add a new registered exit
    function add_registered_exit(Identity calldata entry) public {
        if (is_exit_admin(msg.sender)) {
            // if any client or exit currently registered has overlapping data, do not allow the
            // registration to continue
            if (check_for_any_duplicates(entry)) {
                revert DuplicateUser();
            }

            state_registeredExits.push(entry);
            emit ExitRegisteredEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Remove a new registered exit
    function remove_registered_exit(Identity calldata entry) public {
        if (is_exit_admin(msg.sender)) {
            uint256 index = get_index_of_id(entry, state_registeredExits);
            delete_array_entry(index, state_registeredExits);
            emit ExitRemovedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // start user query functions


    function get_registered_client_with_wg_key(
        uint256 wg_key
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredUsers.length; i++) {
            if (state_registeredUsers[i].wg_key == wg_key) {
                return state_registeredUsers[i];
            }
        }
        return get_null_identity();
    }

    function get_registered_client_with_mesh_ip(
        uint128 mesh_ip
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredUsers.length; i++) {
            if (state_registeredUsers[i].mesh_ip == mesh_ip) {
                return state_registeredUsers[i];
            }
        }
        return get_null_identity();
    }

    function get_registered_client_with_eth_addr(
        address eth_addr
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredUsers.length; i++) {
            if (state_registeredUsers[i].eth_addr == eth_addr) {
                return state_registeredUsers[i];
            }
        }
        return get_null_identity();
    }

    function get_registered_exit_with_wg_key(
        uint256 wg_key
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredExits.length; i++) {
            if (state_registeredExits[i].wg_key == wg_key) {
                return state_registeredExits[i];
            }
        }
        return get_null_identity();
    }

    function get_registered_exit_with_mesh_ip(
        uint128 mesh_ip
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredExits.length; i++) {
            if (state_registeredExits[i].mesh_ip == mesh_ip) {
                return state_registeredExits[i];
            }
        }
        return get_null_identity();
    }

    function get_registered_exit_with_eth_addr(
        address eth_addr
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredExits.length; i++) {
            if (state_registeredExits[i].eth_addr == eth_addr) {
                return state_registeredExits[i];
            }
        }
        return get_null_identity();
    }

    // start admin management functions

    // Add a new user admin
    function add_user_admin(address entry) public {
        if (state_admin == msg.sender) {
            if (is_user_admin(entry)) {
                revert DuplicateAdmin();
            }

            state_UserAdmins.push(entry);
            emit UserAdminAddedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Remove a user admin
    function remove_user_admin(address entry) public {
        if (state_admin == msg.sender) {
            uint256 index = get_index_of_admin(entry, state_UserAdmins);
            delete_array_entry(index, state_UserAdmins);
            emit UserAdminAddedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Add a new exit admin
    function add_exit_admin(address entry) public {
        if (state_admin == msg.sender) {
            if (is_exit_admin(entry)) {
                revert DuplicateAdmin();
            }

            state_ExitAdmins.push(entry);
            emit ExitAdminAddedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Remove a exit admin
    function remove_exit_admin(address entry) public {
        if (state_admin == msg.sender) {
            uint256 index = get_index_of_admin(entry, state_ExitAdmins);
            delete_array_entry(index, state_ExitAdmins);
            emit UserAdminAddedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }
}
