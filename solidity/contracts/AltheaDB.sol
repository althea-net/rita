//SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21; // Force solidity compliance

/// Identity struct
struct Identity {
    uint128 mesh_ip;
    uint256 wg_key;
    address eth_addr;
}

/// Identity struct for an exit, including a list of allowed region codes
/// This is to protect a user from connecting to an exit that does not allow
/// their region despite providing the best connection metrics otherwise
/// The payment types specification prevents clients from moving to exits
/// that do not accept their tokens as payment
struct ExitIdentity {
    uint128 mesh_ip;
    uint256 wg_key;
    address eth_addr;
    uint16 registration_port;
    uint16 wg_exit_listen_port;
    uint256[] allowed_regions;
    uint256[] payment_types;
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

    // List of regsitered clients
    Identity[] public state_registeredUsers;
    // List of regsitered exits
    ExitIdentity[] public state_registeredExits;

    // Mappings for duplicate checking
    mapping(uint128 => bool) public state_registeredIps;
    mapping(uint256 => bool) public state_registeredKey;
    mapping(address => bool) public state_registeredAddr;

    event UserRegisteredEvent(Identity indexed _user);
    event UserRemovedEvent(Identity indexed _user);
    event ExitRegisteredEvent(ExitIdentity indexed _user);
    event ExitRemovedEvent(ExitIdentity indexed _user);
    event UserAdminAddedEvent(address indexed _admin);
    event UserAdminRemovedEvent(address indexed _admin);
    event ExitAdminAddedEvent(address indexed _admin);
    event ExitAdminRemovedEvent(address indexed _admin);

    constructor(address _admin) {
        state_admin = _admin;
    }

    // start utility function

    // Used to convert an exit identity struct to an identity struct essentially just dropping the
    // region codes component. This is mostly used for comparison and duplicate checking as we want
    // to ignore the region codes when adding and removing an exit to avoid having identical exits
    // with different region codes.
    function exitIdToId(
        ExitIdentity memory input
    ) public pure returns (Identity memory) {
        return
            Identity({
                mesh_ip: input.mesh_ip,
                wg_key: input.wg_key,
                eth_addr: input.eth_addr
            });
    }

    function getNullIdentity() public pure returns (Identity memory) {
        return Identity({mesh_ip: 0, wg_key: 0, eth_addr: address(0)});
    }

    function getNullExitIdentity() public pure returns (ExitIdentity memory) {
        uint256[] memory empty_array;
        return
            ExitIdentity({
                mesh_ip: 0,
                wg_key: 0,
                eth_addr: address(0),
                registration_port: 0,
                wg_exit_listen_port: 0,
                allowed_regions: empty_array,
                payment_types: empty_array
            });
    }

    function isNullIdentity(
        Identity calldata input
    ) public pure returns (bool) {
        return identitiesAreEqual(input, getNullIdentity());
    }

    function identitiesAreEqual(
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

    function isUserAdmin(address potential_admin) public view returns (bool) {
        for (uint256 i = 0; i < state_UserAdmins.length; i++) {
            if (potential_admin == state_UserAdmins[i]) {
                return true;
            }
        }
        return false;
    }

    function isExitAdmin(address potential_admin) public view returns (bool) {
        for (uint256 i = 0; i < state_ExitAdmins.length; i++) {
            if (potential_admin == state_ExitAdmins[i]) {
                return true;
            }
        }
        return false;
    }

    /// Deletes an entry of the provided array
    function deleteArrayEntry(uint index, Identity[] storage array) private {
        require(index < array.length);
        // copy the last element into the index that we want to delete
        // in the case that we want to delete the last element, just skip this
        if (index != array.length - 1) {
            array[index] = array[array.length - 1];
        }
        // drop the new duplicated end element effectively deleting the originally
        // specified index
        array.pop();
    }

    /// Deletes an entry of the provided array
    function deleteArrayEntry(
        uint index,
        ExitIdentity[] storage array
    ) private {
        require(index < array.length);
        // copy the last element into the index that we want to delete
        // in the case that we want to delete the last element, just skip this
        if (index != array.length - 1) {
            array[index] = array[array.length - 1];
        }
        // drop the new duplicated end element effectively deleting the originally
        // specified index
        array.pop();
    }

    /// Deletes an entry of the provided array
    function deleteArrayEntry(uint index, address[] storage array) private {
        require(index < array.length);
        // copy the last element into the index that we want to delete
        // in the case that we want to delete the last element, just skip this
        if (index != array.length - 1) {
            array[index] = array[array.length - 1];
        }
        // drop the new duplicated end element effectively deleting the originally
        // specified index
        array.pop();
    }

    function getIndexOfId(
        Identity memory id,
        Identity[] memory array
    ) private pure returns (uint256) {
        for (uint256 i = 0; i < array.length; i++) {
            if (identitiesAreEqual(array[i], id)) {
                return i;
            }
        }
        revert IdentityNotFound();
    }

    function getIndexOfId(
        ExitIdentity memory id,
        ExitIdentity[] memory array
    ) private pure returns (uint256) {
        for (uint256 i = 0; i < array.length; i++) {
            if (identitiesAreEqual(exitIdToId(array[i]), exitIdToId(id))) {
                return i;
            }
        }
        revert IdentityNotFound();
    }

    function getIndexOfAdmin(
        address admin,
        address[] memory array
    ) private pure returns (uint256) {
        for (uint256 i = 0; i < array.length; i++) {
            if (admin == array[i]) {
                return i;
            }
        }
        revert AdminNotFound();
    }

    /// Checks both the exit and the client lists for any entry with any
    /// sort of duplicate ID component
    function checkForAnyDuplicates(
        Identity memory entry
    ) public view returns (bool) {
        if (state_registeredIps[entry.mesh_ip] == true) {
            return true;
        }

        if (state_registeredKey[entry.wg_key] == true) {
            return true;
        }

        if (state_registeredAddr[entry.eth_addr] == true) {
            return true;
        }

        return false;
    }

    // start user and exit management functions

    // Add a new registered user
    function addRegisteredUser(Identity calldata entry) public {
        if (isUserAdmin(msg.sender)) {
            // if any client or exit currently registered has overlapping data, do not allow the
            // registration to continue
            if (checkForAnyDuplicates(entry)) {
                revert DuplicateUser();
            }

            state_registeredIps[entry.mesh_ip] = true;
            state_registeredKey[entry.wg_key] = true;
            state_registeredAddr[entry.eth_addr] = true;

            state_registeredUsers.push(entry);
            emit UserRegisteredEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Utility function that registers users in bulk within a single transaction
    function addRegisteredUsersBulk(Identity[] calldata users) public {
        for (uint256 i = 0; i < users.length; i++) {
            addRegisteredUser(users[i]);
        }
    }

    // Remove a new registered user
    function removeRegisteredUser(Identity calldata entry) public {
        if (isUserAdmin(msg.sender)) {
            uint256 index = getIndexOfId(entry, state_registeredUsers);
            deleteArrayEntry(index, state_registeredUsers);

            state_registeredAddr[entry.eth_addr] = false;
            state_registeredIps[entry.mesh_ip] = false;
            state_registeredKey[entry.wg_key] = false;

            emit UserRemovedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Utility function that removes exits in bulk within a single transaction
    function removeRegisteredUsersBulk(Identity[] calldata users) public {
        for (uint256 i = 0; i < users.length; i++) {
            removeRegisteredUser(users[i]);
        }
    }

    // Add a new registered exit
    function addRegisteredExit(ExitIdentity calldata entry) public {
        if (isExitAdmin(msg.sender)) {
            // if any client or exit currently registered has overlapping data, do not allow the
            // registration to continue
            if (checkForAnyDuplicates(exitIdToId(entry))) {
                revert DuplicateUser();
            }

            state_registeredIps[entry.mesh_ip] = true;
            state_registeredKey[entry.wg_key] = true;
            state_registeredAddr[entry.eth_addr] = true;

            state_registeredExits.push(entry);
            emit ExitRegisteredEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Utility function that registers exits in bulk within a single transaction
    function addRegisteredExitsBulk(ExitIdentity[] calldata exits) public {
        for (uint256 i = 0; i < exits.length; i++) {
            addRegisteredExit(exits[i]);
        }
    }

    // Remove a new registered exit
    function removeRegisteredExit(ExitIdentity calldata entry) public {
        if (isExitAdmin(msg.sender)) {
            uint256 index = getIndexOfId(entry, state_registeredExits);
            deleteArrayEntry(index, state_registeredExits);

            state_registeredAddr[entry.eth_addr] = false;
            state_registeredIps[entry.mesh_ip] = false;
            state_registeredKey[entry.wg_key] = false;

            emit ExitRemovedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Utility function that removes exits in bulk within a single transaction
    function removeRegisteredExitsBulk(ExitIdentity[] calldata exits) public {
        for (uint256 i = 0; i < exits.length; i++) {
            removeRegisteredExit(exits[i]);
        }
    }

    // start user query functions

    function getAllRegisteredUsers() public view returns (Identity[] memory) {
        return state_registeredUsers;
    }

    function getAllRegisteredExits()
        public
        view
        returns (ExitIdentity[] memory)
    {
        return state_registeredExits;
    }

    function getRegisteredClientWithWgKey(
        uint256 wg_key
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredUsers.length; i++) {
            if (state_registeredUsers[i].wg_key == wg_key) {
                return state_registeredUsers[i];
            }
        }
        return getNullIdentity();
    }

    function getRegisteredClientWithMeshIp(
        uint128 mesh_ip
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredUsers.length; i++) {
            if (state_registeredUsers[i].mesh_ip == mesh_ip) {
                return state_registeredUsers[i];
            }
        }
        return getNullIdentity();
    }

    function getRegisteredClientWithEthAddr(
        address eth_addr
    ) public view returns (Identity memory) {
        for (uint256 i = 0; i < state_registeredUsers.length; i++) {
            if (state_registeredUsers[i].eth_addr == eth_addr) {
                return state_registeredUsers[i];
            }
        }
        return getNullIdentity();
    }

    function getRegisteredExitWithWgKey(
        uint256 wg_key
    ) public view returns (ExitIdentity memory) {
        for (uint256 i = 0; i < state_registeredExits.length; i++) {
            if (state_registeredExits[i].wg_key == wg_key) {
                return state_registeredExits[i];
            }
        }
        return getNullExitIdentity();
    }

    function getRegisteredExitWithMeshIp(
        uint128 mesh_ip
    ) public view returns (ExitIdentity memory) {
        for (uint256 i = 0; i < state_registeredExits.length; i++) {
            if (state_registeredExits[i].mesh_ip == mesh_ip) {
                return state_registeredExits[i];
            }
        }
        return getNullExitIdentity();
    }

    function getRegisteredExitWithEthAddr(
        address eth_addr
    ) public view returns (ExitIdentity memory) {
        for (uint256 i = 0; i < state_registeredExits.length; i++) {
            if (state_registeredExits[i].eth_addr == eth_addr) {
                return state_registeredExits[i];
            }
        }
        return getNullExitIdentity();
    }

    // start admin management functions

    // Add a new user admin
    function addUserAdmin(address entry) public {
        if (state_admin == msg.sender) {
            if (isUserAdmin(entry)) {
                revert DuplicateAdmin();
            }

            state_UserAdmins.push(entry);
            emit UserAdminAddedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Remove a user admin
    function removeUserAdmin(address entry) public {
        if (state_admin == msg.sender) {
            uint256 index = getIndexOfAdmin(entry, state_UserAdmins);
            deleteArrayEntry(index, state_UserAdmins);
            emit UserAdminAddedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Add a new exit admin
    function addExitAdmin(address entry) public {
        if (state_admin == msg.sender) {
            if (isExitAdmin(entry)) {
                revert DuplicateAdmin();
            }

            state_ExitAdmins.push(entry);
            emit ExitAdminAddedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }

    // Remove a exit admin
    function removeExitAdmin(address entry) public {
        if (state_admin == msg.sender) {
            uint256 index = getIndexOfAdmin(entry, state_ExitAdmins);
            deleteArrayEntry(index, state_ExitAdmins);
            emit UserAdminAddedEvent(entry);
        } else {
            revert UnathorizedCaller();
        }
    }
}
