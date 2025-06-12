// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
contract AccessControlContract {
    address public owner; // Address of the contract owner
    bytes32[] public blockIDS; // Array of hashed block IDs associated with the record
    uint256 public recordFee; // Fee required to access the record
    uint256 public refundWindow; // Time window for refund requests
    bytes public publicKey; // Buyer public key for encryption/decryption
    bytes32 public recordID; // Unique identifier for the record
    bool public proofOfEncryption; // Placeholder for proof of encryption (assume true for now)
    mapping(address => mapping(uint256 => uint256[])) public access_table;

    struct Request {
        address requester_address; // Address of the buyer requesting access
        uint256 expire;   // Timestamp when the request expires
    }

    mapping(address => Request) public requests; // Array of requests made by buyers

    constructor(
        bytes32[] memory _blockIDS,
        uint256 _recordFee,
        uint256 _refundWindow,
        bytes memory _publicKey,
        bytes32 _recordID
    ) {
        owner = msg.sender;
        blockIDS = _blockIDS;
        recordFee = _recordFee;
        refundWindow = _refundWindow;
        publicKey = _publicKey;
        recordID = _recordID;
        proofOfEncryption = true; // Placeholder for proof of encryption
    }

    // Function called by the buyer to request access to the record
    function requestRecordAccess(bytes32[] memory blockIDs) external payable {
    require(msg.value >= recordFee, "Insufficient fee");
    require(keccak256(abi.encodePacked(blockIDs)) == recordID, "Invalid recordID/blockIDs");
    requests[msg.sender] = Request({
        requester_address: msg.sender,
        expire: block.timestamp + refundWindow
    });
}

function withdrawFunds(
    address buyer,
    uint256[] memory gamma,
    bytes32[] memory hash_gamma,
    bytes32[] memory blockID,
    bytes[] memory PoD
) external {
    Request storage request = requests[buyer];
    require(request.requester_address != address(0), "Buyer Record Request not found");
    require(block.timestamp < request.expire, "Buyer Request expired");
    require(msg.sender == owner, "Only owner can withdraw");
    require(
        gamma.length == hash_gamma.length &&
        gamma.length == blockID.length &&
        gamma.length == PoD.length,
        "Array length mismatch"
    );

    for (uint256 i = 0; i < blockID.length; i++) {
        bytes32 hashed = keccak256(abi.encodePacked(gamma[i]));
        require(hash_gamma[i] == hashed, "Hash mismatch");
        bytes32 expected_message = keccak256(abi.encodePacked(blockID[i], hash_gamma[i]));
        require(verify(buyer, PoD[i], expected_message), "PoD verification failed");
        access_table[buyer][i].push(uint256(gamma[i]));
    }

    // Prevent re-entrancy and double-withdrawal
    delete requests[buyer];

    (bool sent, ) = payable(owner).call{value: recordFee}("");
    require(sent, "Failed to send Ether");
}

    // ECDSA signature verification - Updated to handle Ethereum signed message hash
    function verify(
        address buyer,
        bytes memory PoD,
        bytes32 expected_message
    ) public pure returns (bool) {
        // Create Ethereum signed message hash
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", expected_message)
        );

        address recovered = ECDSA.recover(ethSignedMessageHash, PoD);
        return (recovered == buyer);
    }

    // Fallback to receive Ether
    receive() external payable {}
}