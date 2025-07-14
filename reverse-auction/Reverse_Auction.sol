// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/**
 * @title Improved Reverse Auction Contract with ZK Verification
 * @dev Based on ESORICS 2018 paper with modern Solidity best practices and ZK proof verification
 */

import "./verifier.sol";

contract ReverseAuction {
    // Custom errors
    error AuctionEnded();
    error AuctionNotStarted();
    error AuctionNotEnded();
    error InvalidFairnessFee();
    error InvalidBudget();
    error BudgetTooLow();
    error MaxBiddersReached();
    error BidderAlreadyExists();
    error BidderNotFound();
    error NotAuthorized();
    error WinnerAlreadyDetermined();
    error InvalidBidAmount();
    error AlreadyWithdrawn();
    error WithdrawFailed();
    error PaymentFailed();
    error InvalidWinnerData();
    error InvalidProof();
    error VerificationFailed();
    error CommitmentMismatch();

    enum VerificationState { Init, Verified, Finished }

    struct Bidder {
        uint32[8] commit; // Commitment to bid
        uint32 cipher;    // Changed from bytes to uint32 to match proof expectations
        bool paidBack;
        bool existing;
    }

    struct ZKProof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    VerificationState public state;

    mapping(address => Bidder) public bidders;
    address[] public bidderAddresses;

    address public immutable auctioneerAddress;
    uint256 public immutable bidEnd;
    uint256 public immutable revealEnd;
    uint256 public immutable verifyEnd;
    uint256 public immutable withdrawEnd;
    uint256 public immutable maxBiddersCount;
    uint256 public immutable fairnessFees;
    string public auctioneerRSAPublicKey;

    address public winner;
    uint256 public winningBid;
    uint32[8] public winningCommitment;
    bool public immutable testing;
    uint256 public immutable budget;
    
    // Separate accounting for fairness fees collected
    uint256 public totalFairnessFeesCollected;

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private reentrancyStatus;

    bool public destroyed; // New flag to replace selfdestruct

    // ZK Verification components
    Verifier public immutable verifierContract;
    bool public proofVerified;

    // Events
    event BidCommitted(address indexed bidder, uint32[8] commit);
    event BidRevealed(address indexed bidder, uint32 cipher);
    event WinnerDetermined(address indexed winner, uint256 winningBid, uint32[8] winningCommitment);
    event ProofVerified(address indexed verifier, bool success);
    event FairnessFeeWithdrawn(address indexed bidder);
    event WinnerPaymentReceived(address indexed winner, uint256 amount);
    event BudgetRefunded(address indexed buyer, uint256 amount);
    event AuctionDestroyed();

    modifier onlyAuctioneer() {
        if (msg.sender != auctioneerAddress) revert NotAuthorized();
        _;
    }

    modifier nonReentrant() {
        if (reentrancyStatus == ENTERED) revert("ReentrancyGuard: reentrant call");
        reentrancyStatus = ENTERED;
        _;
        reentrancyStatus = NOT_ENTERED;
    }

    modifier onlyDuringBidding() {
        if (!testing && block.number >= bidEnd) revert AuctionEnded();
        _;
    }

    modifier onlyDuringReveal() {
        if (!testing && (block.number <= bidEnd || block.number >= revealEnd)) 
            revert AuctionNotStarted();
        _;
    }

    modifier bidderExists() {
        if (!bidders[msg.sender].existing) revert BidderNotFound();
        _;
    }

    modifier whenNotDestroyed() {
        require(!destroyed, "Contract has been destroyed");
        _;
    }

    constructor(
        uint256 _bidInterval,
        uint256 _revealInterval,
        uint256 _verifyInterval,
        uint256 _maxBiddersCount,
        uint256 _fairnessFees,
        string memory _auctioneerRSAPublicKey,
        address _verifierContract,
        bool _testing  // Added testing parameter
    ) payable {
        if (_maxBiddersCount == 0) revert("Invalid max bidders count");
        if (_fairnessFees == 0) revert("Invalid fairness fees");
        if (msg.value == 0) revert InvalidBudget();
        if (_verifierContract == address(0)) revert("Invalid verifier contract");

        auctioneerAddress = msg.sender;
        bidEnd = block.number + _bidInterval;
        revealEnd = bidEnd + _revealInterval;
        verifyEnd = revealEnd + _verifyInterval;
        withdrawEnd = verifyEnd + 600;
        maxBiddersCount = _maxBiddersCount;
        fairnessFees = _fairnessFees;
        auctioneerRSAPublicKey = _auctioneerRSAPublicKey;
        verifierContract = Verifier(_verifierContract);
        testing = _testing;  // Set testing mode

        budget = msg.value; // Full amount sent is the budget
        totalFairnessFeesCollected = 0;

        state = VerificationState.Init;
        reentrancyStatus = NOT_ENTERED;
        destroyed = false;
        proofVerified = false;
    }

    // Bidders/sellers submit their commitment to their bid and pay fairness fees
    function submitBid(uint32[8] calldata commit) external payable onlyDuringBidding whenNotDestroyed {
        if (bidderAddresses.length >= maxBiddersCount) revert MaxBiddersReached();
        if (msg.value != fairnessFees) revert InvalidFairnessFee();
        if (bidders[msg.sender].existing) revert BidderAlreadyExists();

        bidders[msg.sender] = Bidder({
            commit: commit,
            cipher: 0,  // Initialize with 0 instead of empty bytes
            paidBack: false,
            existing: true
        });
        bidderAddresses.push(msg.sender);
        totalFairnessFeesCollected += fairnessFees;
        
        emit BidCommitted(msg.sender, commit);
    }

    // Sellers/bidders reveal their bids to the auctioneer/seller
    function revealBid(uint32 cipher) external onlyDuringReveal bidderExists whenNotDestroyed {
        if (cipher == 0) revert("Invalid cipher");
        bidders[msg.sender].cipher = cipher;
        emit BidRevealed(msg.sender, cipher);
    }

    // Determines winner of auction with ZK proof verification
    function determineWinner(
        address _winner, 
        uint256 _winningBid,
        ZKProof calldata proof
    ) external onlyAuctioneer whenNotDestroyed {
        if (state != VerificationState.Init) revert WinnerAlreadyDetermined();
        if (_winner == address(0)) revert InvalidWinnerData();
        if (!bidders[_winner].existing) revert BidderNotFound();
        if (_winningBid == 0) revert InvalidWinnerData();
        if (_winningBid > budget) revert BudgetTooLow();

        // Get the winner's commitment from storage
        uint32[8] memory _winningCommitment = bidders[_winner].commit;
        
        // Verify the ZK proof
        if (!verifyAuctionProof(proof, _winningCommitment)) {
            revert VerificationFailed();
        }

        winner = _winner;
        winningBid = _winningBid;
        winningCommitment = _winningCommitment;
        state = VerificationState.Verified;
        proofVerified = true;
        
        emit WinnerDetermined(_winner, _winningBid, _winningCommitment);
        emit ProofVerified(msg.sender, true);
    }

    // Verify ZK proof that the auction was executed correctly
  // Verify ZK proof that the auction was executed correctly
function verifyAuctionProof(
    ZKProof calldata proof,
    uint32[8] memory expectedWinningCommitment
) internal view returns (bool) {
    // Construct public inputs: all commitments + winning commitment
    // Convert uint32 values to uint256 as expected by the verifier
    uint256 totalInputs = bidderAddresses.length * 8 + 8;
    uint256[] memory publicInputs = new uint256[](totalInputs);
    
    uint256 inputIndex = 0;
    
    // Add all bidder commitments as public inputs (convert uint32 to uint256)
    for (uint256 i = 0; i < bidderAddresses.length; i++) {
        uint32[8] memory commitment = bidders[bidderAddresses[i]].commit;
        for (uint256 j = 0; j < 8; j++) {
            publicInputs[inputIndex] = uint256(commitment[j]);
            inputIndex++;
        }
    }
    
    // Add winning commitment as public input (convert uint32 to uint256)
    for (uint256 i = 0; i < 8; i++) {
        publicInputs[inputIndex] = uint256(expectedWinningCommitment[i]);
        inputIndex++;
    }

   Verifier.Proof memory verifierProof = Verifier.Proof({
    a: Pairing.G1Point(proof.a[0], proof.a[1]),
    b: Pairing.G2Point([proof.b[0][0], proof.b[0][1]], [proof.b[1][0], proof.b[1][1]]),
    c: Pairing.G1Point(proof.c[0], proof.c[1])
});

uint[16] memory inputArray;
for (uint i = 0; i < 16; i++) {
    inputArray[i] = publicInputs[i];
}

bool result = verifierContract.verifyTx(verifierProof, inputArray);
return result;
}

// Prepare proof and publicInputs as before

// Convert proof to Verifier.Proof type and publicInputs to uint[16] (if 16 inputs)

    // Allow losing sellers/bidders withdraw their fairness fees
    function withdrawFairnessFee() external nonReentrant bidderExists whenNotDestroyed {
        if (state != VerificationState.Verified) {
            if (!testing && block.number <= verifyEnd) revert AuctionNotEnded();
        }
        if (msg.sender == winner) revert NotAuthorized();
        if (bidders[msg.sender].paidBack) revert AlreadyWithdrawn();

        bidders[msg.sender].paidBack = true;
        totalFairnessFeesCollected -= fairnessFees;

        (bool success, ) = payable(msg.sender).call{value: fairnessFees}("");
        if (!success) {
            bidders[msg.sender].paidBack = false;
            totalFairnessFeesCollected += fairnessFees;
            revert WithdrawFailed();
        }

        emit FairnessFeeWithdrawn(msg.sender);
    }

    // Winning seller accepts payment
    function claimWinnerPayment() external nonReentrant whenNotDestroyed {
        if (state != VerificationState.Verified) revert AuctionNotEnded();
        if (msg.sender != winner) revert NotAuthorized();
        if (!proofVerified) revert VerificationFailed();

        state = VerificationState.Finished;

        (bool success, ) = payable(winner).call{value: winningBid}("");
        if (!success) revert PaymentFailed();

        emit WinnerPaymentReceived(winner, winningBid);
    }
    
    // Function to allow buyer/auctioneer to withdraw his extra money after the auction is over. 
    function claimBudgetRefund() external nonReentrant onlyAuctioneer whenNotDestroyed {
        if (state != VerificationState.Finished) revert AuctionNotEnded();

        // Calculate remaining budget after winner payment
        uint256 remainingBudget = budget - winningBid;
        if (remainingBudget > 0) {
            (bool success, ) = payable(auctioneerAddress).call{value: remainingBudget}("");
            if (!success) revert WithdrawFailed();
            emit BudgetRefunded(auctioneerAddress, remainingBudget);
        }
    }

    // Allows buyer/auctioneer to withdraw his money if the winner never accepts his payment and completes the sale
    function emergencyWithdraw() external onlyAuctioneer nonReentrant whenNotDestroyed {
        if (!testing && block.number <= withdrawEnd) revert AuctionNotEnded();
        if (state == VerificationState.Finished) revert("Use claimBudgetRefund instead");

        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool success, ) = payable(auctioneerAddress).call{value: balance}("");
            if (!success) revert WithdrawFailed();
        }
    }

    // Disables contract and returns money to buyer/auctioneer. Can only be called after the auction is complete
    function destroyContract() external onlyAuctioneer nonReentrant whenNotDestroyed {
        if (!testing && state != VerificationState.Finished && block.number <= verifyEnd) {
            revert AuctionNotEnded();
        }

        destroyed = true;

        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool success, ) = payable(auctioneerAddress).call{value: balance}("");
            if (!success) revert WithdrawFailed();
        }

        emit AuctionDestroyed();
    }

    // View functions for transparency
    function getAllCommitments() external view returns (uint32[8][] memory) {
        uint32[8][] memory commitments = new uint32[8][](bidderAddresses.length);
        for (uint256 i = 0; i < bidderAddresses.length; i++) {
            commitments[i] = bidders[bidderAddresses[i]].commit;
        }
        return commitments;
    }

    function getAllCiphers() external view returns (uint32[] memory) {
        uint32[] memory ciphers = new uint32[](bidderAddresses.length);
        for (uint256 i = 0; i < bidderAddresses.length; i++) {
            ciphers[i] = bidders[bidderAddresses[i]].cipher;
        }
        return ciphers;
    }

    function getBidderCount() external view returns (uint256) {
        return bidderAddresses.length;
    }

    function getWinnerInfo() external view returns (address, uint256, uint32[8] memory, bool) {
        return (winner, winningBid, winningCommitment, proofVerified);
    }

    function isProofVerified() external view returns (bool) {
        return proofVerified;
    }

    // Function to get commitment for a specific bidder
    function getBidderCommitment(address bidder) external view returns (uint32[8] memory) {
        if (!bidders[bidder].existing) revert BidderNotFound();
        return bidders[bidder].commit;
    }

    // Function to get cipher for a specific bidder
    function getBidderCipher(address bidder) external view returns (uint32) {
        if (!bidders[bidder].existing) revert BidderNotFound();
        return bidders[bidder].cipher;
    }

    // Testing helper functions
    function skipToRevealPhase() external onlyAuctioneer {
        require(testing, "Only available in testing mode");
        // In testing mode, timing constraints are already bypassed
    }

    function skipToVerifyPhase() external onlyAuctioneer {
        require(testing, "Only available in testing mode");
        // In testing mode, timing constraints are already bypassed
    }

    function skipToWithdrawPhase() external onlyAuctioneer {
        require(testing, "Only available in testing mode");
        // In testing mode, timing constraints are already bypassed
    }
}