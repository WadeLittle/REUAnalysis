const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const CSV_PATH = path.join(__dirname, "../custom-gas-analysis.csv");
const iterations = 1;
const NUM_BLOCK_IDS = 5; // Change this to test with different numbers of block IDs
const BLOCK_ID_SCENARIOS = [1, 2, 5, 10, 20]; // Test with different numbers of block IDs

function writeHeader() {
  fs.writeFileSync(CSV_PATH, "function,iteration,numBlockIds,gasUsed\n");
}

function logGas(fnName, iteration, numBlockIds, gasUsed) {
  fs.appendFileSync(CSV_PATH, `${fnName},${iteration},${numBlockIds},${gasUsed}\n`);
}

// Helper function to create block IDs array
function createBlockIDs(count) {
  const blockIDS = [];
  for (let i = 0; i < count; i++) {
    blockIDS.push(ethers.keccak256(ethers.toUtf8Bytes(`block${i + 1}`)));
  }
  return blockIDS;
}

// Helper function to calculate record ID
function calculateRecordID(blockIDS) {
  const concatenated = ethers.concat(blockIDS);
  return ethers.keccak256(concatenated);
}

describe("AccessControlContract Gas Analysis", function () {
  let contractFactory;
  let owner, buyer;
  let recordFee;
  const refundWindow = 3600;

  before(async function () {
    writeHeader();
    
    [owner, buyer] = await ethers.getSigners();
    contractFactory = await ethers.getContractFactory("AccessControlContract");
    recordFee = ethers.parseEther("0.01");
    
    console.log(`Running comprehensive gas analysis...`);
  });

  // Test with single scenario (configurable)
  describe(`Single Scenario Test (${NUM_BLOCK_IDS} block IDs)`, function () {
    let contract, blockIDS, recordID;

    before(async function () {
      blockIDS = createBlockIDs(NUM_BLOCK_IDS);
      recordID = calculateRecordID(blockIDS);
      console.log(`Testing with ${NUM_BLOCK_IDS} block IDs`);
    });

    beforeEach(async function () {
      // Deploy contract
      contract = await contractFactory.deploy(blockIDS, recordFee, refundWindow, "0x", recordID);
      await contract.waitForDeployment();
      
      // Get deployment transaction receipt and log constructor gas
      const deploymentTx = contract.deploymentTransaction();
      if (deploymentTx) {
        const receipt = await deploymentTx.wait();
        logGas("constructor", 0, NUM_BLOCK_IDS, receipt.gasUsed.toString());
        console.log(`Constructor gas (${NUM_BLOCK_IDS} blocks): ${receipt.gasUsed.toString()}`);
      }
    });

    it("Logs gas for requestRecordAccess", async function () {
      for (let i = 0; i < iterations; i++) {
        const tx = await contract.connect(buyer).requestRecordAccess(blockIDS, { value: recordFee });
        const receipt = await tx.wait();
        logGas("requestRecordAccess", i, NUM_BLOCK_IDS, receipt.gasUsed.toString());
        console.log(`requestRecordAccess iteration ${i} gas (${NUM_BLOCK_IDS} blocks): ${receipt.gasUsed.toString()}`);
      }
    });

    it("Logs gas for withdrawFunds", async function () {
      for (let i = 0; i < iterations; i++) {
        // Create gamma and hash_gamma arrays matching the number of block IDs
        const gamma = [];
        const hash_gamma = [];
        
        for (let j = 0; j < NUM_BLOCK_IDS; j++) {
          const gammaValue = 123 + i * NUM_BLOCK_IDS + j; // Unique value for each iteration and block
          gamma.push(gammaValue);
          hash_gamma.push(
            ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [gammaValue]))
          );
        }
        
        const blockID = blockIDS;

        // Make request first
        await contract.connect(buyer).requestRecordAccess(blockIDS, { value: recordFee });

        // Create signatures for each block ID
        const signatures = [];
        for (let j = 0; j < NUM_BLOCK_IDS; j++) {
          const messageHash = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32"],
            [blockID[j], hash_gamma[j]]
          );
          const signature = await buyer.signMessage(ethers.getBytes(messageHash));
          signatures.push(signature);
        }

        const tx = await contract.connect(owner).withdrawFunds(
          buyer.address,
          gamma,
          hash_gamma,
          blockID,
          signatures
        );

        const receipt = await tx.wait();
        logGas("withdrawFunds", i, NUM_BLOCK_IDS, receipt.gasUsed.toString());
        console.log(`withdrawFunds iteration ${i} gas (${NUM_BLOCK_IDS} blocks): ${receipt.gasUsed.toString()}`);
      }
    });
  });

  // Comprehensive test with multiple block ID scenarios
  describe("Comprehensive Analysis (Multiple Block ID Scenarios)", function () {
    it("Tests gas usage across different block ID counts", async function () {
      console.log(`\n=== Running comprehensive analysis with scenarios: ${BLOCK_ID_SCENARIOS.join(', ')} ===`);
      
      for (const numBlocks of BLOCK_ID_SCENARIOS) {
        console.log(`\n--- Testing with ${numBlocks} block IDs ---`);
        
        // Create block IDs and record ID for this scenario
        const blockIDS = createBlockIDs(numBlocks);
        const recordID = calculateRecordID(blockIDS);
        
        // Deploy contract
        const contract = await contractFactory.deploy(blockIDS, recordFee, refundWindow, "0x", recordID);
        await contract.waitForDeployment();
        
        // Log constructor gas
        const deploymentTx = contract.deploymentTransaction();
        if (deploymentTx) {
          const receipt = await deploymentTx.wait();
          logGas("constructor", 0, numBlocks, receipt.gasUsed.toString());
          console.log(`Constructor gas (${numBlocks} blocks): ${receipt.gasUsed.toString()}`);
        }
        
        // Test requestRecordAccess
        const requestTx = await contract.connect(buyer).requestRecordAccess(blockIDS, { value: recordFee });
        const requestReceipt = await requestTx.wait();
        logGas("requestRecordAccess", 0, numBlocks, requestReceipt.gasUsed.toString());
        console.log(`requestRecordAccess gas (${numBlocks} blocks): ${requestReceipt.gasUsed.toString()}`);
        
        // Test withdrawFunds
        const gamma = [];
        const hash_gamma = [];
        const signatures = [];
        
        for (let j = 0; j < numBlocks; j++) {
          const gammaValue = 123 + j;
          gamma.push(gammaValue);
          hash_gamma.push(
            ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [gammaValue]))
          );
          
          const messageHash = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32"],
            [blockIDS[j], hash_gamma[j]]
          );
          const signature = await buyer.signMessage(ethers.getBytes(messageHash));
          signatures.push(signature);
        }
        
        const withdrawTx = await contract.connect(owner).withdrawFunds(
          buyer.address,
          gamma,
          hash_gamma,
          blockIDS,
          signatures
        );
        
        const withdrawReceipt = await withdrawTx.wait();
        logGas("withdrawFunds", 0, numBlocks, withdrawReceipt.gasUsed.toString());
        console.log(`withdrawFunds gas (${numBlocks} blocks): ${withdrawReceipt.gasUsed.toString()}`);
      }
      
      console.log(`\n=== Comprehensive analysis complete! Check ${CSV_PATH} for detailed results ===`);
    });
  });
});