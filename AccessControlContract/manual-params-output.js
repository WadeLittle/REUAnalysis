const { ethers } = require("hardhat");
const { arrayify } = ethers;
const fs = require("fs");
const path = require("path");

const PARAMS_PATH = path.join(__dirname, "../manual-test-params.txt");
const NUM_BLOCK_IDS = 1;

function arrayLiteral(arr) {
  if (arr.length === 0) return "[]";
  if (typeof arr[0] === "string" && arr[0].startsWith("0x")) {
    return `[${arr.map((x) => `"${x}"`).join(",")}]`;
  }
  return `[${arr.join(",")}]`;
}

async function main() {
  fs.writeFileSync(PARAMS_PATH, "Manual Remix Parameters for 1 blockID\n\n");

  const [owner, buyer] = await ethers.getSigners();
  const recordFee = ethers.parseEther("0.01");
  const refundWindow = 3600;
  const publicKey = "0x"; // Placeholder, set as needed

  // Prepare parameters
  const blockIDS = [ethers.keccak256(ethers.toUtf8Bytes("block1"))];
  const concatenated = ethers.concat(blockIDS);
  const recordID = ethers.keccak256(concatenated);

  // --- Constructor ---
  fs.appendFileSync(PARAMS_PATH, "=== Constructor ===\n");
  fs.appendFileSync(
    PARAMS_PATH,
    `blockIDS: ${arrayLiteral(blockIDS)}\nrecordFee: ${recordFee.toString()}\nrefundWindow: ${refundWindow}\npublicKey: "${publicKey}"\nrecordID: "${recordID}"\n\n`
  );

  // --- requestRecordAccess ---
  fs.appendFileSync(PARAMS_PATH, "=== requestRecordAccess ===\n");
  fs.appendFileSync(PARAMS_PATH, `blockIDS: ${arrayLiteral(blockIDS)}\n\n`);

  // --- withdrawFunds ---
  const gamma = [123];
  const hash_gamma = [
    ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], gamma)
    ),
  ];

  // This must match the contract's expected_message logic:
  const expected_message = ethers.solidityPackedKeccak256(
    ["bytes32", "bytes32"],
    [blockIDS[0], hash_gamma[0]]
  );

  // Output the message to sign for Remix
  fs.appendFileSync(PARAMS_PATH, "=== withdrawFunds ===\n");
  fs.appendFileSync(
    PARAMS_PATH,
    `buyer: "${buyer.address}"\ngamma: ${arrayLiteral(gamma)}\nhash_gamma: ${arrayLiteral(hash_gamma)}\nblockID: ${arrayLiteral(blockIDS)}\n\n`
  );
  fs.appendFileSync(
    PARAMS_PATH,
    `Message to sign (hex): ${expected_message}\n`
  );

  console.log(`Manual test parameters written to ${PARAMS_PATH}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});