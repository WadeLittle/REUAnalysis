#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Configuration
const CONFIG = {
    numBidders: 5,     // Must match MAX_BIDDERS in ZoKrates code
    minBid: 10,        // Minimum bid value
    maxBid: 500,       // Maximum bid value
    iterations: 5,     // Number of benchmark iterations
    circuitPath: './auction.zok',  // Path to your ZoKrates circuit file
    outputDir: './benchmark_output' // Directory for generated files
};

// Timing utilities
class Timer {
    constructor() {
        this.start = process.hrtime.bigint();
    }
    
    stop() {
        const end = process.hrtime.bigint();
        return Number(end - this.start) / 1000000; // Convert to milliseconds
    }
}

// Parameter generation functions (from your example)
function u32To32bitBE(val) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(val);
    return buf;
}

function padTo256Bits(data) {
    if (data.length > 32) throw new Error("Input too long");
    return Buffer.concat([data, Buffer.alloc(32 - data.length)]);
}

function hashBid(bid) {
    const bidBuf = u32To32bitBE(bid);
    const input = padTo256Bits(bidBuf);
    const hash = crypto.createHash("sha256").update(input).digest();

    const u32s = [];
    for (let i = 0; i < 32; i += 4) {
        u32s.push(hash.readUInt32BE(i));
    }
    return u32s;
}

function generateRandomBid(min = 1, max = 1000) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateBidData(numBidders = 2, minBid = 1, maxBid = 1000) {
    const bids = [];
    for (let i = 0; i < numBidders; i++) {
        bids.push(generateRandomBid(minBid, maxBid));
    }
    
    const commitments = bids.map(hashBid);
    
    // Find winning bid (lowest bid for auction)
    const winningBid = Math.min(...bids);
    const winningIndex = bids.indexOf(winningBid);
    const winningCommitment = commitments[winningIndex];
    
    return {
        bids,
        commitments,
        winningBid,
        winningCommitment,
        winningIndex
    };
}

// ZoKrates CLI wrapper functions
function runZoKratesCommand(command, description) {
    console.log(`\n🔧 ${description}...`);
    const timer = new Timer();
    
    try {
        const result = execSync(command, { 
            stdio: 'pipe',
            encoding: 'utf8',
            cwd: CONFIG.outputDir
        });
        
        const time = timer.stop();
        console.log(`✅ ${description} completed in ${time.toFixed(2)}ms`);
        return { success: true, time, output: result };
    } catch (error) {
        const time = timer.stop();
        console.error(`❌ ${description} failed in ${time.toFixed(2)}ms`);
        console.error(`Error: ${error.message}`);
        return { success: false, time, error: error.message };
    }
}

function setupOutputDirectory() {
    if (!fs.existsSync(CONFIG.outputDir)) {
        fs.mkdirSync(CONFIG.outputDir, { recursive: true });
    }
    
    // Copy circuit file to output directory
    if (fs.existsSync(CONFIG.circuitPath)) {
        const circuitContent = fs.readFileSync(CONFIG.circuitPath, 'utf8');
        fs.writeFileSync(path.join(CONFIG.outputDir, 'auction.zok'), circuitContent);
        console.log(`📄 Circuit file copied to ${CONFIG.outputDir}`);
    } else {
        console.warn(`⚠️  Circuit file not found at ${CONFIG.circuitPath}`);
        console.log('Creating a basic auction circuit file...');
        
        // Create the circuit file with your provided code
        const circuitCode = `import "utils/casts/u32_to_bits" as u32_to_bits;
import "utils/casts/bool_256_to_u32_8" as to_u32_8;
import "hashes/sha256/256bitPadded" as sha;

const u32 MAX_BIDDERS = 5;

def main(
    private u32[MAX_BIDDERS] bids,
    public u32[MAX_BIDDERS][8] commitments,
    public u32[8] winning_commitment
) {
    // First, verify all bid commitments
    for u32 i in 0..MAX_BIDDERS {
        // Convert bid to 32 bits (big endian)
        bool[32] bid_bits = u32_to_bits(bids[i]);

        // Pad to 256 bits
        bool[256] mut padded_bits = [false; 256];
        for u32 j in 0..32 {
            padded_bits[j] = bid_bits[j];
        }

        // Compute hash
        u32[8] hash_output = sha(to_u32_8(padded_bits));

        // Assert each piece of commitment
        for u32 k in 0..8 {
            assert(hash_output[k] == commitments[i][k]);
        }
    }

    // Find minimum bid with tie-breaking (first bidder wins)
    // Compute minimum bid and index using ternary expressions
    u32 mut min_bid = bids[0];
    u32 mut min_index = 0;

    for u32 i in 1..MAX_BIDDERS {
        bool is_less = bids[i] < min_bid;
        min_bid = is_less ? bids[i] : min_bid;
        min_index = is_less ? i : min_index;
    }

    // Set winner flags using ternary logic
    bool[MAX_BIDDERS] mut is_minimum = [false; MAX_BIDDERS];
    for u32 i in 0..MAX_BIDDERS {
        is_minimum[i] = (i == min_index);
    }
    
    // Find the winning commitment directly from the commitments array
    u32[8] mut computed_winning_commitment = [0; 8];
    
    for u32 i in 0..MAX_BIDDERS {
        // Add this commitment to result if this is the minimum bidder
        for u32 k in 0..8 {
            computed_winning_commitment[k] = computed_winning_commitment[k] + 
                (is_minimum[i] ? commitments[i][k] : 0);
        }
    }
    
    // Assert the computed winning commitment matches the public input
    for u32 k in 0..8 {
        assert(computed_winning_commitment[k] == winning_commitment[k]);
    }

    return;
}`;
        
        fs.writeFileSync(path.join(CONFIG.outputDir, 'auction.zok'), circuitCode);
    }
}

function formatArgumentsForZoKrates(bidData) {
    const { bids, commitments, winningCommitment } = bidData;
    
    // Private arguments (bids)
    const privateArgs = bids.join(' ');
    
    // Public arguments (commitments as flattened array)
    const flatCommitments = commitments.flat().join(' ');
    
    // Winning commitment
    const winningCommitmentStr = winningCommitment.join(' ');
    
    const allArgs = `${privateArgs} ${flatCommitments} ${winningCommitmentStr}`;
    
    return {
        privateArgs,
        publicArgs: `${flatCommitments} ${winningCommitmentStr}`,
        allArgs
    };
}

async function runSetupPhase() {
    console.log('\n🔧 === SETUP PHASE ===');
    
    const timer = new Timer();
    
    // 1. Compile
    const compileResult = runZoKratesCommand(
        'zokrates compile -i auction.zok',
        'Compiling circuit'
    );
    
    if (!compileResult.success) {
        return { success: false, time: timer.stop(), error: 'Compilation failed' };
    }
    
    // 2. Setup
    const setupResult = runZoKratesCommand(
        'zokrates setup',
        'Generating proving and verification keys'
    );
    
    if (!setupResult.success) {
        return { success: false, time: timer.stop(), error: 'Setup failed' };
    }
    
    const totalTime = timer.stop();
    console.log(`✅ Setup phase completed in ${totalTime.toFixed(2)}ms`);
    
    return { 
        success: true, 
        time: totalTime, 
        compile: compileResult, 
        setup: setupResult 
    };
}

async function runProvingPhase(bidData) {
    console.log('\n🔐 === PROVING PHASE ===');
    
    const args = formatArgumentsForZoKrates(bidData);
    const timer = new Timer();
    
    // 1. Compute witness
    const witnessResult = runZoKratesCommand(
        `zokrates compute-witness -a ${args.allArgs}`,
        'Computing witness'
    );
    
    if (!witnessResult.success) {
        return { success: false, time: timer.stop(), error: 'Witness computation failed' };
    }
    
    // 2. Generate proof
    const proofResult = runZoKratesCommand(
        'zokrates generate-proof',
        'Generating proof'
    );
    
    if (!proofResult.success) {
        return { success: false, time: timer.stop(), error: 'Proof generation failed' };
    }
    
    const totalTime = timer.stop();
    console.log(`✅ Proving phase completed in ${totalTime.toFixed(2)}ms`);
    
    return { 
        success: true, 
        time: totalTime, 
        witness: witnessResult, 
        proof: proofResult 
    };
}

async function runVerificationPhase() {
    console.log('\n🔍 === VERIFICATION PHASE ===');
    
    const timer = new Timer();
    
    const verifyResult = runZoKratesCommand(
        'zokrates verify',
        'Verifying proof'
    );
    
    const totalTime = timer.stop();
    
    if (verifyResult.success) {
        console.log(`✅ Verification phase completed in ${totalTime.toFixed(2)}ms`);
    } else {
        console.log(`❌ Verification phase failed in ${totalTime.toFixed(2)}ms`);
    }
    
    return { 
        success: verifyResult.success, 
        time: totalTime, 
        verify: verifyResult 
    };
}

async function runSingleBenchmark(iteration) {
    console.log(`\n🚀 === BENCHMARK ITERATION ${iteration + 1} ===`);
    
    // Generate random bid data
    const bidData = generateBidData(CONFIG.numBidders, CONFIG.minBid, CONFIG.maxBid);
    
    console.log(`📊 Generated bids: [${bidData.bids.join(', ')}]`);
    console.log(`🏆 Winning bid: ${bidData.winningBid} (bidder ${bidData.winningIndex + 1})`);
    
    const results = {};
    
    // Run setup phase (compile + setup)
    results.setupPhase = await runSetupPhase();
    if (!results.setupPhase.success) return results;
    
    // Run proving phase (witness + proof)
    results.provingPhase = await runProvingPhase(bidData);
    if (!results.provingPhase.success) return results;
    
    // Run verification phase
    results.verificationPhase = await runVerificationPhase();
    
    // Save witness and proof for inspection
    const iterationDir = path.join(CONFIG.outputDir, `iteration_${iteration + 1}`);
    if (!fs.existsSync(iterationDir)) {
        fs.mkdirSync(iterationDir);
    }
    
    // Save bid data
    fs.writeFileSync(
        path.join(iterationDir, 'bid_data.json'),
        JSON.stringify(bidData, null, 2)
    );
    
    // Save formatted arguments
    const args = formatArgumentsForZoKrates(bidData);
    fs.writeFileSync(
        path.join(iterationDir, 'arguments.txt'),
        `Private args: ${args.privateArgs}\nPublic args: ${args.publicArgs}\nAll args: ${args.allArgs}`
    );
    
    return results;
}

function calculateStatistics(benchmarkResults) {
    const phases = ['setupPhase', 'provingPhase', 'verificationPhase'];
    const stats = {};
    
    phases.forEach(phase => {
        const times = benchmarkResults
            .filter(result => result[phase] && result[phase].success)
            .map(result => result[phase].time);
        
        if (times.length > 0) {
            stats[phase] = {
                count: times.length,
                min: Math.min(...times),
                max: Math.max(...times),
                avg: times.reduce((a, b) => a + b, 0) / times.length,
                total: times.reduce((a, b) => a + b, 0)
            };
        } else {
            stats[phase] = { count: 0, error: 'No successful runs' };
        }
    });
    
    return stats;
}

function displayResults(benchmarkResults, stats) {
    console.log('\n📈 === BENCHMARK RESULTS ===');
    
    // Success rate
    const totalRuns = benchmarkResults.length;
    const successfulRuns = benchmarkResults.filter(result => 
        result.verificationPhase && result.verificationPhase.success
    ).length;
    
    console.log(`\n✅ Success Rate: ${successfulRuns}/${totalRuns} (${(successfulRuns/totalRuns*100).toFixed(1)}%)`);
    
    // Timing statistics
    console.log('\n⏱️  Timing Statistics (ms):');
    console.log('Phase'.padEnd(20) + 'Count'.padEnd(8) + 'Min'.padEnd(12) + 'Max'.padEnd(12) + 'Avg'.padEnd(12) + 'Total');
    console.log('-'.repeat(76));
    
    const phaseLabels = {
        setupPhase: 'Setup (Compile+Setup)',
        provingPhase: 'Proving (Witness+Proof)',
        verificationPhase: 'Verification'
    };
    
    Object.entries(stats).forEach(([phase, data]) => {
        const label = phaseLabels[phase] || phase;
        if (data.count > 0) {
            console.log(
                label.padEnd(20) +
                data.count.toString().padEnd(8) +
                data.min.toFixed(2).padEnd(12) +
                data.max.toFixed(2).padEnd(12) +
                data.avg.toFixed(2).padEnd(12) +
                data.total.toFixed(2)
            );
        } else {
            console.log(label.padEnd(20) + '0'.padEnd(8) + data.error);
        }
    });
    
    // Total time
    const totalTime = Object.values(stats)
        .filter(data => data.total)
        .reduce((sum, data) => sum + data.total, 0);
    
    console.log('\n🕐 Total benchmark time: ' + totalTime.toFixed(2) + 'ms');
    
    // Average per complete run
    if (successfulRuns > 0) {
        console.log(`📊 Average time per successful run: ${(totalTime / successfulRuns).toFixed(2)}ms`);
    }
    
    // Save detailed results
    const resultsFile = path.join(CONFIG.outputDir, 'benchmark_results.json');
    fs.writeFileSync(resultsFile, JSON.stringify({
        config: CONFIG,
        results: benchmarkResults,
        statistics: stats,
        summary: {
            totalRuns,
            successfulRuns,
            successRate: (successfulRuns / totalRuns * 100).toFixed(1) + '%',
            totalTime: totalTime.toFixed(2) + 'ms',
            avgTimePerRun: successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(2) + 'ms' : 'N/A'
        },
        timestamp: new Date().toISOString()
    }, null, 2));
    
    console.log(`\n💾 Detailed results saved to: ${resultsFile}`);
}

async function main() {
    console.log('🔍 ZoKrates Auction Circuit Benchmark Tool');
    console.log(`Configuration: ${CONFIG.numBidders} bidders, ${CONFIG.iterations} iterations`);
    
    // Setup
    setupOutputDirectory();
    
    // Check if ZoKrates is installed
    try {
        execSync('zokrates --version', { stdio: 'pipe' });
        console.log('✅ ZoKrates CLI found');
    } catch (error) {
        console.error('❌ ZoKrates CLI not found. Please install ZoKrates first.');
        console.error('Visit: https://zokrates.github.io/gettingstarted.html');
        process.exit(1);
    }
    
    // Run benchmarks
    const benchmarkResults = [];
    
    for (let i = 0; i < CONFIG.iterations; i++) {
        const result = await runSingleBenchmark(i);
        benchmarkResults.push(result);
        
        // Small delay between iterations
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    // Calculate and display statistics
    const stats = calculateStatistics(benchmarkResults);
    displayResults(benchmarkResults, stats);
    
    console.log('\n🎉 Benchmark completed!');
    console.log(`📁 All files saved to: ${CONFIG.outputDir}`);
}

// Run the benchmark
if (require.main === module) {
    main().catch(console.error);
}

// Export for use as module
module.exports = {
    generateBidData,
    formatArgumentsForZoKrates,
    runSingleBenchmark,
    CONFIG
};