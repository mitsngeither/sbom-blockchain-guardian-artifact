import "dotenv/config";
import { readFileSync } from "node:fs";
import { network } from "hardhat";

import {
    buildSBOMMerkleTree,
    parseSBOMContent,
    verifyComponentProof,
} from "@guardian/sbom-core";

// Times verifyComponent against the deployed contract (CONTRACT_ADDRESS, --network sepolia)
// using an Active record written by CI. View calls only (eth_call): no transaction, no fee.
//
// Usage:
//   pnpm hardhat run scripts/benchmark-verify-component.ts --network sepolia
// Env:
//   CONTRACT_ADDRESS (required), BENCH_SBOM_PATH, BENCH_PROJECT_ID, BENCH_RECORD_VERSION (optional)

const SBOM_PATH =
    process.env.BENCH_SBOM_PATH ??
    "results/sbom-ci-38974146992.json";
const PROJECT_ID = process.env.BENCH_PROJECT_ID ?? "sbom-blockchain-guardian";
const RECORD_VERSION =
    process.env.BENCH_RECORD_VERSION ?? "1.0.0+9028fbd.38974146992-1";

const SAMPLE_COMPONENTS = 10;
const ROUNDS = 10; // total calls = SAMPLE_COMPONENTS * ROUNDS

function stats(samplesMs: number[]) {
    const sorted = [...samplesMs].sort((a, b) => a - b);
    const mean = samplesMs.reduce((a, b) => a + b, 0) / samplesMs.length;
    const median = sorted[Math.floor(sorted.length / 2)];
    return {
        runs: samplesMs.length,
        min: sorted[0].toFixed(1),
        median: median.toFixed(1),
        max: sorted[sorted.length - 1].toFixed(1),
        mean: mean.toFixed(1),
    };
}

async function main() {
    const contractAddress = process.env.CONTRACT_ADDRESS;
    if (!contractAddress) {
        throw new Error("Missing CONTRACT_ADDRESS env variable");
    }

    const { ethers } = await network.getOrCreate();
    const registry = await ethers.getContractAt("SBOMRegistry", contractAddress);
    const networkInfo = await ethers.provider.getNetwork();

    const projectId = ethers.keccak256(ethers.toUtf8Bytes(PROJECT_ID));
    const record = await registry.getVersion(projectId, RECORD_VERSION);
    if (Number(record.status) !== 1) {
        throw new Error(`Record ${PROJECT_ID}@${RECORD_VERSION} is not Active on chain`);
    }

    const sbom = parseSBOMContent(readFileSync(SBOM_PATH, "utf8"));
    const merkleTree = buildSBOMMerkleTree(sbom);
    if (merkleTree.root !== record.merkleRoot) {
        throw new Error(
            `Local root ${merkleTree.root} != on-chain merkleRoot ${record.merkleRoot}`
        );
    }

    const n = merkleTree.leaves.length;
    const step = Math.floor(n / SAMPLE_COMPONENTS);
    const samples = Array.from({ length: SAMPLE_COMPONENTS }, (_, i) => {
        const leafIndex = i * step;
        const leaf = merkleTree.leaves[leafIndex];
        return {
            leaf,
            proof: merkleTree.tree.getProof(leafIndex),
            arg: {
                key: leaf.key,
                identity: leaf.identity,
                version: leaf.version,
                componentType: leaf.type,
                componentHash: leaf.componentHash,
            },
        };
    });

    // Sanity check first: valid proof -> true; tampered proof or missing record -> false.
    for (const s of samples) {
        if (!(await registry.verifyComponent(projectId, RECORD_VERSION, s.arg, s.proof))) {
            throw new Error(`verifyComponent returned false for ${s.leaf.key}`);
        }
    }
    const tampered = [...samples[0].proof];
    tampered[0] = ethers.keccak256(ethers.toUtf8Bytes("tampered"));
    const tamperedResult = await registry.verifyComponent(projectId, RECORD_VERSION, samples[0].arg, tampered);
    const missingResult = await registry.verifyComponent(projectId, "does-not-exist", samples[0].arg, samples[0].proof);
    if (tamperedResult || missingResult) {
        throw new Error("Negative checks did not fail closed");
    }

    // Gas this would cost inside a transaction (estimateGas only, nothing is sent).
    const gasEstimates: bigint[] = [];
    for (const s of samples) {
        gasEstimates.push(
            await registry.verifyComponent.estimateGas(projectId, RECORD_VERSION, s.arg, s.proof)
        );
    }

    const componentSamples: number[] = [];
    const sbomSamples: number[] = [];
    const localSamples: number[] = [];
    for (let round = 0; round < ROUNDS; round++) {
        for (const s of samples) {
            let start = performance.now();
            await registry.verifyComponent(projectId, RECORD_VERSION, s.arg, s.proof);
            componentSamples.push(performance.now() - start);

            start = performance.now();
            await registry.verifySBOM(projectId, RECORD_VERSION, record.sbomHash);
            sbomSamples.push(performance.now() - start);

            start = performance.now();
            verifyComponentProof({ root: merkleTree.root, leaf: s.leaf, proof: s.proof });
            localSamples.push(performance.now() - start);
        }
    }

    const proofLengths = samples.map((s) => s.proof.length);
    const gasNums = gasEstimates.map(Number);
    const result = {
        network: `${networkInfo.name} chainId=${networkInfo.chainId}`,
        contract: contractAddress,
        record: `${PROJECT_ID}@${RECORD_VERSION}`,
        components: n,
        proofLength: { min: Math.min(...proofLengths), max: Math.max(...proofLengths) },
        negativeChecks: { tamperedProof: tamperedResult, missingRecord: missingResult },
        verifyComponentGasEstimate: { min: Math.min(...gasNums), max: Math.max(...gasNums) },
        latencyMs: {
            "verifyComponent view call (RPC)": stats(componentSamples),
            "verifySBOM view call (RPC)": stats(sbomSamples),
            "verifyComponentProof (local JS)": stats(localSamples),
        },
    };

    console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
