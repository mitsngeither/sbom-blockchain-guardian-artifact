import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { network } from "hardhat";

import { parseSBOMContent } from "@guardian/sbom-core";
import { compareSBOMs } from "@guardian/sbom-core";
import { runDetectorPipeline } from "../src/detector/detector-pipeline.ts";
import { generateRiskReport } from "../src/detector/risk-scorer.ts";
import { buildSBOMMerkleTree } from "@guardian/sbom-core";

const PIPELINE_RUNS = 10;  // used for both the local steps and the on-chain ones (network from --network)
const NETWORK_RUNS = 5;

function stats(samplesMs: number[]) {
    const min = Math.min(...samplesMs);
    const max = Math.max(...samplesMs);
    const mean = samplesMs.reduce((a, b) => a + b, 0) / samplesMs.length;
    return {
        min: min.toFixed(1),
        max: max.toFixed(1),
        mean: mean.toFixed(1),
        runs: samplesMs.length,
    };
}

async function timeit(label: string, runs: number, fn: () => Promise<void>) {
    const samples: number[] = [];
    for (let i = 0; i < runs; i++) {
        const start = performance.now();
        await fn();
        samples.push(performance.now() - start);
    }
    return { label, ...stats(samples) };
}

async function main() {
    const results: Array<{
        label: string;
        min: string;
        max: string;
        mean: string;
        runs: number;
    }> = [];

    // 1. Generate SBOM (real pnpm command, lockfile-only, no network fetch of registry)
    results.push(
        await timeit("generateSbom (pnpm sbom --lockfile-only)", PIPELINE_RUNS, async () => {
            execSync(
                "pnpm sbom --sbom-format cyclonedx --lockfile-only",
                { cwd: process.cwd(), stdio: "ignore" }
            );
        })
    );

    // Fixtures used for the rest of the pipeline: the axios case study pair
    const previousRaw = readFileSync(
        "test/sboms/sbom-v2-added-axios.json",
        "utf8"
    );
    const currentRaw = readFileSync(
        "test/sboms/sbom-v3-axios-1.14.0.json",
        "utf8"
    );

    // 2. Parse
    results.push(
        await timeit("parseSBOM (parseSBOMContent x2)", PIPELINE_RUNS, async () => {
            parseSBOMContent(previousRaw);
            parseSBOMContent(currentRaw);
        })
    );

    const previousSbom = parseSBOMContent(previousRaw);
    const currentSbom = parseSBOMContent(currentRaw);

    // 3. Diff
    results.push(
        await timeit("diff (compareSBOMs)", PIPELINE_RUNS, async () => {
            compareSBOMs(previousSbom, currentSbom);
        })
    );

    // 4. Detector pipeline (full run: diff + per-package risk scoring, hits npm registry)
    results.push(
        await timeit(
            "detectorPipeline (runDetectorPipeline, network)",
            NETWORK_RUNS,
            async () => {
                await runDetectorPipeline({
                    projectId: "latency-benchmark",
                    previousVersion: "v2-added-axios",
                    currentVersion: "v3-axios-1.14.0",
                    previousSbom,
                    currentSbom,
                    mode: "incremental",
                });
            }
        )
    );

    // 5. Risk scoring in isolation (single package, still hits npm registry twice: lifecycle + cooldown)
    results.push(
        await timeit(
            "riskScoring (generateRiskReport('axios'), network, subset of #4)",
            NETWORK_RUNS,
            async () => {
                await generateRiskReport("axios", "1.14.0", {
                    previousPackageNames: previousSbom.components.map(
                        (c) => c.name
                    ),
                });
            }
        )
    );

    // 6. Merkle tree build (local, deterministic)
    results.push(
        await timeit("merkleBuild (buildSBOMMerkleTree)", PIPELINE_RUNS, async () => {
            buildSBOMMerkleTree(currentSbom);
        })
    );

    // 7/8/9. EIP-712 signing, submit transaction, verify on-chain — on the network given by --network (e.g. sepolia)
    const { ethers } = await network.getOrCreate();
    const [owner] = await ethers.getSigners();
    const SBOMRegistry = await ethers.getContractFactory("SBOMRegistry");
    const registry = await SBOMRegistry.deploy();
    await registry.waitForDeployment();
    const contractAddress = await registry.getAddress();

    const networkInfo = await ethers.provider.getNetwork();
    const domain = {
        name: "MyDApp",
        version: "1",
        chainId: Number(networkInfo.chainId),
        verifyingContract: contractAddress,
    };
    const types = {
        SBOMSubmission: [
            { name: "projectId", type: "bytes32" },
            { name: "version", type: "string" },
            { name: "sbomHash", type: "bytes32" },
            { name: "artifactHash", type: "bytes32" },
            { name: "merkleRoot", type: "bytes32" },
            { name: "riskScore", type: "uint32" },
            { name: "nonce", type: "uint256" },
        ],
    };

    const signSamples: number[] = [];
    const submitSamples: number[] = [];
    const verifySamples: number[] = [];

    for (let i = 0; i < PIPELINE_RUNS; i++) {
        const projectId = ethers.keccak256(
            ethers.toUtf8Bytes(`latency-bench-${i}`)
        );
        const version = `1.0.${i}`;
        const sbomHash = ethers.keccak256(ethers.toUtf8Bytes(`sbom-${i}`));
        const artifactHash = ethers.keccak256(
            ethers.toUtf8Bytes(`artifact-${i}`)
        );
        const merkleRoot = ethers.keccak256(
            ethers.toUtf8Bytes(`merkle-${i}`)
        );
        const nonce = await registry.nonces(owner.address);
        const submission = {
            projectId,
            version,
            sbomHash,
            artifactHash,
            merkleRoot,
            riskScore: 12,
            nonce,
        };

        const signStart = performance.now();
        const signature = await owner.signTypedData(domain, types, submission);
        signSamples.push(performance.now() - signStart);

        const submitStart = performance.now();
        const tx = await registry.submitWithSignature(submission, signature);
        await tx.wait();
        submitSamples.push(performance.now() - submitStart);

        const verifyStart = performance.now();
        await registry.verifySBOM(projectId, version, sbomHash);
        verifySamples.push(performance.now() - verifyStart);
    }

    const netLabel = `${networkInfo.name ?? "unknown"} chainId=${networkInfo.chainId}`;
    results.push({ label: `eip712Signing (signTypedData, ${netLabel})`, ...stats(signSamples) });
    results.push({ label: `submitTransaction (submitWithSignature+wait, ${netLabel})`, ...stats(submitSamples) });
    results.push({ label: `verifyOnChain (verifySBOM view call, ${netLabel})`, ...stats(verifySamples) });

    console.log(
        `\nLatency benchmark (ms), network=${networkInfo.name ?? "unknown"} chainId=${networkInfo.chainId} contract=${contractAddress} + live registry.npmjs.org calls`
    );
    console.log("=".repeat(100));
    for (const r of results) {
        console.log(
            r.label.padEnd(55),
            `runs=${r.runs}`.padStart(9),
            `min=${r.min}`.padStart(14),
            `max=${r.max}`.padStart(14),
            `mean=${r.mean}`.padStart(14)
        );
    }

    console.log("\nJSON:");
    console.log(JSON.stringify(results, null, 2));
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});