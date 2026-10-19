import "dotenv/config";
import { readFile } from "node:fs/promises";

import { ethers as ethersLibrary } from "ethers";
import { network } from "hardhat";

import {
    NO_PACKAGES_ANALYZED_SCORE,
    prepareSubmission,
    type SubmissionRiskReport,
} from "../src/pipeline/prepare-submission.ts";
import { receiptPathForRun, requireRunId, writeChainReceipt } from "../src/pipeline/write-chain-receipt.ts";
import { ingestSbomArtifact } from "../src/pipeline/ingest-sbom-artifact.ts";

const EIP712_TYPES = {
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

function requireEnv(name: string): string {
    const value = process.env[name]?.trim();

    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }

    return value;
}

async function main(): Promise<void> {
    requireEnv("RPC_URL");
    requireEnv("PRIVATE_KEY");
    const contractAddress = requireEnv("CONTRACT_ADDRESS");

    if (!ethersLibrary.isAddress(contractAddress)) {
        throw new Error("CONTRACT_ADDRESS is not a valid Ethereum address");
    }

    const sbomPath = process.env.SBOM_PATH ??
        "pipeline-artifacts/sbom/current-bom.json";
    const reportPath = process.env.RISK_REPORT_PATH ??
        "pipeline-artifacts/risk/risk-report.json";
    const [sbomContent, reportContent, packageContent] = await Promise.all([
        readFile(sbomPath, "utf8"),
        readFile(reportPath, "utf8"),
        readFile("package.json", "utf8"),
    ]);
    const riskReport = JSON.parse(reportContent) as SubmissionRiskReport;
    const runId = requireRunId(riskReport);
    const packageJson = JSON.parse(packageContent) as {
        name?: string;
        version?: string;
    };
    const projectName = packageJson.name ?? "";
    // Set when CI runs this path alongside the threshold path in one run.
    const submissionTag = process.env.SUBMISSION_TAG?.trim() || undefined;
    const prepared = await prepareSubmission({
        projectName,
        packageVersion: packageJson.version ?? "",
        sbomContent,
        riskReport,
        commitSha: process.env.GITHUB_SHA,
        submissionVersion: process.env.SBOM_VERSION,
        runId,
        versionTag: submissionTag,
    });

    const { ethers } = await network.getOrCreate();
    const [submitter] = await ethers.getSigners();
    const registry = await ethers.getContractAt(
        "SBOMRegistry",
        contractAddress
    );
    const deployedCode = await ethers.provider.getCode(contractAddress);

    if (deployedCode === "0x") {
        throw new Error(
            `No SBOMRegistry contract code at ${contractAddress}`
        );
    }

    const networkInfo = await ethers.provider.getNetwork();
    const nonce = await registry.nonces(submitter.address);
    const artifactHashForChain = prepared.artifactHash || ethersLibrary.ZeroHash;
    const submission = {
        projectId: prepared.projectId,
        version: prepared.submissionVersion,
        sbomHash: prepared.sbomHash,
        artifactHash: artifactHashForChain,
        merkleRoot: prepared.merkleRoot,
        riskScore: prepared.riskScore,
        nonce,
    };
    const signature = await submitter.signTypedData(
        {
            name: "MyDApp",
            version: "1",
            chainId: networkInfo.chainId,
            verifyingContract: contractAddress,
        },
        EIP712_TYPES,
        submission
    );
    const transaction = await registry.submitWithSignature(
        submission,
        signature
    );
    const receipt = await transaction.wait();

    if (!receipt) {
        throw new Error("Submission transaction was not mined");
    }

    const verified = await registry.verifySBOM(
        prepared.projectId,
        prepared.submissionVersion,
        prepared.sbomHash
    );

    if (!verified) {
        throw new Error("On-chain SBOM verification failed after submission");
    }

    // Tagged runs write their own receipt instead of overwriting receipt-<runId>.json.
    await writeChainReceipt(
        {
            runId,
            transactionHash: receipt.hash,
            projectId: prepared.projectId,
            version: prepared.submissionVersion,
            merkleRoot: prepared.merkleRoot,
            riskScore: prepared.riskScore,
        },
        process.env.RECEIPT_PATH ??
        receiptPathForRun(submissionTag ? `${runId}-${submissionTag}` : runId)
    );

    console.log("SBOM submitted and verified on-chain");
    console.log(`Transaction hash: ${receipt.hash}`);
    console.log(`Block number: ${receipt.blockNumber}`);
    console.log(`Project ID: ${prepared.projectId}`);
    console.log(`Version: ${prepared.submissionVersion}`);
    console.log(`SBOM hash: ${prepared.sbomHash}`);
    console.log(`Merkle root: ${prepared.merkleRoot}`);
    console.log(
        `Risk score: ${prepared.riskScore}` +
        (prepared.riskScore === NO_PACKAGES_ANALYZED_SCORE
            ? " (sentinel: no packages were analyzed, so this is not" +
            " an assessed-and-clean score)"
            : "")
    );
    console.log(`Analyzed packages: ${prepared.analyzedPackages}`);
    console.log(`Policy decision: ${riskReport.summary.decision}`);
    console.log(`Verify result: ${verified}`);

    // The artifact store is keyed by the plain project name, not the on-chain hash.
    await ingestSbomArtifact({
        projectId: projectName,
        version: prepared.submissionVersion,
        sbomContent,
        riskScore: prepared.riskScore,
        commit: process.env.GITHUB_SHA,
        txHash: receipt.hash,
    });
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
});
