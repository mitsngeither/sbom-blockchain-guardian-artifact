import "dotenv/config";
import { readFile } from "node:fs/promises";

import { ethers as ethersLibrary } from "ethers";
import { network } from "hardhat";

import {
    NO_PACKAGES_ANALYZED_SCORE,
    prepareSubmission,
    type SubmissionRiskReport,
} from "../src/pipeline/prepare-submission.ts";
import { requireRunId, writeChainReceipt } from "../src/pipeline/write-chain-receipt.ts";
import { ingestSbomArtifact } from "../src/pipeline/ingest-sbom-artifact.ts";

function requireEnv(name: string): string {
    const value = process.env[name]?.trim();
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}


async function main(): Promise<void> {
    const sepoliaRpcUrl = requireEnv("SEPOLIA_RPC_URL");
    requireEnv("SEPOLIA_PRIVATE_KEY");
    const contractAddress = requireEnv("CONTRACT_ADDRESS");
    const reviewer1Key = requireEnv("REVIEWER_1_KEY");
    const reviewer2Key = requireEnv("REVIEWER_2_KEY");
    const { ethers } = await network.getOrCreate();
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

    const prepared = await prepareSubmission({
        projectName,
        packageVersion: packageJson.version ?? "",
        sbomContent,
        riskReport,
        commitSha: process.env.GITHUB_SHA,
        submissionVersion: process.env.SBOM_VERSION,
        runId,
    });

    const registry = await ethers.getContractAt("SBOMRegistry", contractAddress);

    const deployedCode = await ethers.provider.getCode(contractAddress);
    if (deployedCode === "0x") {
        throw new Error(`No SBOMRegistry contract code at ${contractAddress}`);
    }

    const rawProvider = new ethersLibrary.JsonRpcProvider(sepoliaRpcUrl);
    const reviewer1 = new ethersLibrary.Wallet(reviewer1Key, rawProvider);
    const reviewer2 = new ethersLibrary.Wallet(reviewer2Key, rawProvider);

    const [proposer] = await ethers.getSigners();
    const threshold = 2;

    const artifactHashForChain = prepared.artifactHash || ethersLibrary.ZeroHash;

    console.log(`Proposing SBOM for ${prepared.submissionVersion}...`);
    const proposeTx = await registry.connect(proposer).proposeSBOM(
        prepared.projectId,
        prepared.submissionVersion,
        prepared.sbomHash,
        artifactHashForChain,
        prepared.merkleRoot,
        prepared.riskScore,
        threshold
    );
    const proposeReceipt = await proposeTx.wait();
    if (!proposeReceipt) throw new Error("proposeSBOM transaction was not mined");

    const proposalCreated = proposeReceipt.logs
        .map((log: any) => { try { return registry.interface.parseLog(log); } catch { return null; } })
        .find((parsed: any) => parsed?.name === "ProposalCreated");
    if (!proposalCreated) throw new Error("ProposalCreated event not found");
    const proposalId = proposalCreated.args[0] as bigint;
    console.log(`Proposal created, id = ${proposalId}`);

    console.log("Reviewer 1 approving...");
    await (await registry.connect(reviewer1).approveSBOM(proposalId)).wait();

    console.log("Reviewer 2 approving...");
    await (await registry.connect(reviewer2).approveSBOM(proposalId)).wait();

    console.log("Executing proposal...");
    const executeTx = await registry.connect(proposer).executeProposal(proposalId);
    const executeReceipt = await executeTx.wait();
    if (!executeReceipt) throw new Error("executeProposal transaction was not mined");

    const verified = await registry.verifySBOM(
        prepared.projectId,
        prepared.submissionVersion,
        prepared.sbomHash
    );

    if (!verified) {
        throw new Error("On-chain SBOM verification failed after executeProposal");
    }

    await writeChainReceipt({
        runId,
        transactionHash: executeReceipt.hash,
        projectId: prepared.projectId,
        version: prepared.submissionVersion,
        merkleRoot: prepared.merkleRoot,
        riskScore: prepared.riskScore,
    });

    console.log("SBOM submitted via multisig and verified on-chain");
    console.log(`Execute tx: ${executeReceipt.hash}`);
    console.log(`Project ID: ${prepared.projectId}`);
    console.log(`Version: ${prepared.submissionVersion}`);
    console.log(`SBOM hash: ${prepared.sbomHash}`);
    console.log(`Artifact hash: ${artifactHashForChain}${prepared.artifactHash ? "" : " (zero-hash placeholder — project not published on npm)"}`);
    console.log(`Merkle root: ${prepared.merkleRoot}`);
    console.log(
        `Risk score: ${prepared.riskScore}` +
        (prepared.riskScore === NO_PACKAGES_ANALYZED_SCORE
            ? " (sentinel: no packages were analyzed)"
            : "")
    );
    console.log(`Policy decision: ${riskReport.summary.decision}`);
    console.log(`Verify result: ${verified}`);

    // The artifact store is keyed by the plain project name, not the on-chain hash.
    await ingestSbomArtifact({
        projectId: projectName,
        version: prepared.submissionVersion,
        sbomContent,
        riskScore: prepared.riskScore,
        commit: process.env.GITHUB_SHA,
        txHash: executeReceipt.hash,
    });
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
});