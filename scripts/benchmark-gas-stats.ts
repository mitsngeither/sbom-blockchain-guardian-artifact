import { network } from "hardhat";

const RUNS = Number(process.env.GAS_BENCH_RUNS ?? "100");

function stats(samples: bigint[]) {
    const min = samples.reduce((a, b) => (b < a ? b : a));
    const max = samples.reduce((a, b) => (b > a ? b : a));
    const sum = samples.reduce((a, b) => a + b, 0n);
    const mean = Number(sum) / samples.length;
    return {
        min: min.toString(),
        max: max.toString(),
        mean: mean.toFixed(1),
        runs: samples.length,
    };
}

async function main() {
    const { ethers } = await network.getOrCreate();
    const signers = await ethers.getSigners();
    const owner = signers[0];
    const chainIdForKeys = Number((await ethers.provider.getNetwork()).chainId);
    // v2 forbids self-approval, so N=2 needs two approvers besides the proposer, like CI.
    const approvers =
        chainIdForKeys === 11155111
            ? [
                  new ethers.Wallet(process.env.REVIEWER_1_KEY!, ethers.provider),
                  new ethers.Wallet(process.env.REVIEWER_2_KEY!, ethers.provider),
              ]
            : [signers[1], signers[2]];

    const SBOMRegistry = await ethers.getContractFactory("SBOMRegistry");
    const registry = await SBOMRegistry.deploy();
    await registry.waitForDeployment();
    const contractAddress = await registry.getAddress();

    const teamMemberRole = await registry.TEAM_MEMBER_ROLE();
    for (const approver of approvers) {
        await (await registry.grantRole(teamMemberRole, await approver.getAddress())).wait();
    }

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

    const results: Record<string, bigint[]> = {
        registerSBOM: [],
        submitWithSignature: [],
        proposeSBOM: [],
        approveSBOM: [],
        executeProposal: [],
        revokeVersion: [],
    };
    const blocks: number[] = [];

    for (let i = 0; i < RUNS; i++) {
        // registerSBOM
        {
            const projectId = ethers.keccak256(
                ethers.toUtf8Bytes(`gas-register-${i}`)
            );
            const version = `1.0.${i}`;
            const sbomHash = ethers.keccak256(
                ethers.toUtf8Bytes(`sbom-${i}`)
            );
            const artifactHash = ethers.keccak256(
                ethers.toUtf8Bytes(`artifact-${i}`)
            );
            const merkleRoot = ethers.keccak256(
                ethers.toUtf8Bytes(`merkle-${i}`)
            );
            const tx = await registry.registerSBOM(
                projectId,
                version,
                sbomHash,
                artifactHash,
                merkleRoot,
                12
            );
            const receipt = await tx.wait();
            results.registerSBOM.push(receipt!.gasUsed);
            blocks.push(receipt!.blockNumber);
        }

        // submitWithSignature
        {
            const projectId = ethers.keccak256(
                ethers.toUtf8Bytes(`gas-sig-${i}`)
            );
            const version = `1.0.${i}`;
            const sbomHash = ethers.keccak256(
                ethers.toUtf8Bytes(`sig-sbom-${i}`)
            );
            const artifactHash = ethers.keccak256(
                ethers.toUtf8Bytes(`sig-artifact-${i}`)
            );
            const merkleRoot = ethers.keccak256(
                ethers.toUtf8Bytes(`sig-merkle-${i}`)
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
            const signature = await owner.signTypedData(
                domain,
                types,
                submission
            );
            const tx = await registry.submitWithSignature(
                submission,
                signature
            );
            const receipt = await tx.wait();
            results.submitWithSignature.push(receipt!.gasUsed);
            blocks.push(receipt!.blockNumber);
        }

        // proposeSBOM
        let proposalId: bigint;
        {
            const projectId = ethers.keccak256(
                ethers.toUtf8Bytes(`gas-proposal-${i}`)
            );
            const version = `1.0.${i}`;
            const sbomHash = ethers.keccak256(
                ethers.toUtf8Bytes(`prop-sbom-${i}`)
            );
            const artifactHash = ethers.keccak256(
                ethers.toUtf8Bytes(`prop-artifact-${i}`)
            );
            const merkleRoot = ethers.keccak256(
                ethers.toUtf8Bytes(`prop-merkle-${i}`)
            );
            const tx = await registry.proposeSBOM(
                projectId,
                version,
                sbomHash,
                artifactHash,
                merkleRoot,
                12,
                2
            );
            const receipt = await tx.wait();
            results.proposeSBOM.push(receipt!.gasUsed);
            blocks.push(receipt!.blockNumber);
            proposalId = BigInt(i);
        }

        // approveSBOM (first approver; measured)
        {
            const tx = await (registry.connect(approvers[0]) as typeof registry).approveSBOM(proposalId);
            const receipt = await tx.wait();
            results.approveSBOM.push(receipt!.gasUsed);
            blocks.push(receipt!.blockNumber);
        }

        // executeProposal (second approver reaches threshold=2, then the proposer executes)
        {
            await (await (registry.connect(approvers[1]) as typeof registry).approveSBOM(proposalId)).wait();
            const tx = await registry.executeProposal(proposalId);
            const receipt = await tx.wait();
            results.executeProposal.push(receipt!.gasUsed);
            blocks.push(receipt!.blockNumber);
        }

        // revokeVersion (revoke the SBOM registered at the top of this loop iteration)
        {
            const projectId = ethers.keccak256(
                ethers.toUtf8Bytes(`gas-register-${i}`)
            );
            const version = `1.0.${i}`;
            const tx = await registry.revokeVersion(
                projectId,
                version,
                "gas benchmark revoke"
            );
            const receipt = await tx.wait();
            results.revokeVersion.push(receipt!.gasUsed);
            blocks.push(receipt!.blockNumber);
        }
    }

    // Label from the provider, so Hardhat and Sepolia runs are labelled correctly.
    const chainId = Number(networkInfo.chainId);
    const networkLabel =
        chainId === 11155111
            ? "Sepolia public testnet (chainId 11155111)"
            : chainId === 1337
                ? `local dev chain (chainId ${chainId})`
                : `in-memory Hardhat network (chainId ${chainId})`;

    console.log(`\nGas benchmark: ${RUNS} runs per function, ${networkLabel}`);
    console.log("Contract:", contractAddress);
    console.log("=".repeat(70));
    console.log(
        "function".padEnd(22),
        "runs".padStart(5),
        "min".padStart(10),
        "max".padStart(10),
        "mean".padStart(12)
    );
    for (const [name, samples] of Object.entries(results)) {
        const s = stats(samples);
        console.log(
            name.padEnd(22),
            String(s.runs).padStart(5),
            s.min.padStart(10),
            s.max.padStart(10),
            s.mean.padStart(12)
        );
    }

    console.log("\nJSON:");
    console.log(
        JSON.stringify(
            Object.fromEntries(
                Object.entries(results).map(([name, samples]) => [
                    name,
                    stats(samples),
                ])
            ),
            null,
            2
        )
    );

    const firstBlock = await ethers.provider.getBlock(Math.min(...blocks));
    const lastBlock = await ethers.provider.getBlock(Math.max(...blocks));
    console.log("\nRAW:");
    console.log(
        JSON.stringify(
            {
                samples: Object.fromEntries(
                    Object.entries(results).map(([name, samples]) => [name, samples.map(String)])
                ),
                firstBlock: firstBlock!.number,
                lastBlock: lastBlock!.number,
                avgBlockTimeSeconds:
                    (lastBlock!.timestamp - firstBlock!.timestamp) /
                    (lastBlock!.number - firstBlock!.number),
                blockGasLimit: lastBlock!.gasLimit.toString(),
            },
            null,
            2
        )
    );
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});