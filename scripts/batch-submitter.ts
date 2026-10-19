// Signs several SBOM submissions with EIP-712 and sends them in one
// submitBatchWithSignatures call.
import "dotenv/config";
import { network } from "hardhat";

type SBOMSubmission = {
    projectId: string;
    version: string;
    sbomHash: string;
    artifactHash: string;
    merkleRoot: string;
    riskScore: number;
    nonce: bigint;
};

async function main() {
    const contractAddress = process.env.CONTRACT_ADDRESS;
    if (!contractAddress) throw new Error("Missing CONTRACT_ADDRESS");

    const { ethers } = await network.getOrCreate();
    const [submitter] = await ethers.getSigners();

    const registry = await ethers.getContractAt(
        "SBOMRegistry",
        contractAddress
    );

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

    const submissions: SBOMSubmission[] = [];
    const signatures: string[] = [];

    const projectName = "demo-project";
    const projectId = ethers.keccak256(ethers.toUtf8Bytes(projectName));
    const baseNonce = await registry.nonces(submitter.address);
    const versionPrefix = `1.0.${Date.now()}`;

    for (let i = 0; i < 3; i++) {
        const version = `${versionPrefix}-${i}`;

        const sbomJson = JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            metadata: {
                component: {
                    name: projectName,
                    version,
                },
            },
            components: [
                {
                    name: `demo-lib-${i}`,
                    version: "0.1.0",
                },
            ],
        });

        const submission = {
            projectId,
            version,
            sbomHash: ethers.keccak256(ethers.toUtf8Bytes(sbomJson)),
            artifactHash: ethers.ZeroHash,
            merkleRoot: ethers.keccak256(ethers.toUtf8Bytes(`merkle:${sbomJson}`)),
            riskScore: 12 + i,
            nonce: baseNonce + BigInt(i),
        };

        const signature = await submitter.signTypedData(
            domain,
            types,
            submission
        );

        submissions.push(submission);
        signatures.push(signature);
    }

    const tx = await registry.submitBatchWithSignatures(
        submissions,
        signatures
    );

    await tx.wait();

    console.log("Submitted batch");
    console.log("Signer:", submitter.address);
    console.log("Count:", submissions.length);
    console.log("Versions:", submissions.map((submission) => submission.version));
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
