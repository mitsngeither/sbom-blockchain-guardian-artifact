// EIP-712 signature for an SBOM submission
import "dotenv/config";
import { network } from "hardhat";

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
        verifyingContract: contractAddress
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
        ]
    };

    const projectName = "demo-project";
    const projectId = ethers.keccak256(
        ethers.toUtf8Bytes(projectName)
    );

    const version = `1.0.${Date.now()}`;
    const riskScore = 12;

    const sbomJson = JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        metadata: {
            component: {
                name: projectName,
                version
            },
        },
        components: [
            {
                name: "axios",
                version: "1.6.0"
            }
        ]
    });

    const sbomHash = ethers.keccak256(
        ethers.toUtf8Bytes(sbomJson)
    );
    const merkleRoot = ethers.keccak256(
        ethers.toUtf8Bytes(`merkle:${sbomJson}`)
    );

    const nonce = await registry.nonces(submitter.address);

    const submission = {
        projectId,
        version,
        sbomHash,
        artifactHash: ethers.ZeroHash,
        merkleRoot,
        riskScore,
        nonce,
    };

    const signature = await submitter.signTypedData(
        domain, types, submission
    );

    console.log("Signer", submitter.address);
    console.log("Submission", submission);
    console.log("Signature", signature);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});