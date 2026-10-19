import "dotenv/config";
import { network } from "hardhat";

async function main() {
    const contractAddress = process.env.CONTRACT_ADDRESS;

    if (!contractAddress) {
        throw new Error("Missing CONTRACT_ADDRESS");
    }

    const { ethers } = await network.getOrCreate();

    const registry = await ethers.getContractAt(
        "SBOMRegistry",
        contractAddress
    );

    const projectName = "demo-project";
    const projectId = ethers.keccak256(
        ethers.toUtf8Bytes(projectName)
    );

    const version = "1.0.0";
    const riskScore = 12;

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
                name: "axios",
                version: "1.6.0",
            },
        ],
    });

    const sbomHash = ethers.keccak256(
        ethers.toUtf8Bytes(sbomJson)
    );
    const merkleRoot = ethers.keccak256(
        ethers.toUtf8Bytes(`merkle:${sbomJson}`)
    );

    const tx = await registry.registerSBOM(
        projectId,
        version,
        sbomHash,
        ethers.ZeroHash,
        merkleRoot,
        riskScore
    );

    await tx.wait();

    console.log("Registered SBOM");
    console.log("Project:", projectName);
    console.log("Version:", version);
    console.log("SBOM hash:", sbomHash);
    console.log("Merkle root:", merkleRoot);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});