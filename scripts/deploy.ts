import "dotenv/config";
import { network } from "hardhat";

async function main() {
    const { ethers } = await network.getOrCreate();

    const SBOMRegistry = await ethers.getContractFactory("SBOMRegistry");
    const registry = await SBOMRegistry.deploy();

    await registry.waitForDeployment();

    const address = await registry.getAddress();
    console.log("SBOMRegistry deployed to:", address);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
}); 