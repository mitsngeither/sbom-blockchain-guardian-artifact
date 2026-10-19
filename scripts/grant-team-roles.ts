import "dotenv/config";
import { network } from "hardhat";

async function main() {
    const { ethers } = await network.getOrCreate();
    const registry = await ethers.getContractAt("SBOMRegistry", process.env.CONTRACT_ADDRESS!);

    const TEAM_MEMBER_ROLE = await registry.TEAM_MEMBER_ROLE();
    const reviewer1 = process.env.REVIEWER_1_ADDRESS!;
    const reviewer2 = process.env.REVIEWER_2_ADDRESS!;

    await (await registry.grantRole(TEAM_MEMBER_ROLE, reviewer1)).wait();
    console.log("Granted TEAM_MEMBER_ROLE to reviewer 1:", reviewer1);

    await (await registry.grantRole(TEAM_MEMBER_ROLE, reviewer2)).wait();
    console.log("Granted TEAM_MEMBER_ROLE to reviewer 2:", reviewer2);

    console.log("Done.");
}

main().catch(err => { console.error(err); process.exit(1); });