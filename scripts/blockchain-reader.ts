import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { network } from "hardhat";

type StatusName = "None" | "Active" | "Revoked";
type ReaderCommand = "latest" | "history" | "verify";

export type SBOMRecordView = {
    sbomHash: string;
    merkleRoot: string;
    submitter: string;
    timestamp: string;
    riskScore: number;
    status: StatusName;
};

const STATUS_NAMES: StatusName[] = ["None", "Active", "Revoked"];
const READER_COMMANDS: ReaderCommand[] = ["latest", "history", "verify"];

function normalizeBytes32(value: string, label: string): string {
    if (ethers.isHexString(value, 32)) {
        return value;
    }

    if (value.startsWith("0x")) {
        throw new Error(`${label} must be a 32-byte hex string`);
    }

    return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function normalizeProjectId(projectId: string): string {
    return normalizeBytes32(projectId, "projectId");
}

function normalizeSbomHash(sbomHash: string): string {
    return normalizeBytes32(sbomHash, "sbomHash");
}

async function getRegistry() {
    const contractAddress = process.env.CONTRACT_ADDRESS;

    if (!contractAddress) {
        throw new Error("Missing CONTRACT_ADDRESS env variable");
    }

    const { ethers: hardhatEthers } = await network.getOrCreate();
    const deployedCode = await hardhatEthers.provider.getCode(contractAddress);

    if (deployedCode === "0x") {
        throw new Error("No contract code found at CONTRACT_ADDRESS " + contractAddress);
    }

    return hardhatEthers.getContractAt("SBOMRegistry", contractAddress);
}

function formatRecord(record: any): SBOMRecordView {
    const statusIndex = Number(record.status);

    return {
        sbomHash: record.sbomHash,
        merkleRoot: record.merkleRoot,
        submitter: record.submitter,
        timestamp: record.timestamp.toString(),
        riskScore: Number(record.riskScore),
        status: STATUS_NAMES[statusIndex] ?? "None",
    };
}

export async function getLatest(projectId: string): Promise<SBOMRecordView> {
    const registry = await getRegistry();
    const record = await registry.getLatest(normalizeProjectId(projectId));

    return formatRecord(record);
}

export async function getHistory(projectId: string): Promise<string[]> {
    const registry = await getRegistry();

    return registry.getHistory(normalizeProjectId(projectId));
}

export async function verifySBOM(
    projectId: string,
    version: string,
    sbomHash: string
): Promise<boolean> {
    const registry = await getRegistry();

    return registry.verifySBOM(
        normalizeProjectId(projectId),
        version,
        normalizeSbomHash(sbomHash)
    );
}

function readCliInput() {
    const args = process.argv.slice(2);
    const commandIndex = args.findIndex((arg): arg is ReaderCommand =>
        READER_COMMANDS.includes(arg as ReaderCommand)
    );

    const command =
        (process.env.READER_COMMAND as ReaderCommand | undefined) ??
        (commandIndex >= 0 ? (args[commandIndex] as ReaderCommand) : undefined);

    return {
        command,
        projectId:
            process.env.PROJECT_ID ??
            (commandIndex >= 0 ? args[commandIndex + 1] : undefined),
        version:
            process.env.VERSION ??
            (commandIndex >= 0 ? args[commandIndex + 2] : undefined),
        sbomHash:
            process.env.SBOM_HASH ??
            (commandIndex >= 0 ? args[commandIndex + 3] : undefined),
    };
}

async function main() {
    const { command, projectId, version, sbomHash } = readCliInput();

    if (!command || !projectId) {
        console.log(
            "Usage: READER_COMMAND=<latest|history|verify> PROJECT_ID=<projectId> [VERSION=<version>] [SBOM_HASH=<hash>] npx hardhat run scripts/blockchain-reader.ts --network <network>"
        );
        process.exitCode = 1;
        return;
    }

    if (command === "latest") {
        console.log(await getLatest(projectId));
        return;
    }

    if (command === "history") {
        console.log(await getHistory(projectId));
        return;
    }

    if (!version || !sbomHash) {
        throw new Error("verify requires VERSION and SBOM_HASH");
    }

    console.log(await verifySBOM(projectId, version, sbomHash));
}

function isExecutedScript(): boolean {
    const currentFile = fileURLToPath(import.meta.url);

    return process.argv.some((arg) => path.resolve(arg) === currentFile);
}

if (isExecutedScript()) {
    main().catch((error) => {
        console.error(error);
        process.exitCode = 1;
    });
}
