import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { parseRawSBOM } from "@guardian/sbom-core";
import {
    buildSBOMMerkleTree,
    createComponentProof,
    verifyComponentProof,
} from "@guardian/sbom-core";

interface CliOptions {
    sbomPath: string;
    packageSelector?: string;
    outputPath?: string;
}

function usage(): string {
    return [
        "Usage:",
        "  tsx scripts/sbom-to-merkle.ts --sbom <path> [--package <name|purl|key>] [--out <path>]",
        "",
        "Example:",
        "  tsx scripts/sbom-to-merkle.ts --sbom test/sboms/sbom-v3-axios-1.14.1.json --package axios --out pipeline-artifacts/merkle/axios-proof.json",
    ].join("\n");
}

function readOption(args: string[], name: string): string | undefined {
    const index = args.indexOf(name);

    if (index < 0) {
        return undefined;
    }

    return args[index + 1];
}

function parseArgs(args: string[]): CliOptions {
    const positional = args.filter((arg, index) =>
        !arg.startsWith("--") && !args[index - 1]?.startsWith("--")
    );
    const sbomPath = readOption(args, "--sbom") ?? positional[0];
    const packageSelector = readOption(args, "--package") ?? positional[1];
    const outputPath = readOption(args, "--out");

    if (!sbomPath) {
        throw new Error(usage());
    }

    return {
        sbomPath,
        packageSelector,
        outputPath,
    };
}

async function writeArtifact(
    outputPath: string,
    artifact: Record<string, unknown>
): Promise<void> {
    const directory = path.dirname(outputPath);

    await mkdir(directory, { recursive: true });
    await writeFile(
        outputPath,
        JSON.stringify(artifact, null, 2) + "\n",
        "utf8"
    );
}

async function main(): Promise<void> {
    const options = parseArgs(process.argv.slice(2));
    const sbom = await parseRawSBOM(options.sbomPath);
    const merkleTree = buildSBOMMerkleTree(sbom);
    const packageSelector = options.packageSelector ?? merkleTree.leaves[0].key;
    const proof = createComponentProof(
        merkleTree,
        packageSelector
    );
    const verified = verifyComponentProof(proof);
    const artifact = {
        sbomPath: options.sbomPath,
        merkleRoot: merkleTree.root,
        leafCount: merkleTree.leaves.length,
        packageSelector,
        verified,
        proof,
        tree: merkleTree.tree.dump(),
    };

    if (options.outputPath) {
        await writeArtifact(options.outputPath, artifact);
    }

    console.log("SBOM Merkle demo");
    console.log(`SBOM: ${options.sbomPath}`);
    console.log(`Merkle root: ${merkleTree.root}`);
    console.log(`Leaf count: ${merkleTree.leaves.length}`);
    console.log(`Package selector: ${packageSelector}`);
    console.log(`Package: ${proof.leaf.identity}@${proof.leaf.version}`);
    console.log(`Component key: ${proof.leaf.key}`);
    console.log(`Component hash: ${proof.leaf.componentHash}`);
    console.log(`Proof entries: ${proof.proof.length}`);
    console.log(`Proof verified off-chain: ${verified ? "yes" : "no"}`);

    if (options.outputPath) {
        console.log(`Artifact written: ${options.outputPath}`);
    }
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
});
