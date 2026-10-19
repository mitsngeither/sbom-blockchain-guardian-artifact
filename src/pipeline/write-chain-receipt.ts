import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export interface ChainReceiptInput {
    runId: string;
    transactionHash: string;
    projectId: string;
    version: string;
    merkleRoot: string;
    riskScore: number;
}

export function receiptPathForRun(runId: string): string {
    return path.join("pipeline-artifacts", "chain", `receipt-${runId}.json`);
}

// Without a run id the receipt would be filed under the wrong run.
export function requireRunId(report: unknown): string {
    const runId =
        typeof report === "object" && report !== null
            ? (report as { runId?: unknown }).runId
            : undefined;

    if (typeof runId !== "string" || !runId.trim()) {
        throw new Error(
            "Risk report has no runId; re-run pipeline:risk to stamp one " +
            "before submitting, so the receipt can be paired with its run."
        );
    }

    return runId.trim();
}

/** Writes the per-run receipt that RunsService uses to mark a PASS run REGISTERED. */
export async function writeChainReceipt(
    receipt: ChainReceiptInput,
    receiptPath = process.env.RECEIPT_PATH ?? receiptPathForRun(receipt.runId),
): Promise<void> {
    await mkdir(path.dirname(receiptPath), { recursive: true });
    await writeFile(
        receiptPath,
        JSON.stringify(
            {
                status: "CONFIRMED",
                onChainStatus: "ATTESTED",
                runId: receipt.runId,
                transactionHash: receipt.transactionHash,
                projectId: receipt.projectId,
                version: receipt.version,
                merkleRoot: receipt.merkleRoot,
                riskScore: receipt.riskScore,
            },
            null,
            4,
        ) + "\n",
        "utf8",
    );
}
