import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
    receiptPathForRun,
    requireRunId,
    writeChainReceipt,
} from "../../src/pipeline/write-chain-receipt.ts";

const RECEIPT = {
    runId: "1234567890-1",
    transactionHash: "0x" + "a".repeat(64),
    projectId: "0x" + "b".repeat(64),
    version: "1.0.0+702fa42",
    merkleRoot: "0x" + "c".repeat(64),
    riskScore: 7,
};

describe("receiptPathForRun", () => {
    it("names the receipt after the run it belongs to", () => {
        assert.equal(
            receiptPathForRun("1234567890-1"),
            "pipeline-artifacts/chain/receipt-1234567890-1.json",
        );
    });
});

describe("requireRunId", () => {
    it("reads the run id a stamped risk report carries", () => {
        assert.equal(requireRunId({ runId: "77-1" }), "77-1");
    });

    it("throws rather than let a receipt be filed under a guessed id", () => {
        assert.throws(() => requireRunId({}), /runId/);
        assert.throws(() => requireRunId({ runId: "   " }), /runId/);
    });

    it("throws an actionable message rather than a raw TypeError on null", () => {
        assert.throws(() => requireRunId(null), /runId/);
    });
});

describe("writeChainReceipt", () => {
    let dir: string;

    beforeEach(() => {
        dir = mkdtempSync(join(tmpdir(), "guardian-write-receipt-"));
    });

    afterEach(() => {
        rmSync(dir, { recursive: true, force: true });
        delete process.env.RECEIPT_PATH;
    });

    it("records the run id inside the receipt", async () => {
        const target = join(dir, "receipt-1234567890-1.json");

        await writeChainReceipt(RECEIPT, target);

        const written = JSON.parse(readFileSync(target, "utf8")) as Record<string, unknown>;
        assert.equal(written.runId, "1234567890-1");
        assert.equal(written.status, "CONFIRMED");
        assert.equal(written.version, "1.0.0+702fa42");
    });

    it("still honours the RECEIPT_PATH override", async () => {
        const target = join(dir, "custom.json");
        process.env.RECEIPT_PATH = target;

        await writeChainReceipt(RECEIPT);

        assert.equal(
            (JSON.parse(readFileSync(target, "utf8")) as { runId: string }).runId,
            "1234567890-1",
        );
    });
});
