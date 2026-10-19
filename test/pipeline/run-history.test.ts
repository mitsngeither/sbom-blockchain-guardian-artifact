import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
    buildRunHistoryEnvelope,
    historyDirFor,
    HISTORY_RETENTION,
    pruneRunHistory,
    writeRunHistoryEntry,
} from "../../src/pipeline/run-history.ts";

const REPORT = {
    projectId: "sbom-blockchain-guardian",
    currentVersion: "1.0.0",
    mode: "full",
    summary: { overallRating: "LOW", decision: "PASS", analyzedPackages: 3, skippedPackages: 0, reasons: [] },
};

describe("buildRunHistoryEnvelope", () => {
    const saved = { ...process.env };

    afterEach(() => {
        process.env = { ...saved };
    });

    it("uses the GitHub run id and attempt when CI provides them", () => {
        process.env.GITHUB_RUN_ID = "1234567890";
        process.env.GITHUB_RUN_ATTEMPT = "2";
        process.env.GITHUB_SHA = "702fa42abcdef0123456789";

        const envelope = buildRunHistoryEnvelope(new Date("2026-08-26T09:42:18Z"));

        assert.equal(envelope.runId, "1234567890-2");
        assert.equal(envelope.commit, "702fa42");
        assert.equal(envelope.timestamp, "2026-08-26T09:42:18.000Z");
    });

    it("falls back to a local run id and commit outside CI", () => {
        delete process.env.GITHUB_RUN_ID;
        delete process.env.GITHUB_RUN_ATTEMPT;
        delete process.env.GITHUB_SHA;

        const envelope = buildRunHistoryEnvelope(new Date("2026-08-26T09:42:18Z"));

        assert.equal(envelope.runId, "local-20260826T094218Z");
        assert.equal(envelope.commit, "local");
    });
});

describe("writeRunHistoryEntry", () => {
    let dir: string;

    beforeEach(() => {
        dir = mkdtempSync(join(tmpdir(), "guardian-history-"));
    });

    afterEach(() => {
        rmSync(dir, { recursive: true, force: true });
    });

    it("derives the history directory from the report path", () => {
        assert.equal(historyDirFor(join(dir, "risk-report.json")), join(dir, "history"));
    });

    it("writes the report plus the envelope fields under <runId>.json", async () => {
        const envelope = { runId: "42-1", commit: "abc1234", timestamp: "2026-08-26T09:42:18.000Z" };

        const written = await writeRunHistoryEntry(join(dir, "risk-report.json"), REPORT, envelope);

        assert.equal(written, join(dir, "history", "42-1.json"));
        const entry = JSON.parse(readFileSync(written, "utf8")) as Record<string, unknown>;
        assert.equal(entry.runId, "42-1");
        assert.equal(entry.commit, "abc1234");
        assert.equal(entry.timestamp, "2026-08-26T09:42:18.000Z");
        assert.equal(entry.projectId, "sbom-blockchain-guardian");
        assert.deepEqual((entry.summary as { reasons: string[] }).reasons, []);
    });

    it("keeps the envelope authoritative when the report carries colliding keys", async () => {
        const envelope = { runId: "42-1", commit: "abc1234", timestamp: "2026-08-26T09:42:18.000Z" };
        const colliding = { ...REPORT, runId: "hijacked", commit: "0000000", timestamp: "1999-01-01T00:00:00.000Z" };

        const written = await writeRunHistoryEntry(join(dir, "risk-report.json"), colliding, envelope);

        const entry = JSON.parse(readFileSync(written, "utf8")) as Record<string, unknown>;
        assert.equal(entry.runId, "42-1");
        assert.equal(entry.commit, "abc1234");
        assert.equal(entry.timestamp, "2026-08-26T09:42:18.000Z");
    });
});

describe("pruneRunHistory", () => {
    let dir: string;

    beforeEach(() => {
        dir = mkdtempSync(join(tmpdir(), "guardian-prune-"));
        mkdirSync(dir, { recursive: true });
    });

    afterEach(() => {
        rmSync(dir, { recursive: true, force: true });
    });

    function seed(count: number): void {
        for (let index = 0; index < count; index += 1) {
            const minute = String(index).padStart(2, "0");
            writeFileSync(
                join(dir, `run-${minute}.json`),
                JSON.stringify({ runId: `run-${minute}`, timestamp: `2026-08-26T09:${minute}:00.000Z` }),
            );
        }
    }

    it("keeps the newest entries and drops the oldest", async () => {
        seed(HISTORY_RETENTION + 3);

        await pruneRunHistory(dir);

        const remaining = (await readdir(dir)).sort();
        assert.equal(remaining.length, HISTORY_RETENTION);
        assert.ok(!remaining.includes("run-00.json"), "oldest entry must be pruned");
        assert.ok(remaining.includes(`run-${String(HISTORY_RETENTION + 2).padStart(2, "0")}.json`));
    });

    it("leaves a directory below the retention limit untouched", async () => {
        seed(3);

        await pruneRunHistory(dir);

        assert.equal((await readdir(dir)).length, 3);
    });

    it("ignores an entry whose JSON is corrupt instead of throwing", async () => {
        seed(2);
        writeFileSync(join(dir, "broken.json"), "{not json");

        await pruneRunHistory(dir, 2);

        const remaining = await readdir(dir);
        assert.equal(remaining.length, 2);
        assert.ok(!remaining.includes("broken.json"), "corrupt entries sort oldest and are pruned first");
    });
});

describe("run-risk-pipeline wiring", () => {
    let dir: string;

    beforeEach(() => {
        dir = mkdtempSync(join(tmpdir(), "guardian-wiring-"));
    });

    afterEach(() => {
        rmSync(dir, { recursive: true, force: true });
    });

    it("writes a history entry whose runId matches the report it stamped", () => {
        const sbomPath = join(dir, "bom.json");
        const reportPath = join(dir, "risk-report.json");

        writeFileSync(
            sbomPath,
            JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: [] }),
        );

        execFileSync(
            "node",
            ["--import=tsx", "src/pipeline/run-risk-pipeline.ts", sbomPath, "none", reportPath],
            {
                env: {
                    ...process.env,
                    GITHUB_RUN_ID: "424242",
                    GITHUB_RUN_ATTEMPT: "1",
                    GITHUB_SHA: "abcdef1234567890",
                },
                stdio: "pipe",
            },
        );

        const report = JSON.parse(readFileSync(reportPath, "utf8")) as {
            runId: string;
            commit: string;
            timestamp: string;
        };

        assert.equal(report.runId, "424242-1");
        assert.equal(report.commit, "abcdef1");
        assert.ok(report.timestamp, "the report must carry the run timestamp");

        // The submit scripts pair a receipt to its run by exactly this id.
        const entry = JSON.parse(
            readFileSync(join(dir, "history", "424242-1.json"), "utf8"),
        ) as { runId: string; summary: { decision: string } };

        assert.equal(entry.runId, report.runId);
        assert.equal(entry.summary.decision, "PASS");
    });
});
