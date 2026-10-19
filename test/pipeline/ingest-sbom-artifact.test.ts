import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ingestSbomArtifact } from "../../src/pipeline/ingest-sbom-artifact.ts";

describe("ingestSbomArtifact", () => {
    it("POSTs the readable projectId, version, content, riskScore, commit, and txHash", async (t) => {
        let capturedUrl: string | undefined;
        let capturedBody: unknown;

        t.mock.method(global, "fetch", async (url: string, init: RequestInit) => {
            capturedUrl = url;
            capturedBody = JSON.parse(init.body as string);
            return { ok: true, status: 200 } as Response;
        });

        await ingestSbomArtifact(
            {
                projectId: "sbom-blockchain-guardian",
                version: "1.0.0+abc1234",
                sbomContent: "{\"bomFormat\":\"CycloneDX\"}",
                riskScore: 5,
                commit: "abc1234",
                txHash: "0xdeadbeef",
            },
            "http://localhost:5006",
        );

        assert.equal(capturedUrl, "http://localhost:5006/api/sbom/ingest");
        assert.deepEqual(capturedBody, {
            projectId: "sbom-blockchain-guardian",
            version: "1.0.0+abc1234",
            sbomContent: "{\"bomFormat\":\"CycloneDX\"}",
            riskScore: 5,
            commit: "abc1234",
            txHash: "0xdeadbeef",
        });
    });

    it("does not throw when the request fails (best-effort)", async (t) => {
        t.mock.method(global, "fetch", async () => {
            throw new Error("network down");
        });

        await assert.doesNotReject(() =>
            ingestSbomArtifact(
                {
                    projectId: "sbom-blockchain-guardian",
                    version: "1.0.0+abc1234",
                    sbomContent: "{}",
                    riskScore: 0,
                    txHash: "0xdeadbeef",
                },
                "http://localhost:5006",
            ),
        );
    });

    it("does not throw when the server responds non-2xx (best-effort)", async (t) => {
        t.mock.method(global, "fetch", async () => {
            return { ok: false, status: 500, statusText: "Internal Server Error" } as Response;
        });

        await assert.doesNotReject(() =>
            ingestSbomArtifact(
                {
                    projectId: "sbom-blockchain-guardian",
                    version: "1.0.0+abc1234",
                    sbomContent: "{}",
                    riskScore: 0,
                    txHash: "0xdeadbeef",
                },
                "http://localhost:5006",
            ),
        );
    });

    it("defaults apiUrl to http://localhost:5006 when not given", async (t) => {
        let capturedUrl: string | undefined;
        t.mock.method(global, "fetch", async (url: string) => {
            capturedUrl = url;
            return { ok: true, status: 200 } as Response;
        });

        await ingestSbomArtifact({
            projectId: "sbom-blockchain-guardian",
            version: "1.0.0+abc1234",
            sbomContent: "{}",
            riskScore: 0,
            txHash: "0xdeadbeef",
        });

        assert.equal(capturedUrl, "http://localhost:5006/api/sbom/ingest");
    });
});
