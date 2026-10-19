import assert from "node:assert/strict";
import { describe, it } from "node:test";
import crypto from "node:crypto";
import { computeArtifactHash } from "@guardian/sbom-core";

// Buffer.from() on a short string returns a view into a shared 8 KB pool, so
// buf.buffer is the whole pool. Hand fetch only the bytes we mean.
function exactArrayBuffer(buf: Buffer): ArrayBuffer {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

describe("computeArtifactHash", () => {
    it("computes SHA-256 and matches npm's dist.integrity", async (t) => {
        const fakeTarball = Buffer.from("fake tarball content for test");
        const realSha512Base64 = crypto.createHash("sha512").update(fakeTarball).digest("base64");

        let callCount = 0;
        t.mock.method(global, "fetch", async () => {
            callCount++;
            if (callCount === 1) {
                // first call: registry metadata
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        name: "demo-pkg",
                        versions: {
                            "1.0.0": {
                                dist: {
                                    tarball: "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz",
                                    integrity: `sha512-${realSha512Base64}`,
                                },
                            },
                        },
                    }),
                } as Response;
            }
            // second call: the tarball itself
            return {
                ok: true,
                arrayBuffer: async () => exactArrayBuffer(fakeTarball),
            } as Response;
        });

        const result = await computeArtifactHash("demo-pkg", "1.0.0");

        assert.equal(
            result.artifactHash,
            "0x" + crypto.createHash("sha256").update(fakeTarball).digest("hex")
        );
        assert.equal(result.integrityMatches, true);
    });

    it("reports integrityMatches: false on tampered content", async (t) => {
        const servedTarball = Buffer.from("tarball the registry actually served");

        let callCount = 0;
        t.mock.method(global, "fetch", async () => {
            callCount++;
            if (callCount === 1) {
                // integrity belongs to some other content
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        versions: {
                            "1.0.0": {
                                dist: {
                                    tarball: "https://x/tarball.tgz",
                                    integrity: "sha512-" + "a".repeat(88),
                                },
                            },
                        },
                    }),
                } as Response;
            }
            return {
                ok: true,
                arrayBuffer: async () => exactArrayBuffer(servedTarball),
            } as Response;
        });

        const result = await computeArtifactHash("demo-pkg", "1.0.0");

        assert.equal(result.integrityMatches, false);
        assert.equal(
            result.artifactHash,
            "0x" + crypto.createHash("sha256").update(servedTarball).digest("hex")
        );
    });
});