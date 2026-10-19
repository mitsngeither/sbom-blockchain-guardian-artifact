import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ethers } from "ethers";

import { canonicalSbomDocument, parseRawSBOM } from "@guardian/sbom-core";
import { buildSBOMMerkleTree } from "@guardian/sbom-core";

import { scoreRiskComponents } from "../../src/detector/risk-scorer.ts";
import {
    NO_PACKAGES_ANALYZED_SCORE,
    prepareSubmission,
    type SubmissionRiskReport,
} from "../../src/pipeline/prepare-submission.ts";

const VALID_SBOM_CONTENT = JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    components: [
        {
            type: "library",
            name: "demo-lib",
            version: "1.0.0",
            "bom-ref": "demo-lib@1.0.0",
        },
    ],
});

function report(
    decision: "PASS" | "REVIEW" | "BLOCK" = "PASS",
    scores: number[] = [12, 44]
): SubmissionRiskReport {
    return {
        summary: { decision },
        packageReports: scores.map(riskScore => ({
            risk: { riskScore },
        })),
    };
}

describe("prepareSubmission", () => {
    it("builds deterministic hashes, merkle root, highest score, and SHA-qualified version", async (t) => {
        // "guardian-demo" is not on npm: registry answers 404
        t.mock.method(global, "fetch", async () => ({
            ok: false,
            status: 404,
        } as Response));

        const sbomContent = await import("node:fs/promises").then(fs =>
            fs.readFile("test/sboms/sbom-v3-axios-1.14.1.json", "utf8")
        );
        const parsedSbom = await parseRawSBOM("test/sboms/sbom-v3-axios-1.14.1.json");
        const prepared = await prepareSubmission({
            projectName: "guardian-demo",
            packageVersion: "1.2.3",
            sbomContent,
            riskReport: report("PASS", [7, 81, 20]),
            commitSha: "abcdef1234567890",
        });

        assert.deepEqual(prepared, {
            projectId: ethers.keccak256(ethers.toUtf8Bytes("guardian-demo")),
            submissionVersion: "1.2.3+abcdef1",
            sbomHash: ethers.keccak256(ethers.toUtf8Bytes(canonicalSbomDocument(sbomContent))),
            merkleRoot: buildSBOMMerkleTree(parsedSbom).root,
            riskScore: 81,
            analyzedPackages: 3,
            artifactHash: "",
            npmIntegrity: undefined,
            integrityMatches: undefined,
        });
    });

    it("uses an explicit submission version before commit metadata", async () => {
        const prepared = await prepareSubmission({
            projectName: "guardian-demo",
            packageVersion: "1.2.3",
            sbomContent: VALID_SBOM_CONTENT,
            riskReport: report(),
            commitSha: "abcdef1234567890",
            submissionVersion: "release-42",
        });

        assert.equal(prepared.submissionVersion, "release-42");
    });

    it("qualifies the SHA version with the CI run id so every dispatch gets a fresh version", async (t) => {
        t.mock.method(global, "fetch", async () => ({
            ok: false,
            status: 404,
        } as Response));

        const prepared = await prepareSubmission({
            projectName: "guardian-demo",
            packageVersion: "1.2.3",
            sbomContent: VALID_SBOM_CONTENT,
            riskReport: report(),
            commitSha: "abcdef1234567890",
            runId: "38037469173-1",
        });

        assert.equal(prepared.submissionVersion, "1.2.3+abcdef1.38037469173-1");
    });

    it("tags the derived version with the recording path so two paths in one run never collide", async (t) => {
        t.mock.method(global, "fetch", async () => ({
            ok: false,
            status: 404,
        } as Response));

        const prepared = await prepareSubmission({
            projectName: "guardian-demo",
            packageVersion: "1.2.3",
            sbomContent: VALID_SBOM_CONTENT,
            riskReport: report(),
            commitSha: "abcdef1234567890",
            runId: "38037469173-1",
            versionTag: "eip712",
        });

        assert.equal(prepared.submissionVersion, "1.2.3+abcdef1.38037469173-1.eip712");
    });

    it("never tags an explicit submission version", async (t) => {
        t.mock.method(global, "fetch", async () => ({
            ok: false,
            status: 404,
        } as Response));

        const prepared = await prepareSubmission({
            projectName: "guardian-demo",
            packageVersion: "1.2.3",
            sbomContent: VALID_SBOM_CONTENT,
            riskReport: report(),
            commitSha: "abcdef1234567890",
            submissionVersion: "release-42",
            runId: "38037469173-1",
            versionTag: "eip712",
        });

        assert.equal(prepared.submissionVersion, "release-42");
    });

    it("uses an explicit submission version before the CI run id", async (t) => {
        t.mock.method(global, "fetch", async () => ({
            ok: false,
            status: 404,
        } as Response));

        const prepared = await prepareSubmission({
            projectName: "guardian-demo",
            packageVersion: "1.2.3",
            sbomContent: VALID_SBOM_CONTENT,
            riskReport: report(),
            commitSha: "abcdef1234567890",
            submissionVersion: "release-42",
            runId: "38037469173-1",
        });

        assert.equal(prepared.submissionVersion, "release-42");
    });

    it("refuses reports that are not PASS", async () => {
        for (const decision of ["REVIEW", "BLOCK"] as const) {
            await assert.rejects(
                async () => await prepareSubmission({
                    projectName: "guardian-demo",
                    packageVersion: "1.2.3",
                    sbomContent: VALID_SBOM_CONTENT,
                    riskReport: report(decision),
                }),
                new RegExp(`decision is ${decision}`)
            );
        }
    });

    it("refuses submission when npm's declared integrity does not match the tarball it served", async (t) => {
        let call = 0;
        t.mock.method(global, "fetch", async () => {
            call += 1;
            if (call === 1) {
                return {
                    ok: true,
                    json: async () => ({
                        versions: {
                            "1.2.3": {
                                dist: {
                                    tarball: "https://registry.npmjs.org/guardian-demo/-/guardian-demo-1.2.3.tgz",
                                    // wrong on purpose
                                    integrity: "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                                },
                            },
                        },
                    }),
                } as unknown as Response;
            }
            return {
                arrayBuffer: async () => new TextEncoder().encode("fake-tarball-bytes").buffer,
            } as unknown as Response;
        });

        await assert.rejects(
            async () => await prepareSubmission({
                projectName: "guardian-demo",
                packageVersion: "1.2.3",
                sbomContent: VALID_SBOM_CONTENT,
                riskReport: report(),
            }),
            /artifact integrity does not match/
        );
    });

    it("requires project metadata and exact SBOM content", async () => {
        const base = {
            projectName: "guardian-demo",
            packageVersion: "1.2.3",
            sbomContent: VALID_SBOM_CONTENT,
            riskReport: report(),
        };

        await assert.rejects(
            async () => await prepareSubmission({ ...base, projectName: " " }),
            /project name/i
        );
        await assert.rejects(
            async () => await prepareSubmission({ ...base, packageVersion: " " }),
            /package version/i
        );
        await assert.rejects(
            async () => await prepareSubmission({ ...base, sbomContent: "" }),
            /SBOM content/i
        );
    });
});

describe("riskScore 0 is a sentinel, never an assessed-and-clean score", () => {
    it("cannot produce a score below 1 for a package it actually analyzed", () => {
        // S, O and D are at least 1, so a real analysis scores at least 1.
        const floor = scoreRiskComponents({
            severity: 1,
            occurrenceSignals: [1],
            detection: 1,
        });

        assert.equal(floor, 1);
        assert.ok(floor > NO_PACKAGES_ANALYZED_SCORE);
    });

    it("emits the sentinel exactly when no package was analyzed", async () => {
        const empty = await prepareSubmission({
            projectName: "demo",
            packageVersion: "1.0.0",
            sbomContent: VALID_SBOM_CONTENT,
            riskReport: report("PASS", []),
        });

        assert.equal(empty.riskScore, NO_PACKAGES_ANALYZED_SCORE);
        assert.equal(empty.analyzedPackages, 0);
    });

    it("reports analyzedPackages so a 0 can be told apart from a real score", async () => {
        const analyzed = await prepareSubmission({
            projectName: "demo",
            packageVersion: "1.0.0",
            sbomContent: VALID_SBOM_CONTENT,
            riskReport: report("PASS", [1]),
        });

        assert.equal(analyzed.riskScore, 1);
        assert.equal(analyzed.analyzedPackages, 1);
        assert.notEqual(analyzed.riskScore, NO_PACKAGES_ANALYZED_SCORE);
    });
});
