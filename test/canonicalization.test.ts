import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ethers } from "ethers";

import { canonicalSbomDocument, parseSBOMContent } from "@guardian/sbom-core";
import {
    buildSBOMMerkleTree,
    hashSBOMComponent,
} from "@guardian/sbom-core";
import type {
    FlattenedSBOM,
    FlattenedSBOMComponent,
} from "@guardian/sbom-core";

function component(
    name: string,
    version = "1.0.0",
    overrides: Partial<FlattenedSBOMComponent> = {}
): FlattenedSBOMComponent {
    const key = `pkg:npm/${name}@${version}`;

    return {
        key,
        identity: name,
        bomRef: key,
        type: "library",
        name,
        version,
        purl: key,
        licenseIds: [],
        licenseExpressions: [],
        hashes: [],
        externalUrls: [],
        dependencies: [],
        capabilities: [],
        ...overrides,
    };
}

function sbom(components: FlattenedSBOMComponent[]): FlattenedSBOM {
    return {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        version: 1,
        components,
        componentMap: Object.fromEntries(
            components.map(item => [item.key, item])
        ),
        componentByBomRef: Object.fromEntries(
            components.map(item => [item.bomRef, item])
        ),
    };
}

/** Raw-content hash as in src/pipeline/prepare-submission.ts */
function rawSbomHash(content: string): string {
    return ethers.keccak256(ethers.toUtf8Bytes(content));
}

describe("Canonicalization: component/merkle hash (buildSBOMMerkleTree, hashSBOMComponent)", () => {
    it("array field reorder does not change componentHash (licenseIds, hashes, externalUrls, dependencies, capabilities)", () => {
        const base = component("axios", "1.14.0", {
            licenseIds: ["Apache-2.0", "MIT"],
            hashes: [
                { alg: "SHA-256", content: "aaa" },
                { alg: "SHA-1", content: "bbb" },
            ],
            externalUrls: ["https://a.example", "https://b.example"],
            dependencies: ["pkg:npm/follow-redirects@1.0.0", "pkg:npm/form-data@1.0.0"],
            capabilities: ["network", "fs"],
        });

        const reordered = component("axios", "1.14.0", {
            licenseIds: ["MIT", "Apache-2.0"],
            hashes: [
                { alg: "SHA-1", content: "bbb" },
                { alg: "SHA-256", content: "aaa" },
            ],
            externalUrls: ["https://b.example", "https://a.example"],
            dependencies: ["pkg:npm/form-data@1.0.0", "pkg:npm/follow-redirects@1.0.0"],
            capabilities: ["fs", "network"],
        });

        assert.equal(hashSBOMComponent(base), hashSBOMComponent(reordered));
    });

    it("component order in the SBOM does not change the Merkle root", () => {
        const axios = component("axios", "1.14.0");
        const lodash = component("lodash", "4.17.21");
        const chalk = component("chalk", "5.3.0");

        const first = buildSBOMMerkleTree(sbom([axios, lodash, chalk]));
        const second = buildSBOMMerkleTree(sbom([chalk, axios, lodash]));
        const third = buildSBOMMerkleTree(sbom([lodash, chalk, axios]));

        assert.equal(first.root, second.root);
        assert.equal(first.root, third.root);
    });

    it("JSON key order in the raw CycloneDX text does not change the parsed Merkle root", () => {
        // Same component and fields, keys in a different order.
        const metadataFirst = JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            metadata: { component: { type: "application", name: "demo-app", version: "1.0.0" } },
            components: [
                {
                    type: "library",
                    name: "axios",
                    version: "1.14.0",
                    purl: "pkg:npm/axios@1.14.0",
                    licenses: [{ license: { id: "MIT" } }],
                },
            ],
        });

        const shuffledKeys = JSON.stringify({
            components: [
                {
                    licenses: [{ license: { id: "MIT" } }],
                    purl: "pkg:npm/axios@1.14.0",
                    version: "1.14.0",
                    name: "axios",
                    type: "library",
                },
            ],
            specVersion: "1.6",
            metadata: { component: { version: "1.0.0", name: "demo-app", type: "application" } },
            bomFormat: "CycloneDX",
        });

        const rootA = buildSBOMMerkleTree(parseSBOMContent(metadataFirst)).root;
        const rootB = buildSBOMMerkleTree(parseSBOMContent(shuffledKeys)).root;

        assert.equal(rootA, rootB);
        // The two texts differ byte for byte.
        assert.notEqual(metadataFirst, shuffledKeys);
    });

    it("a real logic change (version bump) changes componentHash and the Merkle root", () => {
        const before = component("axios", "1.14.0");
        const after = component("axios", "1.14.1");

        assert.notEqual(hashSBOMComponent(before), hashSBOMComponent(after));

        const rootBefore = buildSBOMMerkleTree(sbom([before])).root;
        const rootAfter = buildSBOMMerkleTree(sbom([after])).root;
        assert.notEqual(rootBefore, rootAfter);
    });

    it("a real logic change (added dependency / changed license / changed hash content) changes componentHash", () => {
        const base = component("axios", "1.14.0", {
            licenseIds: ["MIT"],
            dependencies: ["pkg:npm/follow-redirects@1.0.0"],
            hashes: [{ alg: "SHA-256", content: "aaa" }],
        });

        const licenseChanged = { ...base, licenseIds: ["Apache-2.0"] };
        const dependencyAdded = {
            ...base,
            dependencies: [...base.dependencies, "pkg:npm/form-data@1.0.0"],
        };
        const hashContentChanged = {
            ...base,
            hashes: [{ alg: "SHA-256", content: "different-content" }],
        };

        const baseHash = hashSBOMComponent(base);
        assert.notEqual(baseHash, hashSBOMComponent(licenseChanged));
        assert.notEqual(baseHash, hashSBOMComponent(dependencyAdded));
        assert.notEqual(baseHash, hashSBOMComponent(hashContentChanged));
    });

    it("adding or removing a component changes the Merkle root", () => {
        const axios = component("axios", "1.14.0");
        const lodash = component("lodash", "4.17.21");

        const withTwo = buildSBOMMerkleTree(sbom([axios, lodash])).root;
        const withOne = buildSBOMMerkleTree(sbom([axios])).root;

        assert.notEqual(withTwo, withOne);
    });
});

describe("Layer 1 sbomHash is now canonicalized: stable across pure JSON key reordering", () => {
    it("sbomHash does NOT change when only JSON key order differs", () => {
        const metadataFirst = JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            metadata: { component: { type: "application", name: "demo-app", version: "1.0.0" } },
            components: [
                { type: "library", name: "axios", version: "1.14.0", purl: "pkg:npm/axios@1.14.0" },
            ],
        });

        const shuffledKeys = JSON.stringify({
            components: [
                { version: "1.14.0", name: "axios", type: "library", purl: "pkg:npm/axios@1.14.0" },
            ],
            specVersion: "1.6",
            metadata: { component: { version: "1.0.0", name: "demo-app", type: "application" } },
            bomFormat: "CycloneDX",
        });

        const rootA = buildSBOMMerkleTree(parseSBOMContent(metadataFirst)).root;
        const rootB = buildSBOMMerkleTree(parseSBOMContent(shuffledKeys)).root;
        assert.equal(rootA, rootB);

        // Layer 1: canonicalSbomDocument sorts keys before hashing
        assert.equal(
            canonicalSbomDocument(metadataFirst),
            canonicalSbomDocument(shuffledKeys)
        );
    });

    it("sbomHash does NOT change when only serialNumber or metadata.timestamp differ (independent regenerations)", () => {
        const run1 = JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            serialNumber: "urn:uuid:11111111-1111-1111-1111-111111111111",
            metadata: {
                timestamp: "2026-01-01T00:00:00.000Z",
                component: { type: "application", name: "demo-app", version: "1.0.0" },
            },
            components: [
                { type: "library", name: "axios", version: "1.14.0", purl: "pkg:npm/axios@1.14.0" },
            ],
        });

        const run2 = JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            serialNumber: "urn:uuid:22222222-2222-2222-2222-222222222222",
            metadata: {
                timestamp: "2026-06-15T12:34:56.789Z",
                component: { type: "application", name: "demo-app", version: "1.0.0" },
            },
            components: [
                { type: "library", name: "axios", version: "1.14.0", purl: "pkg:npm/axios@1.14.0" },
            ],
        });

        // Two runs of `pnpm sbom` on the same tree differ only in these fields.
        assert.equal(
            canonicalSbomDocument(run1),
            canonicalSbomDocument(run2)
        );

        // The raw texts really differ.
        assert.notEqual(run1, run2);
    });

    it("sbomHash DOES change when semantic content changes", () => {
        const v1 = JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            components: [{ type: "library", name: "axios", version: "1.14.0" }],
        });
        const v2 = JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            components: [{ type: "library", name: "axios", version: "1.15.0" }],
        });

        assert.notEqual(
            canonicalSbomDocument(v1),
            canonicalSbomDocument(v2)
        );
    });
});