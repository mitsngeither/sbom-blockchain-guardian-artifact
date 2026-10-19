import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    buildSBOMMerkleTree,
    createComponentProof,
    verifyComponentProof,
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

function sbom(
    components: FlattenedSBOMComponent[]
): FlattenedSBOM {
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

describe("SBOM Merkle tree", () => {
    it("builds a deterministic root from sorted SBOM components", () => {
        const lodash = component("lodash", "4.17.21");
        const axios = component("axios", "1.14.1");

        const first = buildSBOMMerkleTree(sbom([lodash, axios]));
        const second = buildSBOMMerkleTree(sbom([axios, lodash]));

        assert.equal(first.root, second.root);
        assert.deepEqual(
            first.leaves.map(leaf => leaf.identity),
            ["axios", "lodash"]
        );
    });

    it("creates and verifies a package proof off-chain", () => {
        const tree = buildSBOMMerkleTree(sbom([
            component("lodash", "4.17.21"),
            component("axios", "1.14.1"),
        ]));

        const proof = createComponentProof(tree, "axios");

        assert.equal(proof.leaf.identity, "axios");
        assert.equal(proof.leaf.version, "1.14.1");
        assert.equal(
            verifyComponentProof({
                root: tree.root,
                leaf: proof.leaf,
                proof: proof.proof,
            }),
            true
        );
    });

    it("rejects a proof when the package metadata changes", () => {
        const tree = buildSBOMMerkleTree(sbom([
            component("lodash", "4.17.21"),
            component("axios", "1.14.1"),
        ]));
        const proof = createComponentProof(tree, "axios");

        assert.equal(
            verifyComponentProof({
                root: tree.root,
                leaf: {
                    ...proof.leaf,
                    version: "9.9.9",
                },
                proof: proof.proof,
            }),
            false
        );
    });
});
