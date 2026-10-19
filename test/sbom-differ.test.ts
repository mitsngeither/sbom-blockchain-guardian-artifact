import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { compareSBOMs } from "@guardian/sbom-core";
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

describe("compareSBOMs", () => {
    it("classifies a version bump as a changed component", () => {
        const previous = sbom([component("axios", "1.0.0")]);
        const current = sbom([component("axios", "2.0.0")]);

        const diff = compareSBOMs(previous, current);

        assert.deepEqual(diff.added, []);
        assert.deepEqual(diff.removed, []);
        assert.deepEqual(diff.changed, [{
            key: "pkg:npm/axios",
            changes: {
                version: { old: "1.0.0", new: "2.0.0" },
            },
        }]);
    });

    it("classifies added, removed, and field-level changes", () => {
        const previous = sbom([
            component("root", "1.0.0", {
                licenseIds: ["MIT"],
                hashes: [{ alg: "SHA-256", content: "old" }],
                dependencies: ["pkg:npm/lodash@4.17.20"],
            }),
            component("left-pad"),
        ]);
        const current = sbom([
            component("root", "1.0.0", {
                licenseIds: ["Apache-2.0"],
                hashes: [{ alg: "SHA-256", content: "new" }],
                dependencies: ["pkg:npm/lodash@4.17.21"],
            }),
            component("lodash"),
        ]);

        const diff = compareSBOMs(previous, current);

        assert.deepEqual(diff.added, ["pkg:npm/lodash"]);
        assert.deepEqual(diff.removed, ["pkg:npm/left-pad"]);
        assert.deepEqual(diff.changed, [{
            key: "pkg:npm/root",
            changes: {
                licenseIds: {
                    old: ["MIT"],
                    new: ["Apache-2.0"],
                },
                hashes: {
                    old: [{ alg: "SHA-256", content: "old" }],
                    new: [{ alg: "SHA-256", content: "new" }],
                },
                dependencies: {
                    old: ["pkg:npm/lodash@4.17.20"],
                    new: ["pkg:npm/lodash@4.17.21"],
                },
            },
        }]);
    });
});
