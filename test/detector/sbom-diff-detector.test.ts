import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { detectSBOMChanges } from "../../src/detector/sbom-diff-detector.ts";
import type {
    FlattenedSBOM,
    FlattenedSBOMComponent,
} from "@guardian/sbom-core";

function component(
    name: string,
    version: string,
    type = "library"
): FlattenedSBOMComponent {
    const key = `pkg:npm/${name}@${version}`;
    return {
        key,
        identity: name,
        bomRef: key,
        type,
        name,
        version,
        purl: key,
        licenseIds: [],
        licenseExpressions: [],
        hashes: [],
        externalUrls: [],
        dependencies: [],
        capabilities: [],
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

describe("detectSBOMChanges", () => {
    it("returns rich added, changed, and removed dependency records", () => {
        const previous = sbom([
            component("project", "1.0.0", "application"),
            component("unchanged", "1.0.0"),
            component("upgraded", "1.0.0"),
            component("removed", "1.0.0"),
        ]);
        const current = sbom([
            component("project", "2.0.0", "application"),
            component("unchanged", "1.0.0"),
            component("upgraded", "2.0.0"),
            component("added", "1.0.0"),
        ]);

        const result = detectSBOMChanges(previous, current);

        assert.deepEqual(
            result.added.map(change => ({
                name: change.packageName,
                version: change.currentVersion,
            })),
            [{ name: "added", version: "1.0.0" }]
        );
        assert.deepEqual(
            result.changed.map(change => ({
                name: change.packageName,
                previous: change.previousVersion,
                current: change.currentVersion,
            })),
            [{
                name: "upgraded",
                previous: "1.0.0",
                current: "2.0.0",
            }]
        );
        assert.deepEqual(
            result.removed.map(change => ({
                name: change.packageName,
                version: change.previousVersion,
            })),
            [{ name: "removed", version: "1.0.0" }]
        );
        assert.equal(result.added[0].type, "ADDED");
        assert.equal(result.changed[0].type, "CHANGED");
        assert.equal(result.removed[0].type, "REMOVED");
        assert.equal(result.changed[0].previousComponent?.name, "upgraded");
        assert.equal(result.changed[0].currentComponent?.name, "upgraded");
    });

    it("treats current libraries as added when no baseline exists", () => {
        const current = sbom([
            component("project", "1.0.0", "application"),
            component("lodash", "4.17.21"),
        ]);

        const result = detectSBOMChanges(undefined, current);

        assert.deepEqual(
            result.added.map(change => change.packageName),
            ["lodash"]
        );
        assert.deepEqual(result.changed, []);
        assert.deepEqual(result.removed, []);
    });
});
