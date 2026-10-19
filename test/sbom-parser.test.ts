import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseRawSBOM } from "@guardian/sbom-core";

describe("parseRawSBOM", () => {
    it("normalizes components while preserving bom-ref graph lookups", async () => {
        const sbom = await parseRawSBOM("test/sboms/sbom-v3-axios-1.14.1.json");

        const root = sbom.componentMap["pkg:npm/demo-v1-clean@1.0.0"];
        const lodash = sbom.componentMap["pkg:npm/lodash@4.17.21"];

        assert.ok(root);
        assert.ok(lodash);
        assert.equal(root.bomRef, "demo-v1-clean@1.0.0");
        assert.equal(lodash.bomRef, "demo-v1-clean@1.0.0|lodash@4.17.21");
        assert.deepEqual(root.dependencies, ["pkg:npm/lodash@4.17.21"]);
        assert.equal(sbom.componentByBomRef["demo-v1-clean@1.0.0"], root);
        assert.equal(sbom.componentByBomRef["demo-v1-clean@1.0.0|lodash@4.17.21"], lodash);
        assert.deepEqual(lodash.licenseIds, ["MIT"]);
        assert.deepEqual(lodash.hashes, [
            {
                alg: "SHA-512",
                content: "bf690311ee7b95e713ba568322e3533f2dd1cb880b189e99d4edef13592b81764daec43e2c54c61d5c558dc5cfb35ecb85b65519e74026ff17675b6f8f916f4a",
            },
        ]);
    });
});
