// The pipeline and the API must share one Merkle implementation (@guardian/sbom-core).
// The API side is tested in apps/api/src/sbom/sbom-merkle-parity.spec.ts.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import {
    buildSBOMMerkleTree,
    createComponentProof,
    parseSBOMContent,
    verifyComponentProof,
} from "@guardian/sbom-core";

import { prepareSubmission } from "../../src/pipeline/prepare-submission.ts";

const SBOM_PATH = "test/sboms/sbom-v3-axios-1.14.0.json";
const API_SERVICE_PATH = "apps/api/src/sbom/sbom.service.ts";

describe("SBOM Merkle commitment has one implementation", () => {
    const sbomContent = readFileSync(SBOM_PATH, "utf8");

    it("anchors the root that a package proof verifies against", async () => {
        const prepared = await prepareSubmission({
            projectName: "demo-axios-service",
            packageVersion: "1.14.0",
            sbomContent,
            riskReport: {
                summary: { decision: "PASS" },
                packageReports: [{ risk: { riskScore: 1 } }],
            },
        });

        const tree = buildSBOMMerkleTree(parseSBOMContent(sbomContent));
        const proof = createComponentProof(tree, "axios");

        assert.equal(prepared.merkleRoot, tree.root);
        assert.equal(proof.root, prepared.merkleRoot);
        assert.equal(verifyComponentProof(proof), true);
    });

    it("keeps the root stable under component reordering", () => {
        const parsed = parseSBOMContent(sbomContent);
        const reversed = {
            ...parsed,
            components: [...parsed.components].reverse(),
        };

        assert.equal(
            buildSBOMMerkleTree(reversed).root,
            buildSBOMMerkleTree(parsed).root
        );
    });

    it("parses components that omit the CycloneDX type field", () => {
        const content = JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            version: 1,
            components: [{ name: "axios", version: "1.14.1" }],
        });

        const parsed = parseSBOMContent(content);

        assert.equal(parsed.components[0].type, "");
        assert.doesNotThrow(() => buildSBOMMerkleTree(parsed));
    });

    it("leaves the API with no Merkle implementation of its own", async () => {
        const source = await readFile(API_SERVICE_PATH, "utf8");

        assert.match(
            source,
            /from ['"]@guardian\/sbom-core['"]/,
            "API must take its Merkle root from the shared package"
        );
        assert.match(source, /buildSBOMMerkleTree/);

        // No second, API-local tree (pairwise keccak over concatenated nodes).
        assert.doesNotMatch(source, /keccak256\(\s*ethers\.concat/);
        assert.doesNotMatch(source, /function\s+stableStringify/);
        assert.doesNotMatch(source, /function\s+computeArtifactMerkleRoot/);
    });
});
