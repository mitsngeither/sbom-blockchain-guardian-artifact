import { expect } from "chai";
import { network } from "hardhat";
import {
    parseRawSBOM,
    buildSBOMMerkleTree,
    createComponentProof,
} from "@guardian/sbom-core";

// Real SBOM fixture (axios and its transitive dependencies).
const FIXTURE = "test/sboms/sbom-v3-axios-1.14.0.json";

describe("SBOMRegistry.verifyComponent", function () {
    // Deploy, build the Merkle tree from the fixture, anchor its root.
    async function deployAndRegister() {
        const { ethers } = await network.getOrCreate();

        const SBOMRegistry = await ethers.getContractFactory("SBOMRegistry");
        const registry = await SBOMRegistry.deploy();
        await registry.waitForDeployment();

        // Off chain: parse the SBOM and build the StandardMerkleTree.
        const sbom = await parseRawSBOM(FIXTURE);
        const tree = buildSBOMMerkleTree(sbom);

        const projectId = ethers.keccak256(
            ethers.toUtf8Bytes("verify-component-demo")
        );
        const version = "1.0.0";
        const sbomHash = ethers.keccak256(ethers.toUtf8Bytes("sbom-bytes"));
        const artifactHash = ethers.keccak256(ethers.toUtf8Bytes("artifact-bytes"));
        const riskScore = 1;

        // On chain: anchor that same root.
        await registry.registerSBOM(
            projectId,
            version,
            sbomHash,
            artifactHash,
            tree.root,
            riskScore
        );

        return { ethers, registry, tree, projectId, version };
    }

    it("accepts a component that is in the anchored SBOM", async function () {
        const { registry, tree, projectId, version } = await deployAndRegister();

        // Proof for a real component, selected by its key.
        const selector = tree.leaves[0].key;
        const { leaf, proof } = createComponentProof(tree, selector);

        // leaf.value = [key, identity, version, type, componentHash], the same
        // order as the ComponentLeaf struct, so it can be passed as-is.
        const ok = await registry.verifyComponent(
            projectId,
            version,
            leaf.value,
            proof
        );

        expect(ok).to.equal(true);
    });

    it("rejects a tampered leaf (changed version)", async function () {
        const { registry, tree, projectId, version } = await deployAndRegister();

        const selector = tree.leaves[0].key;
        const { leaf, proof } = createComponentProof(tree, selector);
        const [key, identity, , componentType, componentHash] = leaf.value;

        // Different version -> different leaf -> root does not match.
        const tampered = [key, identity, "99.99.99", componentType, componentHash];

        const ok = await registry.verifyComponent(
            projectId,
            version,
            tampered,
            proof
        );

        expect(ok).to.equal(false);
    });

    it("rejects when the record does not exist or is not Active", async function () {
        const { ethers, registry, tree } = await deployAndRegister();

        const selector = tree.leaves[0].key;
        const { leaf, proof } = createComponentProof(tree, selector);

        // projectId never registered -> status is None.
        const unknownProject = ethers.keccak256(
            ethers.toUtf8Bytes("project-that-does-not-exist")
        );

        const ok = await registry.verifyComponent(
            unknownProject,
            "1.0.0",
            leaf.value,
            proof
        );

        expect(ok).to.equal(false);
    });
});
