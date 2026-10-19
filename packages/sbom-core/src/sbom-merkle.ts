import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import { ethers } from "ethers";

import type {
    FlattenedSBOM,
    FlattenedSBOMComponent,
    SBOMHash,
} from "./types";

export const SBOM_MERKLE_LEAF_ENCODING = [
    "string",
    "string",
    "string",
    "string",
    "bytes32",
] as const;

export type SBOMMerkleLeafValue = [
    key: string,
    identity: string,
    version: string,
    componentType: string,
    componentHash: string,
];

export interface SBOMMerkleLeaf {
    key: string;
    identity: string;
    name: string;
    version: string;
    type: string;
    purl?: string;
    componentHash: string;
    value: SBOMMerkleLeafValue;
}

export interface SBOMMerkleTree {
    root: string;
    leaves: SBOMMerkleLeaf[];
    tree: StandardMerkleTree<SBOMMerkleLeafValue>;
}

export interface SBOMComponentProof {
    root: string;
    leaf: SBOMMerkleLeaf;
    proof: string[];
}

function sortStrings(values: readonly string[]): string[] {
    return [...values].sort();
}

function sortHashes(hashes: readonly SBOMHash[]): SBOMHash[] {
    return [...hashes].sort((first, second) =>
        `${first.alg}:${first.content}`.localeCompare(
            `${second.alg}:${second.content}`
        )
    );
}

function canonicalComponent(
    component: FlattenedSBOMComponent
): Record<string, unknown> {
    return {
        key: component.key,
        identity: component.identity,
        bomRef: component.bomRef,
        type: component.type,
        name: component.name,
        group: component.group ?? null,
        version: component.version,
        purl: component.purl ?? null,
        licenseIds: sortStrings(component.licenseIds),
        licenseExpressions: sortStrings(component.licenseExpressions),
        hashes: sortHashes(component.hashes),
        externalUrls: sortStrings(component.externalUrls),
        dependencies: sortStrings(component.dependencies),
        capabilities: sortStrings(component.capabilities),
    };
}

export function stableStringify(value: unknown): string {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
        return `[${value.map(stableStringify).join(",")}]`;
    }

    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
        .sort()
        .map(key => `${JSON.stringify(key)}:${stableStringify(object[key])}`)
        .join(",")}}`;
}

export function hashSBOMComponent(
    component: FlattenedSBOMComponent
): string {
    return ethers.keccak256(
        ethers.toUtf8Bytes(stableStringify(canonicalComponent(component)))
    );
}

export function componentToMerkleLeaf(
    component: FlattenedSBOMComponent
): SBOMMerkleLeaf {
    const componentHash = hashSBOMComponent(component);

    return {
        key: component.key,
        identity: component.identity,
        name: component.name,
        version: component.version,
        type: component.type,
        purl: component.purl,
        componentHash,
        value: [
            component.key,
            component.identity,
            component.version,
            component.type,
            componentHash,
        ],
    };
}

export function buildSBOMMerkleTree(
    sbom: FlattenedSBOM
): SBOMMerkleTree {
    if (sbom.components.length === 0) {
        throw new Error("Cannot build a Merkle tree from an empty SBOM");
    }

    const leaves = [...sbom.components]
        .sort((first, second) => first.key.localeCompare(second.key))
        .map(componentToMerkleLeaf);
    const tree = StandardMerkleTree.of(
        leaves.map(leaf => leaf.value),
        [...SBOM_MERKLE_LEAF_ENCODING]
    );

    return {
        root: tree.root,
        leaves,
        tree,
    };
}

// serialNumber and metadata.timestamp change on every generation run, so they
// are dropped before hashing.
export function canonicalSbomDocument(sbomJson: string): string {
    const parsed = JSON.parse(sbomJson) as Record<string, unknown>;
    delete parsed.serialNumber;

    const metadata = parsed.metadata;
    if (metadata && typeof metadata === "object" && !Array.isArray(metadata)) {
        delete (metadata as Record<string, unknown>).timestamp;
    }

    return stableStringify(parsed);
}

function findLeafIndex(
    merkleTree: SBOMMerkleTree,
    packageSelector: string
): number {
    const normalized = packageSelector.trim();

    if (!normalized) {
        throw new Error("Package selector is required");
    }

    const exactKeyIndex = merkleTree.leaves.findIndex(
        leaf => leaf.key === normalized
    );

    if (exactKeyIndex >= 0) {
        return exactKeyIndex;
    }

    const matches = merkleTree.leaves
        .map((leaf, index) => ({ leaf, index }))
        .filter(({ leaf }) =>
            leaf.identity === normalized ||
            leaf.name === normalized ||
            leaf.purl === normalized
        );

    if (matches.length === 0) {
        throw new Error(`Package not found in SBOM Merkle tree: ${normalized}`);
    }

    if (matches.length > 1) {
        throw new Error(
            "Package selector is ambiguous; use the exact component key: " +
            matches.map(match => match.leaf.key).join(", ")
        );
    }

    return matches[0].index;
}

export function createComponentProof(
    merkleTree: SBOMMerkleTree,
    packageSelector: string
): SBOMComponentProof {
    const leafIndex = findLeafIndex(merkleTree, packageSelector);
    const leaf = merkleTree.leaves[leafIndex];

    return {
        root: merkleTree.root,
        leaf,
        proof: merkleTree.tree.getProof(leafIndex),
    };
}

export function verifyComponentProof(
    proof: SBOMComponentProof
): boolean {
    const leafValue: SBOMMerkleLeafValue = [
        proof.leaf.key,
        proof.leaf.identity,
        proof.leaf.version,
        proof.leaf.type,
        proof.leaf.componentHash,
    ];

    return StandardMerkleTree.verify(
        proof.root,
        [...SBOM_MERKLE_LEAF_ENCODING],
        leafValue,
        proof.proof
    );
}
