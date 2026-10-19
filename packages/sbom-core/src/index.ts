export type {
    CycloneDXComponent,
    CycloneDXDependency,
    CycloneDXSBOM,
    ExternalReference,
    FlattenedSBOM,
    FlattenedSBOMComponent,
    SBOMHash,
    SBOMLicense,
} from "./types";

export type { ComponentChanges, Differ } from "./differ-type";

export { parseRawSBOM, parseSBOMContent } from "./sbom-parser";
export { compareSBOMs } from "./sbom-differ";
export { mappingComponents, sameHashArray, sameStringArray } from "./sbom-utils";
export { computeArtifactHash } from "./artifact-hash";
export {
    SBOM_MERKLE_LEAF_ENCODING,
    buildSBOMMerkleTree,
    canonicalSbomDocument,
    componentToMerkleLeaf,
    createComponentProof,
    hashSBOMComponent,
    stableStringify,
    verifyComponentProof,
} from "./sbom-merkle";

export type {
    SBOMComponentProof,
    SBOMMerkleLeaf,
    SBOMMerkleLeafValue,
    SBOMMerkleTree,
} from "./sbom-merkle";
