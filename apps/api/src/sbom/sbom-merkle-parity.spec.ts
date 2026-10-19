// The API and the submission pipeline must compute the same Merkle root for the
// same SBOM. Both use @guardian/sbom-core; these tests call it directly.
import {
  buildSBOMMerkleTree,
  createComponentProof,
  parseSBOMContent,
  verifyComponentProof,
} from '@guardian/sbom-core';

import { artifactMerkleRoot } from './sbom.service';

const ZERO_HASH =
  '0x0000000000000000000000000000000000000000000000000000000000000000';

function sbom(components: unknown[]): string {
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    components,
  });
}

describe('Merkle root parity with the submission pipeline', () => {
  const content = sbom([
    { type: 'library', name: 'axios', version: '1.14.0', purl: 'pkg:npm/axios@1.14.0' },
    { type: 'library', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
  ]);

  it('computes the exact root the pipeline would anchor on-chain', () => {
    const pipelineRoot = buildSBOMMerkleTree(parseSBOMContent(content)).root;

    expect(artifactMerkleRoot(content)).toBe(pipelineRoot);
  });

  it('produces a root that a package membership proof verifies against', () => {
    const tree = buildSBOMMerkleTree(parseSBOMContent(content));
    const proof = createComponentProof(tree, 'axios');

    expect(proof.root).toBe(artifactMerkleRoot(content));
    expect(verifyComponentProof(proof)).toBe(true);
  });

  it('is stable under component reordering but changes with a version bump', () => {
    const reordered = sbom([
      { type: 'library', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
      { type: 'library', name: 'axios', version: '1.14.0', purl: 'pkg:npm/axios@1.14.0' },
    ]);
    const bumped = content.replace(/1\.14\.0/g, '1.14.2');

    expect(artifactMerkleRoot(reordered)).toBe(artifactMerkleRoot(content));
    expect(artifactMerkleRoot(bumped)).not.toBe(artifactMerkleRoot(content));
  });

  it('tolerates components that omit the CycloneDX "type" field', () => {
    // Real SBOMs often omit `type`; the parser fills it in.
    expect(() => artifactMerkleRoot(sbom([{ name: 'axios', version: '1.14.1' }]))).not.toThrow();
  });

  it('returns the zero hash for an SBOM with no components', () => {
    expect(artifactMerkleRoot(sbom([]))).toBe(ZERO_HASH);
  });
});
