import { expect } from "chai";
import pkg from "hardhat";
let { network, ethers } = pkg;

describe("SBOMRegistry", function () {
  let connection;

  let registry;
  let admin, submitter, revoker, user;

  let projectId;
  let unknownProjectId;
  const version1 = "1.0.0";
  const version2 = "1.1.0";
  const version3 = "2.0.0";

  let sbomHash1;
  let sbomHash2;
  let sbomHash3;
  let merkleRoot1;
  let merkleRoot2;
  let merkleRoot3;
  let artifactHash1;
  let artifactHash2;
  let artifactHash3;

  const riskScore1 = 42;
  const riskScore2 = 88;
  const riskScore3 = 15;

  beforeEach(async function () {
    connection = await network.create();
    ethers = connection.ethers;

    [admin, submitter, revoker, user] = await ethers.getSigners();

    sbomHash1 = ethers.keccak256(ethers.toUtf8Bytes("sbom-v1"));
    sbomHash2 = ethers.keccak256(ethers.toUtf8Bytes("sbom-v2"));
    sbomHash3 = ethers.keccak256(ethers.toUtf8Bytes("sbom-v3"));
    merkleRoot1 = ethers.keccak256(ethers.toUtf8Bytes("merkle-v1"));
    merkleRoot2 = ethers.keccak256(ethers.toUtf8Bytes("merkle-v2"));
    merkleRoot3 = ethers.keccak256(ethers.toUtf8Bytes("merkle-v3"));
    artifactHash1 = ethers.keccak256(ethers.toUtf8Bytes("artifact-v1"));
    artifactHash2 = ethers.keccak256(ethers.toUtf8Bytes("artifact-v2"));
    artifactHash3 = ethers.keccak256(ethers.toUtf8Bytes("artifact-v3"));

    projectId = ethers.keccak256(ethers.toUtf8Bytes("proj-1"));
    unknownProjectId = ethers.keccak256(ethers.toUtf8Bytes("unknown-proj"));

    const RegistryFactory = await ethers.getContractFactory("SBOMRegistry");
    registry = await RegistryFactory.deploy();
    await registry.waitForDeployment();

    const SUBMITTER_ROLE = await registry.SUBMITTER_ROLE();
    const REVOKER_ROLE = await registry.REVOKER_ROLE();

    await registry.grantRole(SUBMITTER_ROLE, submitter.address);
    await registry.grantRole(REVOKER_ROLE, revoker.address);
  });

  describe("constructor and roles", function () {
    it("should grant initial roles to admin", async function () {
      const DEFAULT_ADMIN_ROLE = await registry.DEFAULT_ADMIN_ROLE();
      const SUBMITTER_ROLE = await registry.SUBMITTER_ROLE();
      const REVOKER_ROLE = await registry.REVOKER_ROLE();

      expect(await registry.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.equal(true);
      expect(await registry.hasRole(SUBMITTER_ROLE, admin.address)).to.equal(true);
      expect(await registry.hasRole(REVOKER_ROLE, admin.address)).to.equal(true);
    });

    it("should allow admin to grant roles", async function () {
      const SUBMITTER_ROLE = await registry.SUBMITTER_ROLE();

      expect(await registry.hasRole(SUBMITTER_ROLE, user.address)).to.equal(false);
      await registry.grantRole(SUBMITTER_ROLE, user.address);
      expect(await registry.hasRole(SUBMITTER_ROLE, user.address)).to.equal(true);
    });
  });

  describe("registerSBOM", function () {
    it("should register SBOM successfully and emit event", async function () {
      await expect(
        registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1)
      )
        .to.emit(registry, "SBOMRegistered")
        .withArgs(projectId, version1, sbomHash1, submitter.address);

      const record = await registry.getVersion(projectId, version1);

      expect(record.sbomHash).to.equal(sbomHash1);
      expect(record.merkleRoot).to.equal(merkleRoot1);
      expect(record.submitter).to.equal(submitter.address);
      expect(record.timestamp).to.be.gt(0n);
      expect(record.riskScore).to.equal(riskScore1);
      expect(record.status).to.equal(1n);
    });

    it("should revert if non-submitter registers", async function () {
      const SUBMITTER_ROLE = await registry.SUBMITTER_ROLE();

      await expect(
        registry.connect(user).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1)
      )
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(user.address, SUBMITTER_ROLE);
    });

    it("should revert on duplicate SBOM version for the same project", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);

      await expect(
        registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1)
      ).to.be.revertedWith("SBOM already exists");
    });

    it("should allow same version string for different projectIds", async function () {
      const projA = ethers.keccak256(ethers.toUtf8Bytes("proj-A"));
      const projB = ethers.keccak256(ethers.toUtf8Bytes("proj-B"));

      await registry.connect(submitter).registerSBOM(projA, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);
      await registry.connect(submitter).registerSBOM(projB, version1, sbomHash2, artifactHash2, merkleRoot2, riskScore2);

      const recordA = await registry.getVersion(projA, version1);
      const recordB = await registry.getVersion(projB, version1);

      expect(recordA.sbomHash).to.equal(sbomHash1);
      expect(recordB.sbomHash).to.equal(sbomHash2);
    });

    it("should update latest version after each successful registration", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);
      let latest = await registry.getLatest(projectId);
      expect(latest.sbomHash).to.equal(sbomHash1);
      expect(latest.riskScore).to.equal(riskScore1);

      await registry.connect(submitter).registerSBOM(projectId, version2, sbomHash2, artifactHash2, merkleRoot2, riskScore2);
      latest = await registry.getLatest(projectId);
      expect(latest.sbomHash).to.equal(sbomHash2);
      expect(latest.riskScore).to.equal(riskScore2);
    });

    it("should append versions to history in order", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);
      await registry.connect(submitter).registerSBOM(projectId, version2, sbomHash2, artifactHash2, merkleRoot2, riskScore2);
      await registry.connect(submitter).registerSBOM(projectId, version3, sbomHash3, artifactHash3, merkleRoot3, riskScore3);

      const versions = await registry.getHistory(projectId);

      expect(versions.length).to.equal(3);
      expect(versions[0]).to.equal(version1);
      expect(versions[1]).to.equal(version2);
      expect(versions[2]).to.equal(version3);
    });
  });

  describe("submitBatch", function () {
    function buildBatch(count, project = projectId) {
      return Array.from({ length: count }, (_, index) => {
        const version = `batch-${index}`;
        return {
          projectId: project,
          version,
          sbomHash: ethers.keccak256(ethers.toUtf8Bytes(`batch-sbom-${index}`)),
          artifactHash: ethers.keccak256(ethers.toUtf8Bytes(`batch-artifact-${index}`)),
          merkleRoot: ethers.keccak256(ethers.toUtf8Bytes(`batch-merkle-${index}`)),
          riskScore: riskScore1 + index,
        };
      });
    }

    it("should submit multiple SBOM records in one transaction", async function () {
      const submissions = buildBatch(3);

      await expect(registry.connect(submitter).submitBatch(submissions))
        .to.emit(registry, "SBOMRegistered")
        .withArgs(projectId, submissions[0].version, submissions[0].sbomHash, submitter.address)
        .and.to.emit(registry, "SBOMRegistered")
        .withArgs(projectId, submissions[1].version, submissions[1].sbomHash, submitter.address)
        .and.to.emit(registry, "SBOMRegistered")
        .withArgs(projectId, submissions[2].version, submissions[2].sbomHash, submitter.address);

      const versions = await registry.getHistory(projectId);
      expect(versions).to.deep.equal(submissions.map((submission) => submission.version));

      const latest = await registry.getLatest(projectId);
      expect(latest.sbomHash).to.equal(submissions[2].sbomHash);

      for (const submission of submissions) {
        const record = await registry.getVersion(projectId, submission.version);
        expect(record.sbomHash).to.equal(submission.sbomHash);
        expect(record.merkleRoot).to.equal(submission.merkleRoot);
        expect(record.submitter).to.equal(submitter.address);
        expect(record.riskScore).to.equal(submission.riskScore);
      }
    });

    it("should revert if non-submitter submits a batch", async function () {
      const SUBMITTER_ROLE = await registry.SUBMITTER_ROLE();

      await expect(registry.connect(user).submitBatch(buildBatch(1)))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(user.address, SUBMITTER_ROLE);
    });

    it("should revert an empty batch", async function () {
      await expect(registry.connect(submitter).submitBatch([])).to.be.revertedWith(
        "Empty batch"
      );
    });

    it("should revert if batch is too large", async function () {
      await expect(registry.connect(submitter).submitBatch(buildBatch(51))).to.be.revertedWith(
        "Batch too large"
      );
    });

    it("should revert the whole batch if any version already exists", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);

      const submissions = [
        {
          projectId,
          version: version2,
          sbomHash: sbomHash2,
          artifactHash: artifactHash2,
          merkleRoot: merkleRoot2,
          riskScore: riskScore2,
        },
        {
          projectId,
          version: version1,
          sbomHash: sbomHash1,
          artifactHash: artifactHash1,
          merkleRoot: merkleRoot1,
          riskScore: riskScore1,
        },
      ];

      await expect(registry.connect(submitter).submitBatch(submissions)).to.be.revertedWith(
        "SBOM already exists"
      );

      const record = await registry.getVersion(projectId, version2);
      expect(record.status).to.equal(0n);
    });
  });

  describe("submitWithSignature", function () {
    const submissionTypes = {
      SBOMSubmission: [
        { name: "projectId", type: "bytes32" },
        { name: "version", type: "string" },
        { name: "sbomHash", type: "bytes32" },
        { name: "artifactHash", type: "bytes32" },
        { name: "merkleRoot", type: "bytes32" },
        { name: "riskScore", type: "uint32" },
        { name: "nonce", type: "uint256" },
      ],
    };

    async function buildDomain() {
      const networkInfo = await ethers.provider.getNetwork();

      return {
        name: "MyDApp",
        version: "1",
        chainId: Number(networkInfo.chainId),
        verifyingContract: await registry.getAddress(),
      };
    }

    it("should accept a valid off-chain signature from an authorized submitter", async function () {
      const nonce = await registry.nonces(submitter.address);
      const submission = {
        projectId,
        version: version1,
        sbomHash: sbomHash1,
        artifactHash: artifactHash1,
        merkleRoot: merkleRoot1,
        riskScore: riskScore1,
        nonce,
      };

      const signature = await submitter.signTypedData(
        await buildDomain(),
        submissionTypes,
        submission
      );

      expect(await registry.recoverSubmissionSigner(submission, signature)).to.equal(
        submitter.address
      );

      await expect(registry.submitWithSignature(submission, signature))
        .to.emit(registry, "SBOMRegistered")
        .withArgs(projectId, version1, sbomHash1, submitter.address);

      const record = await registry.getVersion(projectId, version1);
      expect(record.submitter).to.equal(submitter.address);
      expect(record.sbomHash).to.equal(sbomHash1);
      expect(record.merkleRoot).to.equal(merkleRoot1);
      expect(record.riskScore).to.equal(riskScore1);
    });

    it("should reject a signature from an unauthorized signer", async function () {
      const submission = {
        projectId,
        version: version1,
        sbomHash: sbomHash1,
        artifactHash: artifactHash1,
        merkleRoot: merkleRoot1,
        riskScore: riskScore1,
        nonce: await registry.nonces(user.address),
      };

      const signature = await user.signTypedData(
        await buildDomain(),
        submissionTypes,
        submission
      );

      await expect(registry.submitWithSignature(submission, signature)).to.be.revertedWith(
        "Not authorized"
      );
    });

    it("should reject replaying the same signed payload", async function () {
      const nonce = await registry.nonces(submitter.address);
      const submission = {
        projectId,
        version: version1,
        sbomHash: sbomHash1,
        artifactHash: artifactHash1,
        merkleRoot: merkleRoot1,
        riskScore: riskScore1,
        nonce,
      };

      const signature = await submitter.signTypedData(
        await buildDomain(),
        submissionTypes,
        submission
      );

      await registry.submitWithSignature(submission, signature);

      await expect(registry.submitWithSignature(submission, signature)).to.be.revertedWith(
        "Invalid nonce"
      );
    });

    it("should reject a signature whose nonce does not match the signer's on-chain nonce", async function () {
      // No earlier submission: a valid signature with nonce+1, so only the
      // nonce check can reject it.
      const currentNonce = await registry.nonces(submitter.address);
      const submission = {
        projectId,
        version: version1,
        sbomHash: sbomHash1,
        artifactHash: artifactHash1,
        merkleRoot: merkleRoot1,
        riskScore: riskScore1,
        nonce: currentNonce + 1n,
      };

      const signature = await submitter.signTypedData(
        await buildDomain(),
        submissionTypes,
        submission
      );

      expect(await registry.recoverSubmissionSigner(submission, signature)).to.equal(
        submitter.address
      );

      await expect(registry.submitWithSignature(submission, signature)).to.be.revertedWith(
        "Invalid nonce"
      );
    });

    it("should reject signatures produced under a mismatched EIP-712 domain", async function () {
      // A wrong domain recovers a different address, which lacks SUBMITTER_ROLE.
      // Each of the four domain fields is changed in turn.
      const goodDomain = await buildDomain();
      const submission = {
        projectId,
        version: version1,
        sbomHash: sbomHash1,
        artifactHash: artifactHash1,
        merkleRoot: merkleRoot1,
        riskScore: riskScore1,
        nonce: await registry.nonces(submitter.address),
      };

      const tamperedDomains = [
        { ...goodDomain, name: "EvilDApp" },
        { ...goodDomain, version: "2" },
        { ...goodDomain, chainId: goodDomain.chainId + 1 },
        { ...goodDomain, verifyingContract: user.address },
      ];

      for (const domain of tamperedDomains) {
        const signature = await submitter.signTypedData(
          domain,
          submissionTypes,
          submission
        );

        expect(await registry.recoverSubmissionSigner(submission, signature)).to.not.equal(
          submitter.address
        );

        await expect(registry.submitWithSignature(submission, signature)).to.be.revertedWith(
          "Not authorized"
        );
      }
    });

    it("should accept a valid batch of off-chain signatures", async function () {
      const baseNonce = await registry.nonces(submitter.address);
      const submissions = [version1, version2].map((version, index) => ({
        projectId,
        version,
        sbomHash: index === 0 ? sbomHash1 : sbomHash2,
        artifactHash: index === 0 ? artifactHash1 : artifactHash2,
        merkleRoot: index === 0 ? merkleRoot1 : merkleRoot2,
        riskScore: index === 0 ? riskScore1 : riskScore2,
        nonce: baseNonce + BigInt(index),
      }));
      const signatures = [];

      for (const submission of submissions) {
        signatures.push(
          await submitter.signTypedData(await buildDomain(), submissionTypes, submission)
        );
      }

      await expect(registry.submitBatchWithSignatures(submissions, signatures))
        .to.emit(registry, "SBOMRegistered")
        .withArgs(projectId, version1, sbomHash1, submitter.address)
        .and.to.emit(registry, "SBOMRegistered")
        .withArgs(projectId, version2, sbomHash2, submitter.address);

      expect(await registry.nonces(submitter.address)).to.equal(baseNonce + 2n);
      expect(await registry.verifySBOM(projectId, version1, sbomHash1)).to.equal(true);
      expect(await registry.verifySBOM(projectId, version2, sbomHash2)).to.equal(true);
    });

    it("should reject an empty signed batch", async function () {
      await expect(registry.submitBatchWithSignatures([], [])).to.be.revertedWith(
        "Empty batch"
      );
    });

    it("should reject signed batch length mismatch", async function () {
      const submission = {
        projectId,
        version: version1,
        sbomHash: sbomHash1,
        artifactHash: artifactHash1,
        merkleRoot: merkleRoot1,
        riskScore: riskScore1,
        nonce: await registry.nonces(submitter.address),
      };

      await expect(registry.submitBatchWithSignatures([submission], [])).to.be.revertedWith(
        "Length mismatch"
      );
    });
  });

  describe("verifySBOM", function () {
    it("should return true for correct hash of an active SBOM", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);

      expect(await registry.verifySBOM(projectId, version1, sbomHash1)).to.equal(true);
    });

    it("should return false for wrong hash", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);

      expect(await registry.verifySBOM(projectId, version1, sbomHash2)).to.equal(false);
    });

    it("should return false for non-existing project/version", async function () {
      expect(await registry.verifySBOM(unknownProjectId, version1, sbomHash1)).to.equal(false);
      expect(await registry.verifySBOM(projectId, version1, sbomHash1)).to.equal(false);
    });

    it("should return false after a version is revoked", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);
      await registry.connect(revoker).revokeVersion(projectId, version1, "security issue");

      expect(await registry.verifySBOM(projectId, version1, sbomHash1)).to.equal(false);
    });
  });

  describe("getters", function () {
    it("should return zero-value record for unknown version", async function () {
      const record = await registry.getVersion(unknownProjectId, version1);

      expect(record.sbomHash).to.equal(ethers.ZeroHash);
      expect(record.merkleRoot).to.equal(ethers.ZeroHash);
      expect(record.submitter).to.equal(ethers.ZeroAddress);
      expect(record.timestamp).to.equal(0n);
      expect(record.riskScore).to.equal(0);
      expect(record.status).to.equal(0n);
    });

    it("should return empty history for unknown project", async function () {
      const versions = await registry.getHistory(unknownProjectId);
      expect(versions.length).to.equal(0);
    });

    it("should return zero-value latest record for unknown project", async function () {
      const latest = await registry.getLatest(unknownProjectId);

      expect(latest.sbomHash).to.equal(ethers.ZeroHash);
      expect(latest.merkleRoot).to.equal(ethers.ZeroHash);
      expect(latest.submitter).to.equal(ethers.ZeroAddress);
      expect(latest.timestamp).to.equal(0n);
      expect(latest.riskScore).to.equal(0);
      expect(latest.status).to.equal(0n);
    });
  });

  describe("revokeVersion", function () {
    it("should revoke an active SBOM and emit event", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);

      await expect(
        registry.connect(revoker).revokeVersion(projectId, version1, "security issue")
      )
        .to.emit(registry, "SBOMRevoked")
        .withArgs(projectId, version1, "security issue", revoker.address);

      const record = await registry.getVersion(projectId, version1);
      expect(record.status).to.equal(2n);
    });

    it("should revert if non-revoker tries to revoke", async function () {
      const REVOKER_ROLE = await registry.REVOKER_ROLE();
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);

      await expect(
        registry.connect(user).revokeVersion(projectId, version1, "bad actor")
      )
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(user.address, REVOKER_ROLE);
    });

    it("should revert when revoking non-active SBOM", async function () {
      await expect(
        registry.connect(revoker).revokeVersion(projectId, version1, "not found")
      ).to.be.revertedWith("SBOM is not active");
    });

    it("should revert when revoking an already revoked SBOM", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);
      await registry.connect(revoker).revokeVersion(projectId, version1, "first revoke");

      await expect(
        registry.connect(revoker).revokeVersion(projectId, version1, "second revoke")
      ).to.be.revertedWith("SBOM is not active");
    });

    it("should not change latestVersion pointer after revoke", async function () {
      await registry.connect(submitter).registerSBOM(projectId, version1, sbomHash1, artifactHash1, merkleRoot1, riskScore1);
      await registry.connect(submitter).registerSBOM(projectId, version2, sbomHash2, artifactHash2, merkleRoot2, riskScore2);

      await registry.connect(revoker).revokeVersion(projectId, version2, "security issue");

      const latest = await registry.getLatest(projectId);
      expect(latest.sbomHash).to.equal(sbomHash2);
      expect(latest.status).to.equal(2n);
    });
  });
});
