import { expect } from "chai";
import { network } from "hardhat";

async function expectRevert(promise: Promise<unknown>, message: string) {
    try {
        await promise;
        expect.fail("Expected transaction to revert");
    } catch (error) {
        expect(String(error)).to.include(message);
    }
}

describe("SBOMRegistry multi-signature", function () {
    async function deployFixture() {
        const { ethers } = await network.getOrCreate();
        const [owner, teamMember2, teamMember3, outsider] = await ethers.getSigners();

        const SBOMRegistry = await ethers.getContractFactory("SBOMRegistry");
        const registry = await SBOMRegistry.deploy();
        await registry.waitForDeployment();

        const teamMemberRole = await registry.TEAM_MEMBER_ROLE();
        await registry.grantRole(teamMemberRole, teamMember2.address);
        await registry.grantRole(teamMemberRole, teamMember3.address);

        const projectId = ethers.keccak256(ethers.toUtf8Bytes("demo-project"));
        const sbomHash = ethers.keccak256(ethers.toUtf8Bytes("sbom-v1"));
        const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkle-v1"));
        const artifactHash = ethers.keccak256(ethers.toUtf8Bytes("artifact-v1"));
        const propose = (version = "1.0.0", threshold = 2, from: any = owner) =>
            registry.connect(from).proposeSBOM(projectId, version, sbomHash, artifactHash, merkleRoot, 12, threshold);

        return { ethers, registry, owner, teamMember2, teamMember3, outsider, teamMemberRole, projectId, sbomHash, merkleRoot, propose };
    }

    async function increaseTime(ethers: any, seconds: number) {
        await ethers.provider.send("evm_increaseTime", [seconds]);
        await ethers.provider.send("evm_mine", []);
    }

    it("should create a proposal", async function () {
        const { registry, owner, projectId, sbomHash, merkleRoot, propose } = await deployFixture();

        await (await propose()).wait();

        const proposal = await registry.getProposal(0);
        expect(proposal.projectId).to.equal(projectId);
        expect(proposal.version).to.equal("1.0.0");
        expect(proposal.sbomHash).to.equal(sbomHash);
        expect(proposal.merkleRoot).to.equal(merkleRoot);
        expect(proposal.riskScore).to.equal(12n);
        expect(proposal.proposer).to.equal(owner.address);
        expect(proposal.threshold).to.equal(2n);
        expect(proposal.executed).to.equal(false);
        expect(proposal.cancelled).to.equal(false);
        expect(proposal.deadline > 0n).to.equal(true);
    });

    it("should approve a proposal", async function () {
        const { registry, teamMember2, propose } = await deployFixture();

        await propose();
        await (await registry.connect(teamMember2).approveSBOM(0)).wait();

        const proposal = await registry.getProposal(0);
        expect(proposal.approvalCount).to.equal(1n);
    });

    it("should reject duplicate approval", async function () {
        const { registry, teamMember2, propose } = await deployFixture();

        await propose();
        await registry.connect(teamMember2).approveSBOM(0);

        await expectRevert(registry.connect(teamMember2).approveSBOM(0), "Already approved");
    });

    it("should reject execute when approvals are not enough", async function () {
        const { registry, teamMember2, propose } = await deployFixture();

        await propose();
        await registry.connect(teamMember2).approveSBOM(0);

        await expectRevert(registry.executeProposal(0), "Not enough approvals");
    });

    it("should execute proposal when threshold is reached", async function () {
        const { registry, owner, teamMember2, teamMember3, projectId, sbomHash, merkleRoot, propose } = await deployFixture();

        await propose();
        await registry.connect(teamMember2).approveSBOM(0);
        await registry.connect(teamMember3).approveSBOM(0);
        await (await registry.executeProposal(0)).wait();

        const proposal = await registry.getProposal(0);
        const record = await registry.getVersion(projectId, "1.0.0");
        expect(proposal.executed).to.equal(true);
        expect(await registry.verifySBOM(projectId, "1.0.0", sbomHash)).to.equal(true);
        expect(record.submitter).to.equal(owner.address);
        expect(record.merkleRoot).to.equal(merkleRoot);
    });

    it("should reject non-team-member propose/approve/execute", async function () {
        const { registry, outsider, teamMember2, teamMember3, propose } = await deployFixture();

        await expectRevert(propose("1.0.0", 2, outsider), "Not a team member");

        await propose();
        await expectRevert(registry.connect(outsider).approveSBOM(0), "Not a team member");

        await registry.connect(teamMember2).approveSBOM(0);
        await registry.connect(teamMember3).approveSBOM(0);
        await expectRevert(registry.connect(outsider).executeProposal(0), "Not a team member");
    });

    it("should reject executing the same proposal twice", async function () {
        const { registry, teamMember2, teamMember3, propose } = await deployFixture();

        await propose();
        await registry.connect(teamMember2).approveSBOM(0);
        await registry.connect(teamMember3).approveSBOM(0);
        await registry.executeProposal(0);

        await expectRevert(registry.executeProposal(0), "Proposal already executed");
    });

    it("should reject a threshold below the admin-set minimum", async function () {
        const { registry, propose } = await deployFixture();

        expect(await registry.minApprovals()).to.equal(2n);
        await expectRevert(propose("1.0.0", 1), "Threshold below minimum");
    });

    it("should reject the proposer approving its own proposal", async function () {
        const { registry, propose } = await deployFixture();

        await propose();
        await expectRevert(registry.approveSBOM(0), "Proposer cannot approve");
    });

    it("should let an approver withdraw its approval before execution", async function () {
        const { registry, teamMember2, teamMember3, propose } = await deployFixture();

        await propose();
        await registry.connect(teamMember2).approveSBOM(0);
        await registry.connect(teamMember3).approveSBOM(0);
        await (await registry.connect(teamMember3).revokeApproval(0)).wait();

        expect((await registry.getProposal(0)).approvalCount).to.equal(1n);
        await expectRevert(registry.executeProposal(0), "Not enough approvals");
        await expectRevert(registry.connect(teamMember3).revokeApproval(0), "Not approved");
    });

    it("should let only the proposer or an admin cancel, and block a cancelled proposal", async function () {
        const { registry, teamMember2, teamMember3, propose } = await deployFixture();

        await propose("1.0.0", 2, teamMember2);
        await expectRevert(registry.connect(teamMember3).cancelProposal(0), "Not proposer or admin");
        await (await registry.connect(teamMember2).cancelProposal(0)).wait();

        expect((await registry.getProposal(0)).cancelled).to.equal(true);
        await expectRevert(registry.connect(teamMember3).approveSBOM(0), "Proposal cancelled");
        await expectRevert(registry.executeProposal(0), "Proposal cancelled");

        await propose("1.0.1", 2, teamMember2);
        await (await registry.cancelProposal(1)).wait(); // owner holds DEFAULT_ADMIN_ROLE
        expect((await registry.getProposal(1)).cancelled).to.equal(true);
    });

    it("should reject approving or executing an expired proposal", async function () {
        const { ethers, registry, teamMember2, teamMember3, propose } = await deployFixture();
        const ttl = Number(await registry.proposalTtl());

        await propose("1.0.0");
        await registry.connect(teamMember2).approveSBOM(0);
        await increaseTime(ethers, ttl + 1);
        await expectRevert(registry.connect(teamMember3).approveSBOM(0), "Proposal expired");

        await propose("1.0.1");
        await registry.connect(teamMember2).approveSBOM(1);
        await registry.connect(teamMember3).approveSBOM(1);
        await increaseTime(ethers, ttl + 1);
        await expectRevert(registry.executeProposal(1), "Proposal expired");
    });

    it("should not count approvers or proposers whose role was revoked", async function () {
        const { registry, teamMember2, teamMember3, teamMemberRole, propose } = await deployFixture();

        await propose("1.0.0");
        await registry.connect(teamMember2).approveSBOM(0);
        await registry.connect(teamMember3).approveSBOM(0);
        await registry.revokeRole(teamMemberRole, teamMember3.address);
        await expectRevert(registry.executeProposal(0), "Not enough approvals");

        await registry.grantRole(teamMemberRole, teamMember3.address);
        await propose("1.0.1", 2, teamMember2);
        await registry.approveSBOM(1);
        await registry.connect(teamMember3).approveSBOM(1);
        await registry.revokeRole(teamMemberRole, teamMember2.address);
        await expectRevert(registry.executeProposal(1), "Proposer is not a team member");
    });

    it("should apply a raised minimum to open proposals and restrict the setters to the admin", async function () {
        const { registry, teamMember2, teamMember3, propose } = await deployFixture();

        await propose();
        await registry.connect(teamMember2).approveSBOM(0);
        await registry.connect(teamMember3).approveSBOM(0);
        await registry.setMinApprovals(3);
        await expectRevert(registry.executeProposal(0), "Not enough approvals");

        await expectRevert(registry.setMinApprovals(0), "Invalid minimum");
        await expectRevert(registry.setProposalTtl(0), "Invalid TTL");
        await expect(registry.connect(teamMember2).setMinApprovals(1))
            .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
        await expect(registry.connect(teamMember2).setProposalTtl(1))
            .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });
});
