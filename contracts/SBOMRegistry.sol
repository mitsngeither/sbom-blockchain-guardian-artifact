// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    MerkleProof
} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract SBOMRegistry is EIP712("MyDApp", "1"), AccessControl {
    uint256 private constant MAX_BATCH_SIZE = 50;

    bytes32 public constant SUBMITTER_ROLE = keccak256("SUBMITTER_ROLE");
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");
    bytes32 public constant TEAM_MEMBER_ROLE = keccak256("TEAM_MEMBER_ROLE"); //gán role = hash của chuỗi quyền => duy nhất k sợ trùng
    bytes32 public constant SBOM_SUBMISSION_TYPEHASH =
        keccak256(
            "SBOMSubmission(bytes32 projectId,string version,bytes32 sbomHash,bytes32 artifactHash,bytes32 merkleRoot,uint32 riskScore,uint256 nonce)"
        );

    enum Status {
        None,
        Active,
        Revoked
    }

    struct SBOMRecord {
        bytes32 sbomHash;
        bytes32 artifactHash;
        bytes32 merkleRoot;
        address submitter;
        uint48 timestamp;
        uint32 riskScore;
        Status status;
    }

    struct SBOMSubmission {
        bytes32 projectId;
        string version;
        bytes32 sbomHash;
        bytes32 artifactHash;
        bytes32 merkleRoot;
        uint32 riskScore;
        uint256 nonce;
    }

    struct SBOMBatchItem {
        bytes32 projectId;
        string version;
        bytes32 sbomHash;
        bytes32 artifactHash;
        bytes32 merkleRoot;
        uint32 riskScore;
    }

    struct ComponentLeaf {
        string key;
        string identity;
        string version; // version của component (khác recordVersion)
        string componentType;
        bytes32 componentHash;
    }

    mapping(bytes32 => mapping(string => SBOMRecord)) private records;
    mapping(bytes32 => string) private latestVersion;
    mapping(bytes32 => string[]) private history;
    mapping(address => uint256) public nonces;

    event SBOMRegistered(
        bytes32 indexed projectId,
        string version,
        bytes32 sbomHash,
        address indexed submitter
    );

    event SBOMRevoked(
        bytes32 indexed projectId,
        string version,
        string reason,
        address indexed revokedBy
    );

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SUBMITTER_ROLE, msg.sender);
        _grantRole(REVOKER_ROLE, msg.sender);
        _grantRole(TEAM_MEMBER_ROLE, msg.sender);
    }

    function registerSBOM(
        bytes32 projectId,
        string calldata version,
        bytes32 sbomHash,
        bytes32 artifactHash,
        bytes32 merkleRoot,
        uint32 riskScore
    ) external onlyRole(SUBMITTER_ROLE) {
        _commitSBOM(
            projectId,
            version,
            sbomHash,
            artifactHash,
            merkleRoot,
            riskScore,
            msg.sender
        );
    }

    function submitBatch(
        SBOMBatchItem[] calldata submissions
    ) external onlyRole(SUBMITTER_ROLE) {
        uint256 length = submissions.length;
        require(length > 0, "Empty batch");
        require(length <= MAX_BATCH_SIZE, "Batch too large");

        for (uint256 i = 0; i < length; ) {
            SBOMBatchItem calldata submission = submissions[i];
            _commitSBOM(
                submission.projectId,
                submission.version,
                submission.sbomHash,
                submission.artifactHash,
                submission.merkleRoot,
                submission.riskScore,
                msg.sender
            );

            unchecked {
                ++i;
            }
        }
    }

    function submitWithSignature(
        SBOMSubmission calldata data,
        bytes calldata signature
    ) external {
        address signer = recoverSubmissionSigner(data, signature);
        require(hasRole(SUBMITTER_ROLE, signer), "Not authorized");
        require(data.nonce == nonces[signer], "Invalid nonce");

        _commitSBOM(
            data.projectId,
            data.version,
            data.sbomHash,
            data.artifactHash,
            data.merkleRoot,
            data.riskScore,
            signer
        );

        nonces[signer]++;
    }

    function submitBatchWithSignatures(
        SBOMSubmission[] calldata submissions,
        bytes[] calldata signatures
    ) external {
        uint256 length = submissions.length;
        require(length == signatures.length, "Length mismatch");
        require(length > 0, "Empty batch");
        require(length <= MAX_BATCH_SIZE, "Batch too large");

        for (uint256 i = 0; i < length; ) {
            address signer = recoverSubmissionSigner(
                submissions[i],
                signatures[i]
            );

            require(hasRole(SUBMITTER_ROLE, signer), "Not authorized");
            require(submissions[i].nonce == nonces[signer], "Invalid nonce");

            _commitSBOM(
                submissions[i].projectId,
                submissions[i].version,
                submissions[i].sbomHash,
                submissions[i].artifactHash,
                submissions[i].merkleRoot,
                submissions[i].riskScore,
                signer
            );

            unchecked {
                ++nonces[signer];
                ++i;
            }
        }
    }

    function recoverSubmissionSigner(
        SBOMSubmission calldata data,
        bytes calldata signature
    ) public view returns (address) {
        return
            ECDSA.recover(_hashTypedDataV4(_hashSubmission(data)), signature);
    }

    function _hashSubmission(
        SBOMSubmission calldata data
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    SBOM_SUBMISSION_TYPEHASH,
                    data.projectId,
                    keccak256(bytes(data.version)),
                    data.sbomHash,
                    data.artifactHash,
                    data.merkleRoot,
                    data.riskScore,
                    data.nonce
                )
            );
    }

    function verifySBOM(
        bytes32 projectId,
        string calldata version,
        bytes32 sbomHash
    ) external view returns (bool) {
        SBOMRecord storage record = records[projectId][version];
        return record.status == Status.Active && record.sbomHash == sbomHash;
    }

    function verifyComponent(
        bytes32 projectId,
        string calldata recordVersion, //ver của bản ghi SBOM
        ComponentLeaf calldata component,
        bytes32[] calldata proof
    ) external view returns (bool) {
        SBOMRecord storage record = records[projectId][recordVersion];
        if (record.status != Status.Active) {
            return false; // bản ghi không tồn tại hoặc đã revoke → không verify
        }

        bytes32 leaf = keccak256(
            bytes.concat(
                keccak256(
                    abi.encode(
                        component.key,
                        component.identity,
                        component.version,
                        component.componentType,
                        component.componentHash
                    )
                )
            )
        );

        return MerkleProof.verify(proof, record.merkleRoot, leaf);
    }

    function getLatest(
        bytes32 projectId
    ) external view returns (SBOMRecord memory) {
        string memory version = latestVersion[projectId];
        return records[projectId][version];
    }

    function getHistory(
        bytes32 projectId
    ) external view returns (string[] memory) {
        return history[projectId];
    }

    function getVersion(
        bytes32 projectId,
        string calldata version
    ) external view returns (SBOMRecord memory) {
        return records[projectId][version];
    }

    function revokeVersion(
        bytes32 projectId,
        string calldata version,
        string calldata reason
    ) external onlyRole(REVOKER_ROLE) {
        require(
            records[projectId][version].status == Status.Active,
            "SBOM is not active"
        );

        records[projectId][version].status = Status.Revoked;

        emit SBOMRevoked(projectId, version, reason, msg.sender);
    }

    struct Proposal {
        bytes32 projectId;
        string version;
        bytes32 sbomHash;
        bytes32 artifactHash;
        bytes32 merkleRoot;
        uint256 threshold;
        address proposer;
        uint32 riskScore;
        uint32 approvalCount;
        bool executed;
        bool cancelled;
        uint48 deadline;
    }

    uint256 public minApprovals = 2;
    uint256 public proposalTtl = 7 days;

    uint256 private nextProposalId;
    mapping(uint256 => Proposal) private proposals;
    mapping(uint256 => mapping(address => bool)) private hasApproved;
    mapping(uint256 => address[]) private approvers;

    event ProposalCreated(
        uint256 indexed proposalId,
        bytes32 indexed projectId,
        string version,
        bytes32 sbomHash,
        bytes32 merkleRoot,
        uint32 riskScore,
        address indexed proposer,
        uint256 threshold
    );

    event ProposalApproved(
        uint256 indexed proposalId,
        address indexed approver,
        uint256 approvalCount,
        uint256 threshold
    );

    event ApprovalRevoked(
        uint256 indexed proposalId,
        address indexed approver,
        uint256 approvalCount
    );

    event ProposalCancelled(uint256 indexed proposalId, address indexed cancelledBy);

    event ProposalExecuted(
        uint256 indexed proposalId,
        bytes32 indexed projectId,
        string version,
        bytes32 sbomHash,
        bytes32 merkleRoot
    );

    event MinApprovalsUpdated(uint256 minApprovals);
    event ProposalTtlUpdated(uint256 proposalTtl);

    modifier onlyTeamMember() {
        require(hasRole(TEAM_MEMBER_ROLE, msg.sender), "Not a team member");
        _;
    }
    function _commitSBOM(
        bytes32 projectId,
        string memory version,
        bytes32 sbomHash,
        bytes32 artifactHash,
        bytes32 merkleRoot,
        uint32 riskScore,
        address submitter
    ) internal {
        require(
            records[projectId][version].status == Status.None,
            "SBOM already exists"
        );

        records[projectId][version] = SBOMRecord({
            sbomHash: sbomHash,
            artifactHash: artifactHash,
            merkleRoot: merkleRoot,
            submitter: submitter,
            timestamp: uint48(block.timestamp),
            riskScore: riskScore,
            status: Status.Active
        });

        latestVersion[projectId] = version;
        history[projectId].push(version);

        emit SBOMRegistered(projectId, version, sbomHash, submitter);
    }

    function setMinApprovals(uint256 newMinimum) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMinimum > 0, "Invalid minimum");
        minApprovals = newMinimum;
        emit MinApprovalsUpdated(newMinimum);
    }

    function setProposalTtl(uint256 newTtl) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newTtl > 0, "Invalid TTL");
        proposalTtl = newTtl;
        emit ProposalTtlUpdated(newTtl);
    }

    function proposeSBOM(
        bytes32 projectId,
        string calldata version,
        bytes32 sbomHash,
        bytes32 artifactHash,
        bytes32 merkleRoot,
        uint32 riskScore,
        uint256 threshold
    ) external onlyTeamMember returns (uint256) {
        require(threshold >= minApprovals, "Threshold below minimum");
        require(
            records[projectId][version].status == Status.None,
            "SBOM already exists"
        );

        uint256 proposalId = nextProposalId;
        nextProposalId++;

        Proposal storage proposal = proposals[proposalId];
        proposal.projectId = projectId;
        proposal.version = version;
        proposal.sbomHash = sbomHash;
        proposal.artifactHash = artifactHash;
        proposal.merkleRoot = merkleRoot;
        proposal.threshold = threshold;
        proposal.proposer = msg.sender;
        proposal.riskScore = riskScore;
        proposal.deadline = uint48(block.timestamp + proposalTtl);

        emit ProposalCreated(
            proposalId,
            projectId,
            version,
            sbomHash,
            merkleRoot,
            riskScore,
            msg.sender,
            threshold
        );

        return proposalId;
    }

    function _requireOpen(Proposal storage proposal) private view {
        require(proposal.threshold > 0, "Proposal does not exist");
        require(!proposal.executed, "Proposal already executed");
        require(!proposal.cancelled, "Proposal cancelled");
        require(block.timestamp <= proposal.deadline, "Proposal expired");
    }

    function approveSBOM(uint256 proposalId) external onlyTeamMember {
        Proposal storage proposal = proposals[proposalId];
        _requireOpen(proposal);
        require(msg.sender != proposal.proposer, "Proposer cannot approve");
        require(!hasApproved[proposalId][msg.sender], "Already approved");

        hasApproved[proposalId][msg.sender] = true;
        approvers[proposalId].push(msg.sender);
        proposal.approvalCount++;

        emit ProposalApproved(
            proposalId,
            msg.sender,
            proposal.approvalCount,
            proposal.threshold
        );
    }

    function revokeApproval(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.threshold > 0, "Proposal does not exist");
        require(!proposal.executed, "Proposal already executed");
        require(hasApproved[proposalId][msg.sender], "Not approved");

        hasApproved[proposalId][msg.sender] = false;
        address[] storage list = approvers[proposalId];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == msg.sender) {
                list[i] = list[list.length - 1];
                list.pop();
                break;
            }
        }
        proposal.approvalCount--;

        emit ApprovalRevoked(proposalId, msg.sender, proposal.approvalCount);
    }

    function cancelProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.threshold > 0, "Proposal does not exist");
        require(!proposal.executed, "Proposal already executed");
        require(!proposal.cancelled, "Proposal cancelled");
        require(
            msg.sender == proposal.proposer ||
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not proposer or admin"
        );

        proposal.cancelled = true;

        emit ProposalCancelled(proposalId, msg.sender);
    }

    function executeProposal(uint256 proposalId) external onlyTeamMember {
        Proposal storage proposal = proposals[proposalId];
        _requireOpen(proposal);
        require(
            hasRole(TEAM_MEMBER_ROLE, proposal.proposer),
            "Proposer is not a team member"
        );

        // Recount at execute time: approvals from members whose role was revoked no longer count.
        uint256 required = proposal.threshold > minApprovals
            ? proposal.threshold
            : minApprovals;
        uint256 valid = 0;
        address[] storage list = approvers[proposalId];
        for (uint256 i = 0; i < list.length; i++) {
            if (hasRole(TEAM_MEMBER_ROLE, list[i])) {
                valid++;
            }
        }
        require(valid >= required, "Not enough approvals");

        proposal.executed = true;

        _commitSBOM(
            proposal.projectId,
            proposal.version,
            proposal.sbomHash,
            proposal.artifactHash,
            proposal.merkleRoot,
            proposal.riskScore,
            proposal.proposer
        );

        emit ProposalExecuted(
            proposalId,
            proposal.projectId,
            proposal.version,
            proposal.sbomHash,
            proposal.merkleRoot
        );
    }

    function getProposal(
        uint256 proposalId
    ) external view returns (Proposal memory) {
        return proposals[proposalId];
    }
}
