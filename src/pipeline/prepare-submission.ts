import { ethers } from "ethers";

import type { PolicyDecision } from "../detector/detector-pipeline.ts";
import { buildSBOMMerkleTree, canonicalSbomDocument } from "@guardian/sbom-core";
import { parseSBOMContent, computeArtifactHash } from "@guardian/sbom-core";

const UINT32_MAX = 2 ** 32 - 1;
const SHORT_SHA_LENGTH = 7;

// A package that was actually analyzed scores at least 1 (S, O, D >= 1), so a
// riskScore of 0 means no packages were analyzed. Read analyzedPackages with it.
export const NO_PACKAGES_ANALYZED_SCORE = 0;

export interface SubmissionRiskReport {
    summary: {
        decision: PolicyDecision;
    };
    packageReports: Array<{
        risk: {
            riskScore: number;
        };
    }>;
}

export interface PrepareSubmissionInput {
    projectName: string;
    packageVersion: string;
    sbomContent: string;
    riskReport: SubmissionRiskReport;
    commitSha?: string;
    submissionVersion?: string;
    runId?: string;
    /** Recording path label (e.g. "eip712") appended to a derived version. */
    versionTag?: string;
}

export interface PreparedSubmission {
    projectId: string;
    submissionVersion: string;
    sbomHash: string;
    merkleRoot: string;
    riskScore: number;
    /** 0 means `riskScore` is the NO_PACKAGES_ANALYZED_SCORE sentinel. */
    analyzedPackages: number;
    artifactHash: string;
    npmIntegrity?: string;
    integrityMatches?: boolean;
}

function requireValue(value: string, label: string): string {
    const normalized = value.trim();

    if (!normalized) {
        throw new Error(`${label} is required`);
    }

    return normalized;
}

function highestRiskScore(report: SubmissionRiskReport): number {
    for (const packageReport of report.packageReports) {
        const score = packageReport.risk.riskScore;

        if (
            !Number.isSafeInteger(score) ||
            score < 0 ||
            score > UINT32_MAX
        ) {
            throw new Error("Risk score must be a uint32 integer");
        }
    }

    const score = report.packageReports.reduce(
        (highest, packageReport) => Math.max(
            highest,
            packageReport.risk.riskScore
        ),
        0
    );

    return score;
}

function resolveSubmissionVersion(
    packageVersion: string,
    submissionVersion: string | undefined,
    commitSha: string | undefined,
    runId: string | undefined,
    versionTag: string | undefined
): string {
    if (submissionVersion?.trim()) {
        return submissionVersion.trim();
    }

    let derived = packageVersion;

    if (commitSha?.trim()) {
        const shortSha = commitSha.trim().slice(0, SHORT_SHA_LENGTH);
        // Versions cannot be recorded twice, so the run id keeps a re-dispatch
        // of an already-recorded commit from reverting.
        derived = runId?.trim()
            ? `${packageVersion}+${shortSha}.${runId.trim()}`
            : `${packageVersion}+${shortSha}`;
    }

    // Two recording paths in one run share commit and run id; the tag tells them apart.
    if (versionTag?.trim()) {
        derived += (derived.includes("+") ? "." : "+") + versionTag.trim();
    }

    return derived;
}

export async function prepareSubmission(
    input: PrepareSubmissionInput
): Promise<PreparedSubmission> {
    if (input.riskReport.summary.decision !== "PASS") {
        throw new Error(
            "Refusing blockchain submission because policy " +
            `decision is ${input.riskReport.summary.decision}`
        );
    }

    const projectName = requireValue(
        input.projectName,
        "Project name"
    );

    const packageVersion = requireValue(
        input.packageVersion,
        "Package version"
    );

    let artifactHash = "";
    let npmIntegrity: string | undefined;
    let integrityMatches: boolean | undefined;

    try {
        const result = await computeArtifactHash(projectName, packageVersion);
        artifactHash = result.artifactHash;
        npmIntegrity = result.npmIntegrity;
        integrityMatches = result.integrityMatches;
    } catch {
        // not on npm or network error: skip
    }

    // false: npm's declared integrity does not match the tarball it served, so refuse.
    // undefined (not on npm, or no sha512) is unverifiable and still allowed.
    if (integrityMatches === false) {
        throw new Error(
            "Refusing blockchain submission because artifact integrity " +
            `does not match npm registry metadata for ${projectName}@${packageVersion}`
        );
    }


    if (input.sbomContent.length === 0) {
        throw new Error("SBOM content is required");
    }

    const flattenedSbom = parseSBOMContent(input.sbomContent);
    const canonical = canonicalSbomDocument(input.sbomContent);

    return {
        projectId: ethers.keccak256(
            ethers.toUtf8Bytes(projectName)
        ),
        submissionVersion: resolveSubmissionVersion(
            packageVersion,
            input.submissionVersion,
            input.commitSha,
            input.runId,
            input.versionTag
        ),
        sbomHash: ethers.keccak256(
            ethers.toUtf8Bytes(canonical)
        ),
        merkleRoot: buildSBOMMerkleTree(flattenedSbom).root,
        riskScore: highestRiskScore(input.riskReport),
        analyzedPackages: input.riskReport.packageReports.length,
        artifactHash,
        npmIntegrity,
        integrityMatches
    };
}
