import type { LifecycleScriptsCheckResult } from "./lifescycle-script-detector.ts";
import {
    generateRiskReport,
    type RiskRating,
    type RiskReport,
    type RiskScorerOptions,
} from "./risk-scorer.ts";
import {
    detectSBOMChanges,
    type PackageChange,
    type PackageChangeType,
    type SBOMChangeReport,
} from "./sbom-diff-detector.ts";
import type {
    FlattenedSBOM,
    FlattenedSBOMComponent,
} from "@guardian/sbom-core";

export type AnalysisMode = "incremental" | "full";
export type PolicyDecision = "PASS" | "REVIEW" | "BLOCK";
export type PackageAnalysisChangeType =
    | PackageChangeType
    | "UNCHANGED";

export interface PipelinePolicy {
    decisionByRating: Record<RiskRating, PolicyDecision>;
    mandatoryBlockPatternIds: readonly string[];
}

export interface PipelinePolicyOverrides {
    decisionByRating?: Partial<
        Record<RiskRating, PolicyDecision>
    >;
    mandatoryBlockPatternIds?: readonly string[];
}

export interface PackagePipelineReport {
    changeType: PackageAnalysisChangeType;
    change?: PackageChange;
    risk: RiskReport;
}

export interface SkippedPackageReport {
    packageName: string;
    version: string;
    changeType: PackageAnalysisChangeType;
    reason: string;
}

export interface PipelineSummary {
    overallRating: RiskRating;
    decision: PolicyDecision;
    highestRiskPackages: string[];
    counts: Record<RiskRating, number>;
    analyzedPackages: number;
    skippedPackages: number;
    reasons: string[];
}

export interface PipelineReport {
    projectId: string;
    previousVersion?: string;
    currentVersion: string;
    mode: AnalysisMode;
    diff: SBOMChangeReport;
    packageReports: PackagePipelineReport[];
    skippedPackageReports: SkippedPackageReport[];
    summary: PipelineSummary;
}

export interface DetectorPipelineInput {
    projectId: string;
    previousVersion?: string;
    currentVersion: string;
    mode?: AnalysisMode;
    previousSbom?: FlattenedSBOM;
    currentSbom: FlattenedSBOM;
    riskScorerOptions?: RiskScorerOptions;
    policy?: PipelinePolicyOverrides;
}

export const DEFAULT_PIPELINE_POLICY: PipelinePolicy = {
    decisionByRating: {
        LOW: "PASS",
        MEDIUM: "REVIEW",
        HIGH: "REVIEW",
        CRITICAL: "BLOCK",
    },
    mandatoryBlockPatternIds: [
        "remote-script-pipe-to-shell",
    ],
};

const RATINGS: readonly RiskRating[] = [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
];

function resolvePolicy(
    overrides: PipelinePolicyOverrides | undefined
): PipelinePolicy {
    return {
        decisionByRating: {
            ...DEFAULT_PIPELINE_POLICY.decisionByRating,
            ...overrides?.decisionByRating,
        },
        mandatoryBlockPatternIds:
            overrides?.mandatoryBlockPatternIds ??
            DEFAULT_PIPELINE_POLICY.mandatoryBlockPatternIds,
    };
}

function currentLibraries(
    sbom: FlattenedSBOM
): FlattenedSBOMComponent[] {
    return sbom.components
        .filter(component => component.type === "library")
        .sort((first, second) =>
            first.identity.localeCompare(second.identity)
        );
}

function previousPackageNames(
    sbom: FlattenedSBOM | undefined
): string[] {
    if (!sbom) {
        return [];
    }

    return currentLibraries(sbom).map(component =>
        component.identity
    );
}

function changeByPackageName(
    diff: SBOMChangeReport
): Map<string, PackageChange> {
    return new Map(
        [...diff.added, ...diff.changed].map(change => [
            change.packageName,
            change,
        ])
    );
}

function selectTargets(
    currentSbom: FlattenedSBOM,
    diff: SBOMChangeReport,
    mode: AnalysisMode
): Array<{
    component: FlattenedSBOMComponent;
    changeType: PackageAnalysisChangeType;
    change?: PackageChange;
}> {
    if (mode === "incremental") {
        return [...diff.added, ...diff.changed].map(change => ({
            component: change.currentComponent!,
            changeType: change.type,
            change,
        }));
    }

    const changes = changeByPackageName(diff);
    return currentLibraries(currentSbom).map(component => {
        const change = changes.get(component.identity);
        return {
            component,
            changeType: change?.type ?? "UNCHANGED",
            change,
        };
    });
}

function mandatoryPatternIds(
    risk: RiskReport,
    policy: PipelinePolicy
): string[] {
    const lifecycleEvidence = risk.evidence.find(
        evidence => evidence.detector === "lifecycle-script"
    );

    if (!lifecycleEvidence) {
        return [];
    }

    const lifecycle =
        lifecycleEvidence.details as LifecycleScriptsCheckResult;
    const matchedPatterns = Object.values(lifecycle.scripts)
        .flatMap(script => script.matchedPatterns);

    return [...new Set(matchedPatterns)].filter(pattern =>
        policy.mandatoryBlockPatternIds.includes(pattern)
    );
}

function annotateMandatoryBlock(
    risk: RiskReport,
    patternIds: string[]
): RiskReport {
    if (patternIds.length === 0) {
        return risk;
    }

    const policyReason =
        "Mandatory block lifecycle pattern: " +
        patternIds.join(", ");

    return {
        ...risk,
        evidence: risk.evidence.map(evidence =>
            evidence.detector === "lifecycle-script"
                ? {
                    ...evidence,
                    mandatoryBlock: true,
                    policyReason,
                }
                : evidence
        ),
    };
}

function errorMessage(error: unknown): string {
    if (error instanceof Error) {
        const causeMessage = error.cause
            ? errorMessage(error.cause)
            : "";

        return causeMessage
            ? `${error.message}: ${causeMessage}`
            : error.message;
    }

    return String(error);
}

function isMissingRegistryPackage(error: unknown): boolean {
    const message = errorMessage(error);

    // Unknown package or unpublished version: no registry metadata, skip it.
    return message.includes("Package not found:") ||
        message.includes("Version not found:");
}

function countRatings(
    reports: PackagePipelineReport[]
): Record<RiskRating, number> {
    const counts: Record<RiskRating, number> = {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0,
    };

    for (const report of reports) {
        counts[report.risk.rating]++;
    }

    return counts;
}

function highestRating(
    reports: PackagePipelineReport[]
): RiskRating {
    let highest: RiskRating = "LOW";

    for (const report of reports) {
        if (
            RATINGS.indexOf(report.risk.rating) >
            RATINGS.indexOf(highest)
        ) {
            highest = report.risk.rating;
        }
    }

    return highest;
}

export async function runDetectorPipeline(
    input: DetectorPipelineInput
): Promise<PipelineReport> {
    if (!input.projectId.trim()) {
        throw new Error("Project ID is required");
    }

    if (!input.currentVersion.trim()) {
        throw new Error("Current project version is required");
    }

    const reasons: string[] = [];
    const mode: AnalysisMode = input.previousSbom
        ? input.mode ?? "incremental"
        : "full";

    if (!input.previousSbom) {
        reasons.push(
            "No previous SBOM was provided; using full analysis mode."
        );
    }

    const diff = detectSBOMChanges(
        input.previousSbom,
        input.currentSbom
    );
    const policy = resolvePolicy(input.policy);
    const targets = selectTargets(
        input.currentSbom,
        diff,
        mode
    );
    const oldPackageNames = previousPackageNames(
        input.previousSbom
    );
    const packageReports: PackagePipelineReport[] = [];
    const skippedPackageReports: SkippedPackageReport[] = [];
    let hasMandatoryBlock = false;

    for (const target of targets) {
        const packageName = target.component.identity.trim();
        const version = target.component.version.trim();

        if (!packageName || !version || version === "N/A") {
            throw new Error(
                "Cannot analyze component without package name " +
                "and version: " + target.component.key
            );
        }

        try {
            const rawRisk = await generateRiskReport(
                packageName,
                version,
                {
                    ...input.riskScorerOptions,
                    previousPackageNames: oldPackageNames,
                }
            );
            const patternIds = mandatoryPatternIds(
                rawRisk,
                policy
            );
            const risk = annotateMandatoryBlock(
                rawRisk,
                patternIds
            );

            if (patternIds.length > 0) {
                hasMandatoryBlock = true;
                reasons.push(
                    packageName + ": mandatory block for " +
                    patternIds.join(", ")
                );
            }

            packageReports.push({
                changeType: target.changeType,
                change: target.change,
                risk,
            });
        } catch (error) {
            if (isMissingRegistryPackage(error)) {
                const reason =
                    "Skipped because npm registry metadata is unavailable. " +
                    "The dependency may come from Git, a local path, or " +
                    "another unsupported source.";

                skippedPackageReports.push({
                    packageName,
                    version,
                    changeType: target.changeType,
                    reason,
                });

                reasons.push(
                    packageName + "@" + version + ": " + reason
                );

                continue;
            }

            throw new Error(
                "Detector pipeline failed for " +
                packageName + "@" + version,
                { cause: error }
            );
        }
    }

    const counts = countRatings(packageReports);
    const overallRating = highestRating(packageReports);
    const highestRiskPackages = packageReports
        .filter(report =>
            report.risk.rating === overallRating
        )
        .map(report => report.risk.packageName)
        .sort();
    const ratingDecision = policy.decisionByRating[overallRating];
    const unresolvedRaisesDecision =
        skippedPackageReports.length > 0 &&
        ratingDecision === "PASS";
    const decision = hasMandatoryBlock
        ? "BLOCK"
        : unresolvedRaisesDecision
            ? "REVIEW"
            : ratingDecision;

    reasons.push(
        "Overall rating " + overallRating +
        " maps to policy decision " + ratingDecision + "."
    );

    if (unresolvedRaisesDecision) {
        reasons.push(
            "Unresolved package metadata raises the minimum " +
            "policy decision from PASS to REVIEW."
        );
    }

    return {
        projectId: input.projectId,
        previousVersion: input.previousVersion,
        currentVersion: input.currentVersion,
        mode,
        diff,
        packageReports,
        skippedPackageReports,
        summary: {
            overallRating,
            decision,
            counts,
            highestRiskPackages:
                packageReports.length === 0
                    ? []
                    : highestRiskPackages,
            analyzedPackages: packageReports.length,
            skippedPackages:
                input.currentSbom.components.length -
                packageReports.length,
            reasons,
        },
    };
}
