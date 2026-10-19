import type { CooldownResult } from "../detector/cooldown-checker.ts";
import type { PipelineReport } from "../detector/detector-pipeline.ts";

type PolicyEnv = Record<string, string | undefined>;

function isInCooldown(
    packageReport: PipelineReport["packageReports"][number]
): boolean {
    const cooldownEvidence = packageReport.risk.evidence.find(
        evidence => evidence.detector === "cooldown"
    );

    if (!cooldownEvidence) {
        return false;
    }

    return (cooldownEvidence.details as CooldownResult).isInCooldown;
}

/**
 * A new or changed package version still inside the cooldown window is not
 * submitted automatically.
 *
 * Incremental runs only look at ADDED/CHANGED packages. A full scan has no
 * way to tell new from already recorded, so it is lenient unless
 * COOLDOWN_STRICT_WITHOUT_BASELINE=true (set by the workflow for a dispatch
 * without a baseline). BLOCK_FRESH_DEPENDENCIES=false turns the rule off.
 */
function freshDependencyReason(
    report: PipelineReport,
    env: PolicyEnv
): string | undefined {
    if (env.BLOCK_FRESH_DEPENDENCIES === "false") {
        return undefined;
    }

    if (report.mode === "incremental") {
        const fresh = report.packageReports.some(packageReport =>
            (packageReport.changeType === "ADDED" ||
                packageReport.changeType === "CHANGED") &&
            isInCooldown(packageReport)
        );

        return fresh
            ? "A newly added or changed dependency is inside " +
            "the configured cooldown window."
            : undefined;
    }

    if (env.COOLDOWN_STRICT_WITHOUT_BASELINE !== "true") {
        return undefined;
    }

    return report.packageReports.some(isInCooldown)
        ? "No recorded baseline to diff against, so any dependency " +
        "inside the configured cooldown window blocks automatic recording."
        : undefined;
}

export function applyWorkflowPolicy(
    report: PipelineReport,
    env: PolicyEnv = process.env
): PipelineReport {
    const additionalReason = freshDependencyReason(report, env);

    if (!additionalReason) {
        return report;
    }

    return {
        ...report,
        summary: {
            ...report.summary,
            decision: "BLOCK",
            reasons: [
                ...report.summary.reasons,
                additionalReason,
            ],
        },
    };
}
