/*
 * FMEA-inspired package risk scoring.
 *
 * Detector results are mapped to Severity / Occurrence / Detection on a
 * 1..5 scale. The report keeps both the score breakdown and the raw detector
 * evidence so every rating can be explained.
 */

import {
    checkCooldown,
    type CooldownResult,
} from "./cooldown-checker.ts";
import {
    checkLifecycleScripts,
    type LifecycleScriptsCheckResult,
} from "./lifescycle-script-detector.ts";
import {
    scoreCooldownResult,
    scoreLifecycleResult,
    scoreTyposquatResult,
} from "./risk-scoring-policy.ts";
import {
    checkPackageTyposquatting,
    type TypoCheckResult,
} from "./typosquat-checker.ts";

export interface RiskComponents {
    severity: number;
    occurrence: number;
    detection: number;
}

export type RiskRating =
    | "LOW"
    | "MEDIUM"
    | "HIGH"
    | "CRITICAL";

export interface RiskEvidence {
    detector: "lifecycle-script" | "cooldown" | "typosquat";
    summary: string;
    scores: Partial<RiskComponents>;
    mandatoryBlock?: boolean;
    policyReason?: string;
    details:
        | LifecycleScriptsCheckResult
        | CooldownResult
        | TypoCheckResult;
}

export interface RiskBreakdown extends RiskComponents {
    rawRpn: number;
    normalizedScore: number;
}

export interface RiskReport {
    packageName: string;
    version: string;
    breakdown: RiskBreakdown;
    riskScore: number;
    rating: RiskRating;
    evidence: RiskEvidence[];
}

export interface RiskScorerDependencies {
    checkLifecycleScripts(
        packageName: string,
        version: string
    ): Promise<LifecycleScriptsCheckResult>;
    checkCooldown(
        packageName: string,
        version: string
    ): Promise<CooldownResult>;
    checkPackageTyposquatting(
        packageName: string,
        previousPackageNames: readonly string[],
        popularPackageNames?: readonly string[]
    ): TypoCheckResult;
}

export interface RiskScorerOptions {
    previousPackageNames?: readonly string[];
    popularPackageNames?: readonly string[];
    dependencies?: Partial<RiskScorerDependencies>;
}

const DEFAULT_DEPENDENCIES: RiskScorerDependencies = {
    checkLifecycleScripts,
    checkCooldown,
    checkPackageTyposquatting,
};

function clampScore(value: number): number {
    return Math.min(5, Math.max(1, value));
}

function normalizeRpn(rpn: number): number {
    return Math.round((rpn * 100) / 125);
}

function describeLifecycle(
    result: LifecycleScriptsCheckResult
): string {
    if (result.hasSuspiciousScripts) {
        const scriptNames = Object.values(result.scripts)
            .filter(script => script.suspicious)
            .map(script => script.scriptName);

        return (
            "Suspicious npm lifecycle script detected: " +
            scriptNames.join(", ")
        );
    }

    if (result.hasLifecycleScripts) {
        return "Lifecycle script present without a suspicious pattern";
    }

    return "No npm lifecycle scripts detected";
}

function describeCooldown(result: CooldownResult): string {
    if (!result.isInCooldown) {
        return (
            "Package version is outside the " +
            `${result.cooldownDays}-day cooldown window`
        );
    }

    return (
        "Package version is " +
        `${result.ageDays.toFixed(2)} days old`
    );
}

function describeTyposquat(result: TypoCheckResult): string {
    if (!result.suspicious || !result.match) {
        return "No suspicious package-name similarity detected";
    }

    return (
        `Package name resembles ${result.match.referencePackage} ` +
        `(Levenshtein distance ${result.match.distance})`
    );
}

export function scoreRiskComponents(components: {
    severity: number;
    occurrenceSignals: number[];
    detection: number;
}): number {
    const severity = clampScore(components.severity);
    const occurrence = clampScore(
        Math.max(1, ...components.occurrenceSignals)
    );
    const detection = clampScore(components.detection);

    return normalizeRpn(severity * occurrence * detection);
}

export function getRiskRatingFromScore(
    riskScore: number
): RiskRating {
    if (riskScore <= 24) {
        return "LOW";
    }

    if (riskScore <= 49) {
        return "MEDIUM";
    }

    if (riskScore <= 74) {
        return "HIGH";
    }

    return "CRITICAL";
}

export async function generateRiskReport(
    packageName: string,
    version: string,
    options: RiskScorerOptions = {}
): Promise<RiskReport> {
    if (!packageName.trim()) {
        throw new Error("Package name is required");
    }

    if (!version.trim()) {
        throw new Error("Package version is required");
    }

    const dependencies: RiskScorerDependencies = {
        ...DEFAULT_DEPENDENCIES,
        ...options.dependencies,
    };

    const lifecycle = await dependencies.checkLifecycleScripts(
        packageName,
        version
    );
    const cooldown = await dependencies.checkCooldown(
        packageName,
        version
    );
    const typosquat = dependencies.checkPackageTyposquatting(
        packageName,
        options.previousPackageNames ?? [],
        options.popularPackageNames
    );

    const lifecycleScores = scoreLifecycleResult(lifecycle);
    const cooldownOccurrence = scoreCooldownResult(cooldown);
    const typosquatOccurrence = scoreTyposquatResult(typosquat);

    const severity = clampScore(lifecycleScores.severity);
    const occurrence = clampScore(
        Math.max(
            lifecycleScores.occurrence,
            cooldownOccurrence,
            typosquatOccurrence
        )
    );
    const detection = clampScore(lifecycleScores.detection);
    const rawRpn = severity * occurrence * detection;
    const normalizedScore = normalizeRpn(rawRpn);

    const evidence: RiskEvidence[] = [
        {
            detector: "lifecycle-script",
            summary: describeLifecycle(lifecycle),
            scores: lifecycleScores,
            details: lifecycle,
        },
        {
            detector: "cooldown",
            summary: describeCooldown(cooldown),
            scores: { occurrence: cooldownOccurrence },
            details: cooldown,
        },
        {
            detector: "typosquat",
            summary: describeTyposquat(typosquat),
            scores: { occurrence: typosquatOccurrence },
            details: typosquat,
        },
    ];

    return {
        packageName,
        version,
        breakdown: {
            severity,
            occurrence,
            detection,
            rawRpn,
            normalizedScore,
        },
        riskScore: normalizedScore,
        rating: getRiskRatingFromScore(normalizedScore),
        evidence,
    };
}

export async function riskScorer(
    packageName: string,
    version: string,
    options: RiskScorerOptions = {}
): Promise<number> {
    const report = await generateRiskReport(
        packageName,
        version,
        options
    );

    return report.riskScore;
}

export async function getRiskRating(
    packageName: string,
    version: string,
    options: RiskScorerOptions = {}
): Promise<RiskRating> {
    const report = await generateRiskReport(
        packageName,
        version,
        options
    );

    return report.rating;
}
