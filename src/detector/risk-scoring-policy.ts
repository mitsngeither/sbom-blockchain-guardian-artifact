import type { CooldownResult } from "./cooldown-checker.ts";
import type { LifecycleScriptsCheckResult } from "./lifescycle-script-detector.ts";
import type { TypoCheckResult } from "./typosquat-checker.ts";

export interface RiskScoreComponents {
    severity: number;
    occurrence: number;
    detection: number;
}

export const RISK_SCORE_POLICY = {
    lifecycle: {
        none: {
            scores: { severity: 1, occurrence: 1, detection: 1 },
            rationale:
                "No install-time execution surface was found, so lifecycle risk remains at the baseline.",
        },
        present: {
            scores: { severity: 3, occurrence: 2, detection: 1 },
            rationale:
                "Install-time code can modify the host, but legitimate build and setup scripts are common and visible in metadata.",
        },
        suspicious: {
            scores: { severity: 5, occurrence: 4, detection: 4 },
            rationale:
                "The command can enable arbitrary execution or data loss and strongly resembles attack behavior that dependency review may miss.",
        },
    },
    cooldown: {
        outside: {
            score: 1,
            rationale:
                "The version passed its observation window, so freshness contributes no additional risk evidence.",
        },
        customWindow: {
            score: 2,
            rationale:
                "The version is only fresh under a custom long window, which is a weak exposure signal.",
        },
        thirtyDays: {
            score: 3,
            rationale:
                "The version has limited community observation time, creating a moderate freshness signal.",
        },
        sevenDays: {
            score: 4,
            rationale:
                "The version has very little ecosystem observation time, creating a strong freshness signal.",
        },
        oneDay: {
            score: 5,
            rationale:
                "The version has almost no public observation time and receives the maximum freshness level.",
        },
    },
    typosquat: {
        clean: {
            score: 1,
            rationale:
                "The name is exact or has no suspicious nearby reference, so there is no name-based anomaly.",
        },
        weakSimilarity: {
            score: 2,
            rationale:
                "A custom loose threshold found similarity, but the edit distance is too large for strong typo evidence.",
        },
        distanceTwo: {
            score: 3,
            rationale:
                "Two edits form plausible typo evidence while retaining meaningful risk of coincidental similarity.",
        },
        distanceOne: {
            score: 4,
            rationale:
                "One edit closely matches common typosquat naming, but similarity alone is not proof of malicious intent.",
        },
    },
} as const;

export function scoreLifecycleResult(
    result: LifecycleScriptsCheckResult
): RiskScoreComponents {
    if (!result.hasLifecycleScripts) {
        return { ...RISK_SCORE_POLICY.lifecycle.none.scores };
    }

    if (result.hasSuspiciousScripts) {
        return { ...RISK_SCORE_POLICY.lifecycle.suspicious.scores };
    }

    return { ...RISK_SCORE_POLICY.lifecycle.present.scores };
}

export function scoreCooldownResult(
    result: CooldownResult
): number {
    if (!result.isInCooldown) {
        return RISK_SCORE_POLICY.cooldown.outside.score;
    }

    if (result.ageDays <= 1) {
        return RISK_SCORE_POLICY.cooldown.oneDay.score;
    }

    if (result.ageDays <= 7) {
        return RISK_SCORE_POLICY.cooldown.sevenDays.score;
    }

    if (result.ageDays <= 30) {
        return RISK_SCORE_POLICY.cooldown.thirtyDays.score;
    }

    return RISK_SCORE_POLICY.cooldown.customWindow.score;
}

export function scoreTyposquatResult(
    result: TypoCheckResult
): number {
    if (!result.suspicious || !result.match) {
        return RISK_SCORE_POLICY.typosquat.clean.score;
    }

    if (result.match.distance <= 1) {
        return RISK_SCORE_POLICY.typosquat.distanceOne.score;
    }

    if (result.match.distance === 2) {
        return RISK_SCORE_POLICY.typosquat.distanceTwo.score;
    }

    return RISK_SCORE_POLICY.typosquat.weakSimilarity.score;
}
