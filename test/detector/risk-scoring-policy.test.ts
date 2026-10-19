import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { CooldownResult } from "../../src/detector/cooldown-checker.ts";
import type { LifecycleScriptsCheckResult } from "../../src/detector/lifescycle-script-detector.ts";
import {
    RISK_SCORE_POLICY,
    scoreCooldownResult,
    scoreLifecycleResult,
    scoreTyposquatResult,
} from "../../src/detector/risk-scoring-policy.ts";
import type { TypoCheckResult } from "../../src/detector/typosquat-checker.ts";

function lifecycleResult(
    hasLifecycleScripts: boolean,
    hasSuspiciousScripts: boolean
): LifecycleScriptsCheckResult {
    return {
        packageName: "fixture",
        version: "1.0.0",
        hasLifecycleScripts,
        hasSuspiciousScripts,
        scripts: {
            preinstall: {
                scriptName: "preinstall",
                exists: false,
                suspicious: false,
                matchedPatterns: [],
            },
            install: {
                scriptName: "install",
                exists: false,
                suspicious: false,
                matchedPatterns: [],
            },
            postinstall: {
                scriptName: "postinstall",
                exists: hasLifecycleScripts,
                command: hasLifecycleScripts ? "node setup.js" : undefined,
                suspicious: hasSuspiciousScripts,
                matchedPatterns: hasSuspiciousScripts
                    ? ["remote-script-pipe-to-shell"]
                    : [],
            },
        },
    };
}

function cooldownResult(
    ageDays: number,
    isInCooldown: boolean
): CooldownResult {
    return {
        publishedAt: "2026-07-05T00:00:00.000Z",
        ageDays,
        cooldownDays: 60,
        isInCooldown,
    };
}

function typoResult(distance?: number): TypoCheckResult {
    return {
        packageName: "expresss",
        normalizedPackageName: "expresss",
        existedPreviously: false,
        suspicious: distance !== undefined,
        match: distance === undefined
            ? undefined
            : {
                referencePackage: "express",
                distance,
                normalizedDistance: distance / 8,
                source: "popular-packages",
            },
    };
}

describe("risk scoring policy", () => {
    it("documents every numeric policy value with a rationale", () => {
        for (const category of Object.values(RISK_SCORE_POLICY)) {
            for (const rule of Object.values(category)) {
                assert.ok(rule.rationale.length > 20);
                const scores = "score" in rule
                    ? [rule.score]
                    : Object.values(rule.scores);
                assert.ok(
                    scores.every(score => score >= 1 && score <= 5)
                );
            }
        }
    });

    it("maps lifecycle evidence to calibrated S/O/D values", () => {
        assert.deepEqual(
            scoreLifecycleResult(lifecycleResult(false, false)),
            { severity: 1, occurrence: 1, detection: 1 }
        );
        assert.deepEqual(
            scoreLifecycleResult(lifecycleResult(true, false)),
            { severity: 3, occurrence: 2, detection: 1 }
        );
        assert.deepEqual(
            scoreLifecycleResult(lifecycleResult(true, true)),
            { severity: 5, occurrence: 4, detection: 4 }
        );
    });

    it("increases cooldown Occurrence as observation time shrinks", () => {
        assert.equal(scoreCooldownResult(cooldownResult(90, false)), 1);
        assert.equal(scoreCooldownResult(cooldownResult(45, true)), 2);
        assert.equal(scoreCooldownResult(cooldownResult(20, true)), 3);
        assert.equal(scoreCooldownResult(cooldownResult(5, true)), 4);
        assert.equal(scoreCooldownResult(cooldownResult(0.5, true)), 5);
    });

    it("uses name similarity as strong evidence but never proof", () => {
        assert.equal(scoreTyposquatResult(typoResult()), 1);
        assert.equal(scoreTyposquatResult(typoResult(2)), 3);
        assert.equal(scoreTyposquatResult(typoResult(1)), 4);
    });
});
