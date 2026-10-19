import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    runDetectorPipeline,
    type DetectorPipelineInput,
} from "../../src/detector/detector-pipeline.ts";
import type { CooldownResult } from "../../src/detector/cooldown-checker.ts";
import type { LifecycleScriptsCheckResult } from "../../src/detector/lifescycle-script-detector.ts";
import type { RiskScorerDependencies } from "../../src/detector/risk-scorer.ts";
import type { TypoCheckResult } from "../../src/detector/typosquat-checker.ts";
import type {
    FlattenedSBOM,
    FlattenedSBOMComponent,
} from "@guardian/sbom-core";

function component(
    name: string,
    version: string,
    type = "library"
): FlattenedSBOMComponent {
    const key = `pkg:npm/${name}@${version}`;
    return {
        key,
        identity: name,
        bomRef: key,
        type,
        name,
        version,
        purl: key,
        licenseIds: [],
        licenseExpressions: [],
        hashes: [],
        externalUrls: [],
        dependencies: [],
        capabilities: [],
    };
}

function sbom(
    components: FlattenedSBOMComponent[]
): FlattenedSBOM {
    return {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        version: 1,
        components,
        componentMap: Object.fromEntries(
            components.map(item => [item.key, item])
        ),
        componentByBomRef: Object.fromEntries(
            components.map(item => [item.bomRef, item])
        ),
    };
}

function lifecycleResult(
    packageName: string
): LifecycleScriptsCheckResult {
    const suspicious = ["critical", "high", "pipe"].includes(
        packageName
    );
    const matchedPatterns = packageName === "pipe"
        ? ["remote-script-pipe-to-shell"]
        : suspicious
            ? ["node-child-process"]
            : [];

    return {
        packageName,
        version: "1.0.0",
        hasLifecycleScripts: suspicious,
        hasSuspiciousScripts: suspicious,
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
                exists: suspicious,
                command: suspicious ? "node install.js" : undefined,
                suspicious,
                matchedPatterns,
            },
        },
    };
}

function detectorDependencies(
    calls: string[] = [],
    previousNameSnapshots: string[][] = []
): RiskScorerDependencies {
    return {
        checkLifecycleScripts: async packageName => {
            calls.push(`${packageName}:lifecycle`);
            return lifecycleResult(packageName);
        },
        checkCooldown: async packageName => {
            calls.push(`${packageName}:cooldown`);
            const recent = packageName === "critical";
            const result: CooldownResult = {
                publishedAt: "2026-07-05T00:00:00.000Z",
                ageDays: recent ? 0.25 : 365,
                cooldownDays: 30,
                isInCooldown: recent,
            };
            return result;
        },
        checkPackageTyposquatting: (
            packageName,
            previousPackageNames
        ) => {
            calls.push(`${packageName}:typosquat`);
            previousNameSnapshots.push([...previousPackageNames]);
            const result: TypoCheckResult = {
                packageName,
                normalizedPackageName: packageName,
                existedPreviously: previousPackageNames.includes(
                    packageName
                ),
                suspicious: false,
            };
            return result;
        },
    };
}

function baseInput(
    currentSbom: FlattenedSBOM,
    overrides: Partial<DetectorPipelineInput> = {}
): DetectorPipelineInput {
    return {
        projectId: "demo-project",
        currentVersion: "2.0.0",
        currentSbom,
        riskScorerOptions: {
            dependencies: detectorDependencies(),
        },
        ...overrides,
    };
}

describe("runDetectorPipeline", () => {
    it("analyzes only ADDED and CHANGED libraries sequentially", async () => {
        const calls: string[] = [];
        const previousNames: string[][] = [];
        const previousSbom = sbom([
            component("project", "1.0.0", "application"),
            component("unchanged", "1.0.0"),
            component("upgraded", "1.0.0"),
            component("removed", "1.0.0"),
        ]);
        const currentSbom = sbom([
            component("project", "2.0.0", "application"),
            component("unchanged", "1.0.0"),
            component("upgraded", "2.0.0"),
            component("added", "1.0.0"),
        ]);

        const report = await runDetectorPipeline(baseInput(
            currentSbom,
            {
                previousSbom,
                previousVersion: "1.0.0",
                riskScorerOptions: {
                    dependencies: detectorDependencies(
                        calls,
                        previousNames
                    ),
                },
            }
        ));

        assert.equal(report.mode, "incremental");
        assert.deepEqual(
            report.packageReports.map(item => item.changeType),
            ["ADDED", "CHANGED"]
        );
        assert.deepEqual(
            report.packageReports.map(item => item.risk.packageName),
            ["added", "upgraded"]
        );
        assert.deepEqual(calls, [
            "added:lifecycle",
            "added:cooldown",
            "added:typosquat",
            "upgraded:lifecycle",
            "upgraded:cooldown",
            "upgraded:typosquat",
        ]);
        assert.deepEqual(previousNames[0], [
            "removed",
            "unchanged",
            "upgraded",
        ]);
        assert.equal(report.summary.analyzedPackages, 2);
        assert.equal(report.summary.skippedPackages, 2);
        assert.deepEqual(
            report.diff.removed.map(item => item.packageName),
            ["removed"]
        );
    });

    it("supports explicit full scans with UNCHANGED reports", async () => {
        const previousSbom = sbom([
            component("project", "1.0.0", "application"),
            component("unchanged", "1.0.0"),
        ]);
        const currentSbom = sbom([
            component("project", "1.0.0", "application"),
            component("unchanged", "1.0.0"),
            component("added", "1.0.0"),
        ]);

        const report = await runDetectorPipeline(baseInput(
            currentSbom,
            { previousSbom, mode: "full" }
        ));

        assert.equal(report.mode, "full");
        assert.deepEqual(
            report.packageReports.map(item => ({
                name: item.risk.packageName,
                type: item.changeType,
            })),
            [
                { name: "added", type: "ADDED" },
                { name: "unchanged", type: "UNCHANGED" },
            ]
        );
        assert.equal(report.summary.analyzedPackages, 2);
        assert.equal(report.summary.skippedPackages, 1);
    });

    it("falls back to full mode when no previous SBOM exists", async () => {
        const currentSbom = sbom([
            component("project", "1.0.0", "application"),
            component("lodash", "4.17.21"),
        ]);

        const report = await runDetectorPipeline(
            baseInput(currentSbom)
        );

        assert.equal(report.mode, "full");
        assert.equal(report.packageReports[0].changeType, "ADDED");
        assert.ok(report.summary.reasons.some(reason =>
            reason.includes("No previous SBOM")
        ));
    });

    it("aggregates the highest rating and blocks CRITICAL", async () => {
        const currentSbom = sbom([
            component("project", "1.0.0", "application"),
            component("low", "1.0.0"),
            component("critical", "1.0.0"),
        ]);

        const report = await runDetectorPipeline(
            baseInput(currentSbom)
        );

        assert.equal(report.summary.overallRating, "CRITICAL");
        assert.equal(report.summary.decision, "BLOCK");
        assert.deepEqual(report.summary.highestRiskPackages, [
            "critical",
        ]);
        assert.deepEqual(report.summary.counts, {
            LOW: 1,
            MEDIUM: 0,
            HIGH: 0,
            CRITICAL: 1,
        });
    });

    it("separates default and configurable rating decisions", async () => {
        const currentSbom = sbom([
            component("high", "1.0.0"),
        ]);

        const review = await runDetectorPipeline(
            baseInput(currentSbom)
        );
        const blocked = await runDetectorPipeline(baseInput(
            currentSbom,
            {
                policy: {
                    decisionByRating: { HIGH: "BLOCK" },
                },
            }
        ));

        assert.equal(review.summary.overallRating, "HIGH");
        assert.equal(review.summary.decision, "REVIEW");
        assert.equal(blocked.summary.overallRating, "HIGH");
        assert.equal(blocked.summary.decision, "BLOCK");
    });

    it("mandatory-blocks remote content piped to a shell", async () => {
        const currentSbom = sbom([
            component("pipe", "1.0.0"),
        ]);

        const report = await runDetectorPipeline(
            baseInput(currentSbom)
        );

        assert.equal(report.summary.overallRating, "HIGH");
        assert.equal(report.summary.decision, "BLOCK");
        const lifecycleEvidence = report.packageReports[0]
            .risk.evidence.find(
                evidence => evidence.detector === "lifecycle-script"
            );
        assert.equal(lifecycleEvidence?.mandatoryBlock, true);
        assert.ok(lifecycleEvidence?.policyReason?.includes(
            "remote-script-pipe-to-shell"
        ));
    });

    it("returns LOW/PASS for an empty dependency set", async () => {
        const currentSbom = sbom([
            component("project", "1.0.0", "application"),
        ]);

        const report = await runDetectorPipeline(
            baseInput(currentSbom)
        );

        assert.equal(report.summary.overallRating, "LOW");
        assert.equal(report.summary.decision, "PASS");
        assert.equal(report.summary.analyzedPackages, 0);
        assert.equal(report.summary.skippedPackages, 1);
    });

    it("requires review when npm metadata cannot be resolved", async () => {
        const currentSbom = sbom([
            component("project", "1.0.0", "application"),
            component("private-package", "1.0.0"),
        ]);
        const unavailableDependencies = detectorDependencies();
        unavailableDependencies.checkLifecycleScripts = async () => {
            throw new Error("Package not found: private-package");
        };

        const report = await runDetectorPipeline(baseInput(
            currentSbom,
            {
                riskScorerOptions: {
                    dependencies: unavailableDependencies,
                },
            }
        ));

        assert.equal(report.summary.overallRating, "LOW");
        assert.equal(report.summary.decision, "REVIEW");
        assert.equal(report.summary.analyzedPackages, 0);
        assert.equal(report.summary.skippedPackages, 2);
        assert.equal(report.skippedPackageReports.length, 1);
        assert.ok(report.summary.reasons.some(reason =>
            reason.includes("PASS to REVIEW")
        ));
        assert.equal(
            report.skippedPackageReports[0].packageName,
            "private-package"
        );
    });

    it("skips (instead of crashing the batch) when a version is missing from npm metadata", async () => {
        const currentSbom = sbom([
            component("project", "1.0.0", "application"),
            component("delisted-package", "9.9.9"),
        ]);
        const unavailableDependencies = detectorDependencies();
        unavailableDependencies.checkCooldown = async () => {
            throw new Error("Version not found: delisted-package@9.9.9");
        };

        const report = await runDetectorPipeline(baseInput(
            currentSbom,
            {
                riskScorerOptions: {
                    dependencies: unavailableDependencies,
                },
            }
        ));

        assert.equal(report.summary.decision, "REVIEW");
        assert.equal(report.skippedPackageReports.length, 1);
        assert.equal(
            report.skippedPackageReports[0].packageName,
            "delisted-package"
        );
    });

    it("does not downgrade BLOCK when another package is unresolved", async () => {
        const currentSbom = sbom([
            component("critical", "1.0.0"),
            component("private-package", "1.0.0"),
        ]);
        const unavailableDependencies = detectorDependencies();
        const checkLifecycleScripts =
            unavailableDependencies.checkLifecycleScripts;
        unavailableDependencies.checkLifecycleScripts =
            async packageName => {
                if (packageName === "private-package") {
                    throw new Error(
                        "Package not found: private-package"
                    );
                }

                return checkLifecycleScripts(packageName, "1.0.0");
            };

        const report = await runDetectorPipeline(baseInput(
            currentSbom,
            {
                riskScorerOptions: {
                    dependencies: unavailableDependencies,
                },
            }
        ));

        assert.equal(report.summary.overallRating, "CRITICAL");
        assert.equal(report.summary.decision, "BLOCK");
        assert.equal(report.skippedPackageReports.length, 1);
    });

    it("validates required project metadata before scanning", async () => {
        const currentSbom = sbom([]);

        await assert.rejects(
            runDetectorPipeline(baseInput(currentSbom, {
                projectId: " ",
            })),
            /Project ID is required/
        );
    });
});
