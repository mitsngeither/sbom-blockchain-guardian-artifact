#!/usr/bin/env tsx
/**
 * Runs the real detector pipeline over a labeled dataset and prints the
 * confusion matrix. Offline: install scripts come from the dataset and
 * checkCooldown is stubbed, since removed packages have no publishedAt.
 * The default, labeled-dataset.json (the development set), is not in this
 * repo. The paper's numbers come from evaluate-detector-ablation.ts.
 *
 * DATASET_FILE=test/fixtures/labeled-dataset-primary-eval.json npx tsx scripts/evaluate-detector.ts
 */

import fs from "node:fs";
import path from "node:path";

import { runDetectorPipeline } from "../src/detector/detector-pipeline.ts";
import type { RiskScorerDependencies } from "../src/detector/risk-scorer.ts";
import { detectLifecycleScripts } from "../src/detector/lifescycle-script-detector.ts";
import { checkPackageTyposquatting } from "../src/detector/typosquat-checker.ts";
import { POPULAR_NPM_PACKAGES } from "../src/detector/data/popular-npm-packages.ts";
import type { FlattenedSBOM, FlattenedSBOMComponent } from "@guardian/sbom-core";

// Shape of the labeled-dataset*.json files
interface LabeledPackage {
    label: "malicious" | "benign";
    source: string;
    name: string;
    version: string;
    scripts: Record<string, string>;
    dependencies: string[];
    hasPrePostInstall: boolean;
    hasExternalDownload: boolean;
    hasProcessEnv: boolean;
    rawPackageJson: Record<string, unknown> | null;
}

interface LabeledDataset {
    generatedAt: string;
    counts: { malicious: number; benign: number; total: number; extractionErrors: number; };
    packages: LabeledPackage[];
}

// One-component SBOM per sample
function buildSyntheticSbom(pkg: LabeledPackage): FlattenedSBOM {
    const component: FlattenedSBOMComponent = {
        key: `${pkg.name}@${pkg.version}`,
        identity: pkg.name,
        bomRef: `${pkg.name}@${pkg.version}`,
        type: "library",   // must be "library": currentLibraries() filters on it
        name: pkg.name,
        version: pkg.version,
        licenseIds: [],
        licenseExpressions: [],
        hashes: [],
        externalUrls: [],
        dependencies: pkg.dependencies,
        capabilities: [],
    };

    return {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        version: 1,
        components: [component],
        componentMap: { [component.key]: component },
        componentByBomRef: { [component.bomRef]: component },
    };
}

// Dependency injection, no network
function buildOfflineDependencies(
    pkg: LabeledPackage
): Partial<RiskScorerDependencies> {
    return {
        // use the extracted scripts instead of the registry
        async checkLifecycleScripts(packageName, version) {
            const scripts = detectLifecycleScripts(pkg.scripts);
            const scriptResults = Object.values(scripts);
            return {
                packageName,
                version,
                hasLifecycleScripts: scriptResults.some(r => r.exists),
                hasSuspiciousScripts: scriptResults.some(r => r.suspicious),
                scripts,
            };
        },
        // disabled: no real publishedAt for packages removed from npm
        async checkCooldown(_packageName, _version) {
            return {
                publishedAt: new Date(0).toISOString(),
                ageDays: 9999,
                cooldownDays: 30,
                isInCooldown: false,
            };
        },
        // checkPackageTyposquatting is used unchanged (synchronous, no network)
        checkPackageTyposquatting,
    };
}

// Main
interface EvalRow {
    name: string;
    version: string;
    trueLabel: "malicious" | "benign";
    decision: "PASS" | "REVIEW" | "BLOCK";
    predictedLabel: "malicious" | "benign";
    correct: boolean;
    riskScore: number;
    rating: string;
}

async function main() {
    const datasetPath = process.env["DATASET_FILE"] ?? path.join(
        import.meta.dirname,
        "..",
        "test",
        "fixtures",
        "labeled-dataset.json"
    );
    const dataset: LabeledDataset = JSON.parse(
        fs.readFileSync(datasetPath, "utf8")
    );

    const benignTestNames = new Set(
        dataset.packages.filter(p => p.label === "benign").map(p => p.name)
    );
    const referencePopularNames = POPULAR_NPM_PACKAGES.filter(
        name => !benignTestNames.has(name)
    );

    console.log(`Dataset: ${dataset.counts.total} samples (${dataset.counts.malicious} malicious, ${dataset.counts.benign} benign)`);
    console.log("Running the detector pipeline offline (no network)...\n");

    const rows: EvalRow[] = [];
    let processed = 0;
    let errors = 0;

    for (const pkg of dataset.packages) {
        const sbom = buildSyntheticSbom(pkg);

        try {
            const report = await runDetectorPipeline({
                projectId: "eval-dataset",
                currentVersion: pkg.version,
                mode: "full",
                currentSbom: sbom,
                riskScorerOptions: {
                    popularPackageNames: referencePopularNames,
                    dependencies: buildOfflineDependencies(pkg),
                },
            });

            const decision = report.summary.decision;
            // PASS = predicted benign; REVIEW/BLOCK = predicted malicious
            const predictedLabel: "malicious" | "benign" =
                decision === "PASS" ? "benign" : "malicious";

            rows.push({
                name: pkg.name,
                version: pkg.version,
                trueLabel: pkg.label,
                decision,
                predictedLabel,
                correct: predictedLabel === pkg.label,
                riskScore: report.summary.counts
                    ? report.packageReports[0]?.risk.riskScore ?? 0
                    : 0,
                rating: report.summary.overallRating,
            });
        } catch (err) {
            errors++;
            rows.push({
                name: pkg.name,
                version: pkg.version,
                trueLabel: pkg.label,
                decision: "PASS",
                predictedLabel: "benign",
                correct: pkg.label === "benign",
                riskScore: 0,
                rating: "ERROR",
            });
        }

        processed++;
        if (processed % 40 === 0) {
            console.log(`  ${processed}/${dataset.counts.total} (${errors} errors skipped)`);
        }
    }

    // Confusion matrix
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (const row of rows) {
        if (row.trueLabel === "malicious" && row.predictedLabel === "malicious") tp++;
        else if (row.trueLabel === "benign" && row.predictedLabel === "malicious") fp++;
        else if (row.trueLabel === "benign" && row.predictedLabel === "benign") tn++;
        else if (row.trueLabel === "malicious" && row.predictedLabel === "benign") fn++;
    }

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const falseAlarmRate = fp + tn > 0 ? fp / (fp + tn) : 0; // FPR

    console.log("\n=== RESULT ===");
    console.log(`TP=${tp}  FP=${fp}  TN=${tn}  FN=${fn}  (errors skipped: ${errors})`);
    console.log(`Precision       : ${(precision * 100).toFixed(2)}%`);
    console.log(`Recall          : ${(recall * 100).toFixed(2)}%`);
    console.log(`F1              : ${(f1 * 100).toFixed(2)}%`);
    console.log(`False-alarm rate: ${(falseAlarmRate * 100).toFixed(2)}%`);

    const outputPath = process.env["RESULTS_FILE"] ?? path.join(
        import.meta.dirname, "..", "test", "fixtures", "eval-results.json"
    );
    fs.writeFileSync(
        outputPath,
        JSON.stringify(
            {
                generatedAt: new Date().toISOString(),
                datasetCounts: dataset.counts,
                confusionMatrix: { tp, fp, tn, fn },
                metrics: {
                    precision: Number(precision.toFixed(4)),
                    recall: Number(recall.toFixed(4)),
                    f1: Number(f1.toFixed(4)),
                    falseAlarmRate: Number(falseAlarmRate.toFixed(4)),
                },
                errors,
                rows,
            },
            null,
            2
        ),
        "utf8"
    );
    console.log(`\nDetails written to ${outputPath}`);
}

main().catch(err => {
    console.error("FATAL:", err);
    process.exit(1);
});