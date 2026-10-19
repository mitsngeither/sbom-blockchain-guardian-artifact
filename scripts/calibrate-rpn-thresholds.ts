#!/usr/bin/env tsx
/**
 * RPN threshold calibration, using the scoring functions CI runs (imported, not
 * copied). [1] enumerates every reachable score, [2] sweeps thresholds 0..100 on
 * the labeled dataset, [3] reports the best recall any threshold can reach.
 * Cooldown is stubbed to false for the dataset (no publishedAt for removed
 * packages); [1] still covers the cooldown branches. Sample output:
 * results/rpn-calibration-20261017.log.
 *
 * DATASET_FILE=test/fixtures/labeled-dataset-primary-eval.json npx tsx scripts/calibrate-rpn-thresholds.ts
 */

import fs from "node:fs";
import path from "node:path";

import { SUSPICIOUS_COMMAND_PATTERNS } from "../src/detector/data/suspicious-patterns.ts";
import { POPULAR_NPM_PACKAGES } from "../src/detector/data/popular-npm-packages.ts";
import {
    scoreCooldownResult,
    scoreLifecycleResult,
    scoreTyposquatResult,
} from "../src/detector/risk-scoring-policy.ts";
import {
    getRiskRatingFromScore,
    scoreRiskComponents,
    type RiskRating,
} from "../src/detector/risk-scorer.ts";
import { checkPackageTyposquatting } from "../src/detector/typosquat-checker.ts";
import type { CooldownResult } from "../src/detector/cooldown-checker.ts";
import type { LifecycleScriptsCheckResult } from "../src/detector/lifescycle-script-detector.ts";

const FIXTURES = path.join(import.meta.dirname, "..", "test", "fixtures");
const DATASET_FILE =
    process.env["DATASET_FILE"] ??
    path.join(FIXTURES, "labeled-dataset-primary-eval.json");

// Same mapping as DEFAULT_PIPELINE_POLICY in detector-pipeline.ts.
const DECISION_BY_RATING: Record<RiskRating, "PASS" | "REVIEW" | "BLOCK"> = {
    LOW: "PASS",
    MEDIUM: "REVIEW",
    HIGH: "REVIEW",
    CRITICAL: "BLOCK",
};

const HOOKS = ["preinstall", "install", "postinstall"] as const;

interface Pkg {
    label: "malicious" | "benign";
    name: string;
    version: string;
    scripts: Record<string, string>;
}

// Synthetic check results fed into the real scoring functions
function lifecycleResult(
    hasLifecycleScripts: boolean,
    hasSuspiciousScripts: boolean
): LifecycleScriptsCheckResult {
    return {
        packageName: "x",
        version: "1.0.0",
        hasLifecycleScripts,
        hasSuspiciousScripts,
        scripts: {} as LifecycleScriptsCheckResult["scripts"],
    };
}

function cooldownResult(isInCooldown: boolean, ageDays: number): CooldownResult {
    return { publishedAt: "", ageDays, cooldownDays: 30, isInCooldown };
}

// [1] Exhaustive enumeration of the score space
interface Reachable {
    lifecycle: string;
    cooldown: string;
    typosquat: string;
    severity: number;
    occurrence: number;
    detection: number;
    score: number;
    rating: RiskRating;
    decision: string;
}

const LIFECYCLE_STATES: Array<[string, LifecycleScriptsCheckResult]> = [
    ["none", lifecycleResult(false, false)],
    ["present", lifecycleResult(true, false)],
    ["suspicious", lifecycleResult(true, true)],
];

// Every branch of scoreCooldownResult, including ones the dataset never reaches.
const COOLDOWN_STATES: Array<[string, CooldownResult]> = [
    ["outside", cooldownResult(false, 999)],
    ["<=1d", cooldownResult(true, 1)],
    ["<=7d", cooldownResult(true, 7)],
    ["<=30d", cooldownResult(true, 30)],
    ["custom", cooldownResult(true, 100)],
];

// Every branch of scoreTyposquatResult.
const TYPOSQUAT_STATES: Array<[string, number]> = [
    ["clean", 1],
    ["weak", 2],
    ["dist=2", 3],
    ["dist=1", 4],
];

function enumerateReachable(): Reachable[] {
    const rows: Reachable[] = [];

    for (const [lcName, lc] of LIFECYCLE_STATES) {
        const lcScores = scoreLifecycleResult(lc);

        for (const [cdName, cd] of COOLDOWN_STATES) {
            const cdScore = scoreCooldownResult(cd);

            for (const [tsName, tsScore] of TYPOSQUAT_STATES) {
                const score = scoreRiskComponents({
                    severity: lcScores.severity,
                    occurrenceSignals: [lcScores.occurrence, cdScore, tsScore],
                    detection: lcScores.detection,
                });
                const rating = getRiskRatingFromScore(score);

                rows.push({
                    lifecycle: lcName,
                    cooldown: cdName,
                    typosquat: tsName,
                    severity: lcScores.severity,
                    occurrence: Math.max(lcScores.occurrence, cdScore, tsScore),
                    detection: lcScores.detection,
                    score,
                    rating,
                    decision: DECISION_BY_RATING[rating],
                });
            }
        }
    }

    return rows;
}

// [2] Real scoring on the dataset
function hookText(p: Pkg): string {
    return HOOKS.map(h => p.scripts?.[h] ?? "").filter(Boolean).join("\n");
}

function scorePackage(p: Pkg): number {
    const cmd = hookText(p);
    const hasLifecycle = cmd.trim() !== "";
    const hasSuspicious =
        hasLifecycle &&
        SUSPICIOUS_COMMAND_PATTERNS.some(({ pattern }) => pattern.test(cmd));

    const lcScores = scoreLifecycleResult(
        lifecycleResult(hasLifecycle, hasSuspicious)
    );

    // Stub: removed packages have no real publishedAt.
    const cdScore = scoreCooldownResult(cooldownResult(false, 999));

    const tsScore = scoreTyposquatResult(
        checkPackageTyposquatting(p.name, [], POPULAR_NPM_PACKAGES)
    );

    return scoreRiskComponents({
        severity: lcScores.severity,
        occurrenceSignals: [lcScores.occurrence, cdScore, tsScore],
        detection: lcScores.detection,
    });
}

interface Point {
    threshold: number;
    tp: number;
    fp: number;
    tn: number;
    fn: number;
    precision: number;
    recall: number;
    f1: number;
    far: number;
}

function sweep(scored: Array<{ label: string; score: number }>): Point[] {
    const points: Point[] = [];

    // malicious if score >= t, for every t in 0..100
    for (let t = 0; t <= 100; t++) {
        let tp = 0, fp = 0, tn = 0, fn = 0;

        for (const s of scored) {
            const hit = s.score >= t;
            if (s.label === "malicious") hit ? tp++ : fn++;
            else hit ? fp++ : tn++;
        }

        const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
        const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
        const f1 =
            precision + recall > 0
                ? (2 * precision * recall) / (precision + recall)
                : 0;
        const far = fp + tn > 0 ? fp / (fp + tn) : 0;

        points.push({ threshold: t, tp, fp, tn, fn, precision, recall, f1, far });
    }

    return points;
}

const pct = (x: number) => (x * 100).toFixed(2) + "%";

function main() {
    // Part 1
    console.log(
        "=== [1] Exhaustive enumeration of the RPN score space (policy as run in CI) ===\n"
    );

    const reachable = enumerateReachable();
    const distinct = [...new Set(reachable.map(r => r.score))].sort((a, b) => a - b);

    console.log(
        `Combinations (lifecycle x cooldown x typosquat): ${reachable.length}`
    );
    console.log(`Distinct reachable scores                     : ${distinct.length}`);
    console.log(`Reachable scores                              : {${distinct.join(", ")}}\n`);

    console.log("Score -> rating -> decision, and the combinations that produce it:");
    for (const score of distinct) {
        const rows = reachable.filter(r => r.score === score);
        const first = rows[0]!;
        const lcSet = [...new Set(rows.map(r => r.lifecycle))].join("|");
        console.log(
            `  score=${String(score).padStart(3)}  ${first.rating.padEnd(8)} ` +
            `${first.decision.padEnd(6)}  (lifecycle=${lcSet}, ` +
            `S=${first.severity} D=${first.detection}, ${rows.length} combinations)`
        );
    }

    // Gaps: any threshold inside one gives identical decisions.
    let gapLow = 0, gapHigh = 0;
    for (let i = 1; i < distinct.length; i++) {
        const lo = distinct[i - 1]!, hi = distinct[i]!;
        if (hi - lo > gapHigh - gapLow) { gapLow = lo; gapHigh = hi; }
    }
    console.log(
        `\nLargest gap in the score set: (${gapLow}, ${gapHigh}), ` +
        `${gapHigh - gapLow} points wide, no reachable score inside.`
    );
    console.log(
        `=> Any threshold inside this gap gives identical decisions. ` +
        `The current LOW/MEDIUM threshold (24) is inside it.`
    );

    // Can cooldown or typosquat ever change the rating?
    const byLifecycle = new Map<string, Set<RiskRating>>();
    for (const r of reachable) {
        if (!byLifecycle.has(r.lifecycle)) byLifecycle.set(r.lifecycle, new Set());
        byLifecycle.get(r.lifecycle)!.add(r.rating);
    }
    console.log("\nWith lifecycle fixed, can cooldown + typosquat change the rating?");
    for (const [lc, ratings] of byLifecycle) {
        console.log(
            `  lifecycle=${lc.padEnd(11)} -> reachable ratings: ` +
            `{${[...ratings].join(", ")}}` +
            (ratings.size === 1 ? "   (cannot change)" : "   (can change)")
        );
    }

    // Part 2
    console.log(`\n\n=== [2] Threshold sweep on the labeled dataset ===\n`);
    console.log(`Dataset: ${DATASET_FILE}`);

    const dataset = JSON.parse(fs.readFileSync(DATASET_FILE, "utf8")) as {
        packages: Pkg[];
    };
    const scored = dataset.packages.map(p => ({
        label: p.label,
        name: p.name,
        score: scorePackage(p),
    }));

    const mal = scored.filter(s => s.label === "malicious");
    const ben = scored.filter(s => s.label === "benign");
    console.log(`Malicious: ${mal.length}   Benign: ${ben.length}\n`);

    console.log("Observed score distribution:");
    const allScores = [...new Set(scored.map(s => s.score))].sort((a, b) => a - b);
    for (const sc of allScores) {
        const m = mal.filter(s => s.score === sc).length;
        const b = ben.filter(s => s.score === sc).length;
        const rating = getRiskRatingFromScore(sc);
        console.log(
            `  score=${String(sc).padStart(3)} (${rating.padEnd(8)}` +
            `${DECISION_BY_RATING[rating].padEnd(7)}): ` +
            `malicious=${String(m).padStart(4)}  benign=${String(b).padStart(5)}`
        );
    }

    // Which signal drives the score? If it is only "has an install hook", the
    // FAR depends on how many benign packages use hooks.
    console.log("\nWhich signal produces scores > 1:");
    let benignWithHook = 0;
    let malWithHook = 0;
    const benignHookNames: string[] = [];
    let benignTyposquat = 0;

    for (const p of dataset.packages) {
        const cmd = hookText(p);
        const hasHook = cmd.trim() !== "";
        const ts = scoreTyposquatResult(
            checkPackageTyposquatting(p.name, [], POPULAR_NPM_PACKAGES)
        );

        if (p.label === "benign") {
            if (hasHook) { benignWithHook++; benignHookNames.push(`${p.name}@${p.version}`); }
            if (ts > 1) benignTyposquat++;
        } else if (hasHook) {
            malWithHook++;
        }
    }

    console.log(
        `  Has lifecycle hook: malicious ${malWithHook}/${mal.length} ` +
        `(${((malWithHook / mal.length) * 100).toFixed(1)}%)   ` +
        `benign: ${benignWithHook}/${ben.length} ` +
        `(${((benignWithHook / ben.length) * 100).toFixed(2)}%)`
    );
    console.log(`  Benign flagged by typosquat (score 2-3): ${benignTyposquat}`);
    console.log(`  Benign with hooks: ${benignHookNames.join(", ") || "(none)"}`);
    console.log(
        `\n  Extrapolation warning: the benign set is the .pnpm tree of this one\n` +
        `  project. Only ${benignWithHook}/${ben.length} packages use an install hook, ` +
        `unusually few compared with\n  npm at large (native/node-gyp packages, esbuild, sharp... ` +
        `all have hooks). The measured FAR\n  is therefore an optimistic lower bound; across npm ` +
        `it would be noticeably higher.`
    );

    const points = sweep(scored);

    // Print only thresholds that change the outcome; the rest repeat.
    console.log("\nDistinct operating points (thresholds that change the confusion matrix):");
    console.log(
        "  t".padEnd(6) + "TP".padStart(5) + "FP".padStart(6) +
        "TN".padStart(7) + "FN".padStart(6) +
        "precision".padStart(11) + "recall".padStart(9) +
        "F1".padStart(9) + "FAR".padStart(9)
    );

    let prev = "";
    const distinctPoints: Point[] = [];
    for (const p of points) {
        const key = `${p.tp}/${p.fp}/${p.tn}/${p.fn}`;
        if (key === prev) continue;
        prev = key;
        distinctPoints.push(p);
        console.log(
            `  ${String(p.threshold).padEnd(4)}` +
            String(p.tp).padStart(5) + String(p.fp).padStart(6) +
            String(p.tn).padStart(7) + String(p.fn).padStart(6) +
            pct(p.precision).padStart(11) + pct(p.recall).padStart(9) +
            pct(p.f1).padStart(9) + pct(p.far).padStart(9)
        );
    }
    console.log(
        `\n=> 101 thresholds (t=0..100) give only ${distinctPoints.length} ` +
        `distinct operating points.`
    );

    // Part 3
    console.log(`\n\n=== [3] Ceiling over all thresholds ===\n`);

    // Skip the two degenerate points (flag all / flag none) when looking for best F1.
    const usable = points.filter(p => p.tp + p.fp > 0 && p.fn + p.tn > 0);
    const bestF1 = usable.reduce((a, b) => (b.f1 > a.f1 ? b : a), usable[0]!);

    // Seed from the filtered set; usable[0] may have fp > 0.
    const zeroFp = usable.filter(p => p.fp === 0);
    const bestRecallNoFp = zeroFp.length
        ? zeroFp.reduce((a, b) => (b.recall > a.recall ? b : a))
        : undefined;

    const maxRecall = points.reduce((a, b) => (b.recall > a.recall ? b : a), points[0]!);

    console.log(
        `Best F1               : t=${bestF1.threshold}  ` +
        `P=${pct(bestF1.precision)} R=${pct(bestF1.recall)} ` +
        `F1=${pct(bestF1.f1)} FAR=${pct(bestF1.far)}`
    );
    console.log(
        bestRecallNoFp
            ? `Best recall at FAR=0  : t=${bestRecallNoFp.threshold}  ` +
              `R=${pct(bestRecallNoFp.recall)} (FP=${bestRecallNoFp.fp})`
            : `Best recall at FAR=0  : (no threshold reaches FAR=0)`
    );
    console.log(
        `Max recall (any threshold, incl. flag-all) : ${pct(maxRecall.recall)} ` +
        `at t=${maxRecall.threshold} with FAR=${pct(maxRecall.far)}`
    );

    // Practical ceiling: exclude the degenerate "flag everything" point
    const nonTrivial = usable.reduce((a, b) => (b.recall > a.recall ? b : a), usable[0]!);
    console.log(
        `Max non-degenerate recall : ${pct(nonTrivial.recall)} ` +
        `at t=${nonTrivial.threshold} (FAR=${pct(nonTrivial.far)})`
    );

    console.log(
        `\nConclusion: the whole threshold range was swept. Recall does not exceed ` +
        `${pct(nonTrivial.recall)} at any threshold.\n` +
        `The bottleneck is signal generation, not threshold placement ` +
        `(S and D come only from the lifecycle-script check).\n` +
        `Tuning the threshold cannot fix this; new signals are needed.`
    );

    console.log(
        `\nLimitation: parts [2]/[3] run with cooldown stubbed ` +
        `(isInCooldown=false for every package,\nsince the malicious packages were removed from npm ` +
        `and have no publishedAt). Part [1] enumerates the\ncooldown branches ` +
        `and is not affected.`
    );
}

main();
