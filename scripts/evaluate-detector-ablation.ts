#!/usr/bin/env tsx
/**
 * Detector ablation. Baseline is the pattern set CI runs (the row reported in
 * the paper); Step A adds 6 install-command patterns; Step B adds a scan of file
 * contents. A and B are offline prototypes and are not used in CI. Results are
 * given for all malicious samples and for the "detectable" subset.
 *
 * DATASET_FILE=test/fixtures/labeled-dataset-primary-eval.json npx tsx scripts/evaluate-detector-ablation.ts
 */

import fs from "node:fs";
import path from "node:path";

import { SUSPICIOUS_COMMAND_PATTERNS } from "../src/detector/data/suspicious-patterns.ts";

const FIXTURES = path.join(import.meta.dirname, "..", "test", "fixtures");
const DATASET_FILE = process.env["DATASET_FILE"] ?? path.join(FIXTURES, "labeled-dataset-b2.json");

interface ScannedFile { path: string; content: string }
interface Pkg {
    label: "malicious" | "benign";
    name: string;
    version: string;
    scripts: Record<string, string>;
    scannedFiles?: ScannedFile[];
}

const HOOKS = ["preinstall", "install", "postinstall"] as const;

// Step A: missing install-command patterns
const EXTRA_HOOK_PATTERNS: RegExp[] = [
    /\/dev\/(?:tcp|udp)\//,                                   // reverse shell via /dev/tcp
    /\b(?:curl|wget)\b/i,                                     // outbound network call during install
    /[$`]\(?\s*(?:whoami|hostname|id|pwd|uname)\s*\)?/i,      // recon via command substitution
    /\b(?:nslookup|dig|host)\s+\S/i,                          // DNS exfiltration via CLI
    /\bnode\s+(?:--\S+\s+)*-e\b/i,                            // node -e "..."
    /\b(?:sh|bash|zsh)\s+[\w./-]+\.sh\b/i,                    // runs a helper script
];

// Step B: file-content patterns for source code (not shell)
const CONTENT_PATTERNS: RegExp[] = [
    /(?:oastify\.com|oast\.(?:fun|me|online|site)|burpcollaborator|webhook\.site|interact\.sh|requestbin|pipedream\.net)/i,
    /require\(['"](?:node:)?dns['"]\)|\bdns\.(?:lookup|resolve\w*)\s*\(/i,
    /\bos\.(?:hostname|userInfo|networkInterfaces)\s*\(/i,
];

// "Is there anything to detect?" Defined before measuring, not tuned
const TRIVIAL_HOOK = /^(?:test|open\s+\.|true|:)?\s*$/i;
const FUNCTIONAL_API =
    /require\s*\(|import\s+[\w{}, *]+\s+from|\bfetch\s*\(|https?\.(?:get|request)\s*\(|\.exec(?:Sync)?\s*\(|\.spawn(?:Sync)?\s*\(|process\.env|process\.argv|fs\.\w+\s*\(|location\.href|XMLHttpRequest|WebSocket|child_process|eval\s*\(|Function\s*\(/;

function hookText(p: Pkg): string {
    return HOOKS.map(h => p.scripts?.[h] ?? "").filter(Boolean).join("\n");
}
function hasRealHook(p: Pkg): boolean {
    return HOOKS.some(h => {
        const cmd = (p.scripts?.[h] ?? "").trim();
        return cmd !== "" && !TRIVIAL_HOOK.test(cmd);
    });
}
function contentBlob(p: Pkg): string {
    return (p.scannedFiles ?? []).map(f => f.content).join("\n");
}
function isDetectable(p: Pkg): boolean {
    return hasRealHook(p) || FUNCTIONAL_API.test(contentBlob(p));
}

// Detector per configuration
function baselineHit(p: Pkg): boolean {
    const cmd = hookText(p);
    return cmd.trim() !== "" && SUSPICIOUS_COMMAND_PATTERNS.some(({ pattern }) => pattern.test(cmd));
}
function stepAHit(p: Pkg): boolean {
    const cmd = hookText(p);
    return cmd.trim() !== "" && EXTRA_HOOK_PATTERNS.some(rx => rx.test(cmd));
}
function stepBHit(p: Pkg): boolean {
    const blob = contentBlob(p);
    return blob.trim() !== "" && CONTENT_PATTERNS.some(rx => rx.test(blob));
}

interface Config { label: string; detect: (p: Pkg) => boolean }
const CONFIGS: Config[] = [
    { label: "Baseline (CI)", detect: baselineHit },
    { label: "+ Step A (6 install-command patterns)", detect: p => baselineHit(p) || stepAHit(p) },
    { label: "+ Step B (+ 3 content patterns)", detect: p => baselineHit(p) || stepAHit(p) || stepBHit(p) },
];

// Metrics on one set, two denominators
interface Metrics { tp: number; fp: number; tn: number; fn: number; precision: number; recall: number; f1: number; far: number }

function evaluate(pkgs: readonly Pkg[], detect: (p: Pkg) => boolean, onlyDetectable: boolean): Metrics {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (const p of pkgs) {
        if (onlyDetectable && p.label === "malicious" && !isDetectable(p)) continue;
        const hit = detect(p);
        if (p.label === "malicious") hit ? tp++ : fn++;
        else hit ? fp++ : tn++;
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const far = fp + tn > 0 ? fp / (fp + tn) : 0;
    return { tp, fp, tn, fn, precision, recall, f1, far };
}

const pct = (x: number) => (x * 100).toFixed(2) + "%";
function show(label: string, m: Metrics) {
    console.log(
        `  ${label.padEnd(38)} TP=${String(m.tp).padStart(3)} FP=${String(m.fp).padStart(2)} ` +
        `TN=${String(m.tn).padStart(3)} FN=${String(m.fn).padStart(3)}  ` +
        `P=${pct(m.precision).padStart(7)} R=${pct(m.recall).padStart(7)} ` +
        `F1=${pct(m.f1).padStart(7)} FAR=${pct(m.far).padStart(6)}`
    );
}

// Seeded split for a held-out check
function makeRng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
function shuffle<T>(arr: readonly T[], rng: () => number): T[] {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [copy[i], copy[j]] = [copy[j]!, copy[i]!];
    }
    return copy;
}

function main() {
    const dataset = JSON.parse(fs.readFileSync(DATASET_FILE, "utf8")) as { packages: Pkg[] };
    const pkgs = dataset.packages;
    const mal = pkgs.filter(p => p.label === "malicious");
    const ben = pkgs.filter(p => p.label === "benign");
    const detectableMal = mal.filter(isDetectable);

    console.log(`Dataset: ${DATASET_FILE}`);
    console.log(`Malicious: ${mal.length} (detectable: ${detectableMal.length}, undetectable: ${mal.length - detectableMal.length})`);
    console.log(`Benign   : ${ben.length}\n`);

    console.log(`=== All ${mal.length} malicious ===`);
    for (const cfg of CONFIGS) show(cfg.label, evaluate(pkgs, cfg.detect, false));

    console.log("\n=== Detectable subset only ===");
    for (const cfg of CONFIGS) show(cfg.label, evaluate(pkgs, cfg.detect, true));

    // Held-out check
    const rng = makeRng(4242);
    const shuffledMal = shuffle(mal, rng);
    const shuffledBen = shuffle(ben, rng);
    const half = <T,>(a: readonly T[]) => Math.floor(a.length / 2);
    const dev = [...shuffledMal.slice(0, half(shuffledMal)), ...shuffledBen.slice(0, half(shuffledBen))];
    const held = [...shuffledMal.slice(half(shuffledMal)), ...shuffledBen.slice(half(shuffledBen))];

    console.log(`\n=== Held-out check (dev=${dev.length}, held-out=${held.length}), all samples ===`);
    for (const cfg of CONFIGS) {
        console.log(` [DEV]`);
        show(cfg.label, evaluate(dev, cfg.detect, false));
    }
    for (const cfg of CONFIGS) {
        console.log(` [HELD-OUT]`);
        show(cfg.label, evaluate(held, cfg.detect, false));
    }

    const finalConfig = CONFIGS[CONFIGS.length - 1]!;
    const fps = pkgs.filter(p => p.label === "benign" && finalConfig.detect(p)).map(p => p.name);
    console.log(`\nFalse positives of the last configuration (${finalConfig.label}): ${fps.join(", ") || "(none)"}`);
}

main();
