#!/usr/bin/env tsx
/**
 * Recall on the "core" malicious set. Samples are dropped for two reasons only,
 * decided before looking at detector output: research PoCs (bug-bounty canary
 * domains or researcher signatures) and samples with nothing to detect (no real
 * install command, no file using a general-purpose API).
 *
 * DATASET_FILE=test/fixtures/labeled-dataset-primary-eval.json npx tsx scripts/evaluate-detector-core.ts
 */

import fs from "node:fs";
import path from "node:path";

import { SUSPICIOUS_COMMAND_PATTERNS } from "../src/detector/data/suspicious-patterns.ts";

const DATASET_FILE = process.env["DATASET_FILE"]
    ?? path.join(import.meta.dirname, "..", "test", "fixtures", "labeled-dataset-frozen-eval.json");

interface ScannedFile { path: string; content: string }
interface Pkg {
    label: "malicious" | "benign";
    name: string;
    version: string;
    scripts: Record<string, string>;
    scannedFiles?: ScannedFile[];
}

const HOOKS = ["preinstall", "install", "postinstall"] as const;
function hookText(p: Pkg): string {
    return HOOKS.map(h => p.scripts?.[h] ?? "").filter(Boolean).join("\n");
}
function contentBlob(p: Pkg): string {
    return (p.scannedFiles ?? []).map(f => f.content).join("\n");
}
function fullText(p: Pkg): string {
    return hookText(p) + "\n" + contentBlob(p);
}

// 1. PoC filter (the single definition)
const POC_PATTERN =
    /(oastify\.com|oast\.(?:fun|me|online|site)|burpcollaborator|webhook\.site|interact\.sh|requestbin|pipedream\.net|canarytokens|hackerone|bugcrowd|bug\s*bounty|security\s+research|responsible\s+disclos|this\s+package\s+is\s+reserved|proof\s+of\s+concept|\bpoc\b)/i;
const DNS_CANARY_ONLY = /dns\.(?:lookup|resolve)\w*\s*\(\s*['"][a-z0-9]{20,}\./i;

function isResearchPoc(p: Pkg): boolean {
    return POC_PATTERN.test(fullText(p)) || DNS_CANARY_ONLY.test(fullText(p));
}

// 2. "Anything to detect" filter (same rule as decided before measuring)
const TRIVIAL_HOOK = /^(?:test|open\s+\.|true|:)?\s*$/i;
const FUNCTIONAL_API =
    /require\s*\(|import\s+[\w{}, *]+\s+from|\bfetch\s*\(|https?\.(?:get|request)\s*\(|\.exec(?:Sync)?\s*\(|\.spawn(?:Sync)?\s*\(|process\.env|process\.argv|fs\.\w+\s*\(|location\.href|XMLHttpRequest|WebSocket|child_process|eval\s*\(|Function\s*\(/;

function hasRealHook(p: Pkg): boolean {
    return HOOKS.some(h => {
        const cmd = (p.scripts?.[h] ?? "").trim();
        return cmd !== "" && !TRIVIAL_HOOK.test(cmd);
    });
}
function isEmptySample(p: Pkg): boolean {
    return !hasRealHook(p) && !FUNCTIONAL_API.test(contentBlob(p));
}

// Detector: 3 configurations, offline only, src/detector/data untouched
const EXTRA_HOOK_PATTERNS: RegExp[] = [
    /\/dev\/(?:tcp|udp)\//, /\b(?:curl|wget)\b/i,
    /[$`]\(?\s*(?:whoami|hostname|id|pwd|uname)\s*\)?/i,
    /\b(?:nslookup|dig|host)\s+\S/i, /\bnode\s+(?:--\S+\s+)*-e\b/i,
    /\b(?:sh|bash|zsh)\s+[\w./-]+\.sh\b/i,
];
const CONTENT_PATTERNS: RegExp[] = [
    /(?:oastify\.com|oast\.(?:fun|me|online|site)|burpcollaborator|webhook\.site|interact\.sh|requestbin|pipedream\.net)/i,
    /require\(['"](?:node:)?dns['"]\)|\bdns\.(?:lookup|resolve\w*)\s*\(/i,
    /\bos\.(?:hostname|userInfo|networkInterfaces)\s*\(/i,
];
function baselineHit(p: Pkg): boolean {
    const c = hookText(p);
    return c.trim() !== "" && SUSPICIOUS_COMMAND_PATTERNS.some(({ pattern }) => pattern.test(c));
}
function stepAHit(p: Pkg): boolean {
    const c = hookText(p);
    return c.trim() !== "" && EXTRA_HOOK_PATTERNS.some(rx => rx.test(c));
}
function stepBHit(p: Pkg): boolean {
    const b = contentBlob(p);
    return b.trim() !== "" && CONTENT_PATTERNS.some(rx => rx.test(b));
}
const CONFIGS: { label: string; detect: (p: Pkg) => boolean }[] = [
    { label: "Baseline (CI)", detect: baselineHit },
    { label: "+ Step A (hook patterns)", detect: p => baselineHit(p) || stepAHit(p) },
    { label: "+ Step B (content patterns)", detect: p => baselineHit(p) || stepAHit(p) || stepBHit(p) },
];

function main() {
    const dataset = JSON.parse(fs.readFileSync(DATASET_FILE, "utf8")) as { packages: Pkg[] };
    const mal = dataset.packages.filter(p => p.label === "malicious");

    const poc = mal.filter(isResearchPoc);
    const nonPoc = mal.filter(p => !isResearchPoc(p));
    const empty = nonPoc.filter(isEmptySample);
    const core = nonPoc.filter(p => !isEmptySample(p));

    console.log(`Dataset: ${DATASET_FILE}`);
    console.log(`Malicious total         : ${mal.length}`);
    console.log(`  - research PoC        : ${poc.length}`);
    console.log(`  - empty (non-PoC)     : ${empty.length}`);
    console.log(`  = core                : ${core.length}  (${(100 * core.length / mal.length).toFixed(1)}% of ${mal.length})\n`);

    const pct = (x: number) => (x * 100).toFixed(2) + "%";
    function row(label: string, group: Pkg[]) {
        const c = group.filter(cfg.detect).length;
        console.log(`  ${label.padEnd(30)} ${String(c).padStart(4)}/${String(group.length).padStart(4)}  = ${pct(c / group.length)}`);
    }

    let cfg: { label: string; detect: (p: Pkg) => boolean };
    for (cfg of CONFIGS) {
        console.log(`\n[${cfg.label}]`);
        row("All", mal);
        row("Research PoC", poc);
        row("Empty (not in core)", empty);
        row("Core", core);
    }
}

main();
