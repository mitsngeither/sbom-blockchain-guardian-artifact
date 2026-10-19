#!/usr/bin/env tsx
/**
 * Samples malicious npm packages from the DataDog dataset that were never used
 * to design a detection pattern (names in labeled-dataset.json, the earlier
 * development set, are excluded if that file exists). Includes 100
 * compromised_lib samples. The output is evaluated once and not tuned against.
 *
 * DATASET_DIR=<dataset>/samples/npm npx tsx scripts/build-frozen-holdout.ts
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

const DATASET_DIR: string = process.env["DATASET_DIR"] ?? "";
if (!DATASET_DIR) {
    throw new Error("Set DATASET_DIR to the DataDog dataset's samples/npm folder");
}
const OUTPUT_FILE = process.env["OUT"]
    ?? path.join(import.meta.dirname, "..", "test", "fixtures", "labeled-dataset-frozen-holdout.json");
const EXISTING_FILES = [
    path.join(import.meta.dirname, "..", "test", "fixtures", "labeled-dataset.json"),
];

const TARGET_MALICIOUS_INTENT = Number(process.env["TARGET_MI"] ?? 300);
const TARGET_COMPROMISED_LIB = Number(process.env["TARGET_CL"] ?? 100);
const SEED = Number(process.env["SEED"] ?? 90210);

const MAX_CHARS_PER_FILE = 5000;
const MAX_FILES_PER_PACKAGE = 40;
const MAX_TOTAL_CHARS_PER_PACKAGE = 200_000;

const SAFE_PKG_FIELDS = [
    "name", "version", "description",
    "scripts", "dependencies", "devDependencies",
    "peerDependencies", "license", "author",
    "keywords", "engines",
] as const;

interface ScannedFile { path: string; content: string }
interface LabeledPackage {
    label: "malicious";
    source: "datadog-malicious-intent" | "datadog-compromised-lib";
    name: string;
    version: string;
    scripts: Record<string, string>;
    dependencies: string[];
    hasPrePostInstall: boolean;
    hasExternalDownload: boolean;
    hasProcessEnv: boolean;
    rawPackageJson: Record<string, unknown> | null;
    mainFileContent: string | null;
    scannedFiles: ScannedFile[];
}

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

function safeParseJson(content: string): Record<string, unknown> | null {
    try {
        const parsed = JSON.parse(content);
        if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
            return parsed as Record<string, unknown>;
        }
        return null;
    } catch {
        return null;
    }
}

function extractScripts(pkg: Record<string, unknown>): Record<string, string> {
    const scripts = pkg["scripts"];
    if (typeof scripts !== "object" || scripts === null || Array.isArray(scripts)) return {};
    const result: Record<string, string> = {};
    for (const [k, v] of Object.entries(scripts)) {
        if (typeof v === "string") result[k] = v;
    }
    return result;
}
function extractDependencies(pkg: Record<string, unknown>): string[] {
    const deps: string[] = [];
    for (const field of ["dependencies", "devDependencies", "peerDependencies"]) {
        const d = pkg[field];
        if (typeof d === "object" && d !== null && !Array.isArray(d)) deps.push(...Object.keys(d));
    }
    return [...new Set(deps)];
}
function analyzeScripts(scripts: Record<string, string>) {
    const allScriptText = Object.values(scripts).join(" ");
    return {
        hasPrePostInstall: "preinstall" in scripts || "postinstall" in scripts || "install" in scripts,
        hasExternalDownload: /curl|wget|fetch\(|http:\/\/|https:\/\//i.test(allScriptText),
        hasProcessEnv: /process\.env/.test(allScriptText),
    };
}

function findZipForPackage(baseDir: string, packageName: string): { zipPath: string; version: string } | null {
    const packageDir = path.join(baseDir, packageName);
    if (!fs.existsSync(packageDir)) return null;
    const versions = fs.readdirSync(packageDir).filter(v =>
        fs.statSync(path.join(packageDir, v)).isDirectory()
    );
    if (versions.length === 0) return null;
    const version = versions[0]!;
    const versionDir = path.join(packageDir, version);
    const zips = fs.readdirSync(versionDir).filter(f => f.endsWith(".zip"));
    if (zips.length === 0) return null;
    return { zipPath: path.join(versionDir, zips[0]!), version };
}

function listAllFiles(zipPath: string): string[] {
    try {
        const out = execFileSync("unzip", ["-P", "infected", "-l", zipPath], {
            encoding: "utf8", timeout: 15_000, maxBuffer: 32 * 1024 * 1024,
        });
        return out.split("\n").map(l => l.trim().split(/\s+/).pop() ?? "").filter(Boolean);
    } catch {
        return [];
    }
}

function extractOne(zipPath: string, filePath: string, tmpDir: string): string | null {
    try {
        execFileSync("unzip", ["-P", "infected", "-o", zipPath, filePath, "-d", tmpDir], {
            timeout: 15_000, maxBuffer: 16 * 1024 * 1024,
        });
        const extracted = path.join(tmpDir, filePath);
        if (!fs.existsSync(extracted)) return null;
        return fs.readFileSync(extracted, "utf8");
    } catch {
        return null;
    } finally {
        const top = filePath.split("/")[0];
        if (top) fs.rmSync(path.join(tmpDir, top), { recursive: true, force: true });
    }
}

function processPackage(
    subDir: "malicious_intent" | "compromised_lib",
    packageName: string,
    tmpDir: string
): LabeledPackage | null {
    const baseDir = path.join(DATASET_DIR, subDir);
    const found = findZipForPackage(baseDir, packageName);
    if (!found) return null;

    const allFiles = listAllFiles(found.zipPath);
    const pkgJsonPath = allFiles.find(f => /\/package\/package\.json$/.test(f) && !f.includes("node_modules"));
    if (!pkgJsonPath) return null;

    const pkgJsonContent = extractOne(found.zipPath, pkgJsonPath, tmpDir);
    if (!pkgJsonContent) return null;
    const pkg = safeParseJson(pkgJsonContent);
    if (!pkg) return null;

    const scripts = extractScripts(pkg);
    const flags = analyzeScripts(scripts);

    const jsFiles = allFiles
        .filter(f => /\/package\/.*\.(js|cjs|mjs)$/.test(f) && !f.includes("node_modules"))
        .slice(0, MAX_FILES_PER_PACKAGE);

    const scannedFiles: ScannedFile[] = [];
    let totalChars = 0;
    for (const filePath of jsFiles) {
        if (totalChars >= MAX_TOTAL_CHARS_PER_PACKAGE) break;
        const content = extractOne(found.zipPath, filePath, tmpDir);
        if (content === null) continue;
        const truncated = content.length > MAX_CHARS_PER_FILE
            ? content.slice(0, MAX_CHARS_PER_FILE) + "\n/* ...truncated... */"
            : content;
        scannedFiles.push({ path: filePath, content: truncated });
        totalChars += truncated.length;
    }

    return {
        label: "malicious",
        source: subDir === "malicious_intent" ? "datadog-malicious-intent" : "datadog-compromised-lib",
        name: (pkg["name"] as string | undefined) ?? packageName,
        version: found.version,
        scripts,
        dependencies: extractDependencies(pkg),
        ...flags,
        rawPackageJson: Object.fromEntries(SAFE_PKG_FIELDS.filter(f => f in pkg).map(f => [f, pkg[f]])),
        mainFileContent: scannedFiles[0]?.content ?? null,
        scannedFiles,
    };
}

function sampleFromDir(
    subDir: "malicious_intent" | "compromised_lib",
    target: number,
    excluded: ReadonlySet<string>,
    rng: () => number,
    tmpDir: string
): LabeledPackage[] {
    const baseDir = path.join(DATASET_DIR, subDir);
    const allNames = fs.readdirSync(baseDir).filter(n => !excluded.has(n));
    const shuffled = shuffle(allNames, rng);

    const results: LabeledPackage[] = [];
    let attempts = 0;
    for (const name of shuffled) {
        if (results.length >= target) break;
        attempts++;
        const pkg = processPackage(subDir, name, tmpDir);
        if (pkg) results.push(pkg);
        if (attempts % 100 === 0) {
            console.log(`  [${subDir}] ${attempts} tried, ${results.length}/${target} ok`);
        }
    }
    console.log(`  [${subDir}] done: ${results.length}/${target} (${attempts} tried, pool=${allNames.length})`);
    return results;
}

async function main() {
    console.log("=== build-frozen-holdout.ts ===");
    console.log(`Target malicious_intent : ${TARGET_MALICIOUS_INTENT}`);
    console.log(`Target compromised_lib  : ${TARGET_COMPROMISED_LIB}`);
    console.log(`Seed                    : ${SEED}\n`);

    const excluded = new Set<string>();
    for (const file of EXISTING_FILES) {
        if (!fs.existsSync(file)) continue;
        const existing = JSON.parse(fs.readFileSync(file, "utf8")) as {
            packages: { label: string; name: string }[];
        };
        for (const p of existing.packages) {
            if (p.label === "malicious") excluded.add(p.name);
        }
    }
    console.log(`Excluded ${excluded.size} names used in the earlier dataset.\n`);

    const rng = makeRng(SEED);
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "frozen-holdout-"));

    console.log("[1/2] compromised_lib...");
    const compromisedLib = sampleFromDir("compromised_lib", TARGET_COMPROMISED_LIB, excluded, rng, tmpDir);

    console.log("\n[2/2] malicious_intent...");
    const maliciousIntent = sampleFromDir("malicious_intent", TARGET_MALICIOUS_INTENT, excluded, rng, tmpDir);

    fs.rmSync(tmpDir, { recursive: true, force: true });

    const packages = shuffle([...compromisedLib, ...maliciousIntent], rng);
    const withContent = packages.filter(p => p.scannedFiles.length > 0).length;

    const dataset = {
        generatedAt: new Date().toISOString(),
        note:
            "Frozen hold-out: never used to design patterns or inspected by hand. " +
            "Evaluate once with evaluate-detector-ablation.ts; do not tune " +
            "patterns against it.",
        excludedFrom: EXISTING_FILES,
        seed: SEED,
        counts: {
            maliciousIntent: maliciousIntent.length,
            compromisedLib: compromisedLib.length,
            total: packages.length,
            withScannedContent: withContent,
        },
        packages,
    };

    fs.mkdirSync(path.dirname(OUTPUT_FILE), { recursive: true });
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(dataset, null, 2), "utf8");

    console.log("\n=== XONG ===");
    console.log(`malicious_intent  : ${maliciousIntent.length}/${TARGET_MALICIOUS_INTENT}`);
    console.log(`compromised_lib   : ${compromisedLib.length}/${TARGET_COMPROMISED_LIB}`);
    console.log(`Total             : ${packages.length}`);
    console.log(`With file content : ${withContent}`);
    console.log(`Output            : ${OUTPUT_FILE}`);
}

main().catch(err => {
    console.error("FATAL:", err);
    process.exit(1);
});
