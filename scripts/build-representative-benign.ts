#!/usr/bin/env tsx
/**
 * Benign set: every package in this project's node_modules/.pnpm, unfiltered,
 * i.e. what the detector sees in CI. Scripts and .js/.cjs/.mjs files are
 * extracted the same way as for the malicious set (nested node_modules skipped).
 *
 * npx tsx scripts/build-representative-benign.ts
 */

import fs from "node:fs";
import path from "node:path";

const PNPM_STORE = process.env["PNPM_STORE"]
    ?? path.join(import.meta.dirname, "..", "node_modules", ".pnpm");
const OUTPUT_FILE = process.env["OUT"]
    ?? path.join(import.meta.dirname, "..", "test", "fixtures", "benign-representative.json");

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
    label: "benign";
    source: "local-pnpm-store-representative";
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

function safeParseJson(content: string): Record<string, unknown> | null {
    try {
        const parsed = JSON.parse(content);
        return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
            ? (parsed as Record<string, unknown>) : null;
    } catch {
        return null;
    }
}
function extractScripts(pkg: Record<string, unknown>): Record<string, string> {
    const scripts = pkg["scripts"];
    if (typeof scripts !== "object" || scripts === null || Array.isArray(scripts)) return {};
    const result: Record<string, string> = {};
    for (const [k, v] of Object.entries(scripts)) if (typeof v === "string") result[k] = v;
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

/** Each .pnpm/<name>@<version>/node_modules/<name>/ is one package root. */
function findPackageRoot(storeEntry: string): string | null {
    const nmDir = path.join(PNPM_STORE, storeEntry, "node_modules");
    if (!fs.existsSync(nmDir)) return null;
    const names = fs.readdirSync(nmDir).filter(n => !n.startsWith("."));
    // Prefer a non-scoped directory; descend into @scope below if needed.
    for (const name of names) {
        if (name.startsWith("@")) {
            const scoped = fs.readdirSync(path.join(nmDir, name));
            for (const s of scoped) {
                const p = path.join(nmDir, name, s);
                if (fs.existsSync(path.join(p, "package.json"))) return p;
            }
        } else {
            const p = path.join(nmDir, name);
            if (fs.existsSync(path.join(p, "package.json"))) return p;
        }
    }
    return null;
}

function listJsFiles(root: string): string[] {
    const out: string[] = [];
    function walk(dir: string, depth: number) {
        if (depth > 6) return;
        let entries: fs.Dirent[];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
            if (e.name === "node_modules" || e.name.startsWith(".")) continue;
            const full = path.join(dir, e.name);
            if (e.isDirectory()) walk(full, depth + 1);
            else if (/\.(js|cjs|mjs)$/.test(e.name)) out.push(full);
        }
    }
    walk(root, 0);
    return out;
}

function processPackage(storeEntry: string): LabeledPackage | null {
    const root = findPackageRoot(storeEntry);
    if (!root) return null;

    let pkgJsonContent: string;
    try {
        pkgJsonContent = fs.readFileSync(path.join(root, "package.json"), "utf8");
    } catch {
        return null;
    }
    const pkg = safeParseJson(pkgJsonContent);
    if (!pkg) return null;

    const name = (pkg["name"] as string | undefined) ?? storeEntry;
    const version = (pkg["version"] as string | undefined) ?? "unknown";
    const scripts = extractScripts(pkg);
    const flags = analyzeScripts(scripts);

    const jsFiles = listJsFiles(root).slice(0, MAX_FILES_PER_PACKAGE);
    const scannedFiles: ScannedFile[] = [];
    let totalChars = 0;
    for (const filePath of jsFiles) {
        if (totalChars >= MAX_TOTAL_CHARS_PER_PACKAGE) break;
        let content: string;
        try { content = fs.readFileSync(filePath, "utf8"); } catch { continue; }
        const truncated = content.length > MAX_CHARS_PER_FILE
            ? content.slice(0, MAX_CHARS_PER_FILE) + "\n/* ...truncated... */"
            : content;
        scannedFiles.push({ path: path.relative(root, filePath), content: truncated });
        totalChars += truncated.length;
    }

    return {
        label: "benign",
        source: "local-pnpm-store-representative",
        name,
        version,
        scripts,
        dependencies: extractDependencies(pkg),
        ...flags,
        rawPackageJson: Object.fromEntries(SAFE_PKG_FIELDS.filter(f => f in pkg).map(f => [f, pkg[f]])),
        mainFileContent: scannedFiles[0]?.content ?? null,
        scannedFiles,
    };
}

async function main() {
    console.log("=== build-representative-benign.ts ===");
    console.log(`Source: ${PNPM_STORE}\n`);

    if (!fs.existsSync(PNPM_STORE)) {
        throw new Error(`pnpm store not found: ${PNPM_STORE}`);
    }

    const entries = fs.readdirSync(PNPM_STORE).filter(n => !n.startsWith("."));
    console.log(`Entries in pnpm store: ${entries.length}`);
    console.log(`No filtering, no sampling: taking everything.\n`);

    const packages: LabeledPackage[] = [];
    let skipped = 0;

    for (const [i, entry] of entries.entries()) {
        const pkg = processPackage(entry);
        if (pkg) packages.push(pkg);
        else skipped++;
        if ((i + 1) % 300 === 0) {
            console.log(`  ${i + 1}/${entries.length} (kept: ${packages.length})`);
        }
    }

    const withHook = packages.filter(p => p.hasPrePostInstall).length;
    const withContent = packages.filter(p => p.scannedFiles.length > 0).length;

    const dataset = {
        generatedAt: new Date().toISOString(),
        note:
            "Representative benign set: the project's whole dependency tree " +
            "(node_modules/.pnpm), unfiltered. Used for the false-alarm rate " +
            "at the real operating point.",
        source: PNPM_STORE,
        counts: {
            total: packages.length,
            skipped,
            withInstallHook: withHook,
            withScannedContent: withContent,
        },
        packages,
    };

    fs.mkdirSync(path.dirname(OUTPUT_FILE), { recursive: true });
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(dataset, null, 2), "utf8");

    console.log("\n=== XONG ===");
    console.log(`Packages            : ${packages.length}`);
    console.log(`Skipped (read error): ${skipped}`);
    console.log(`With install hook   : ${withHook}  (${(100 * withHook / packages.length).toFixed(1)}%)`);
    console.log(`With file content   : ${withContent}  (${(100 * withContent / packages.length).toFixed(1)}%)`);
    console.log(`Output               : ${OUTPUT_FILE}`);
}

main().catch(err => {
    console.error("FATAL:", err);
    process.exit(1);
});
