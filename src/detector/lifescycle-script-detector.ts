import { SUSPICIOUS_COMMAND_PATTERNS } from "./data/suspicious-patterns.ts";

export interface NpmPackageVersionMetadata {
    name: string;
    version?: string;
    description?: string;
    license?: string;
    scripts?: Record<string, string>;
}

export type LifecycleScriptName =
    | "preinstall"
    | "install"
    | "postinstall";

export interface LifecycleScriptResult {
    scriptName: LifecycleScriptName;
    exists: boolean;
    command?: string;
    suspicious: boolean;
    matchedPatterns: string[];
}

export interface LifecycleScriptsCheckResult {
    packageName: string;
    version: string;
    hasLifecycleScripts: boolean;
    hasSuspiciousScripts: boolean;
    scripts: Record<LifecycleScriptName, LifecycleScriptResult>;
}

const NPM_REGISTRY_URL = "https://registry.npmjs.org";

export async function getPackageDetail(
    pkgName: string,
    version: string
): Promise<NpmPackageVersionMetadata> {
    if (!pkgName.trim()) {
        throw new Error("Package name is required");
    }

    if (!version.trim()) {
        throw new Error("Package version is required");
    }

    const encodedPackageName = encodeURIComponent(pkgName);
    const encodedVersion = encodeURIComponent(version);

    const url =
        `${NPM_REGISTRY_URL}/${encodedPackageName}/${encodedVersion}`;

    const response = await fetch(url, {
        method: "GET",
        headers: {
            Accept: "application/json",
            "User-Agent": "sbom-handler/1.0",
        },
    });

    if (response.status === 404) {
        throw new Error(`Package not found: ${pkgName}@${version}`);
    }

    if (!response.ok) {
        throw new Error(
            `Failed to fetch npm package "${pkgName}@${version}": ` +
            `${response.status} ${response.statusText}`
        );
    }

    return response.json() as Promise<NpmPackageVersionMetadata>;
}

export function detectSuspiciousCommandPatterns(
    command: string
): string[] {
    return SUSPICIOUS_COMMAND_PATTERNS
        .filter(({ pattern }) => pattern.test(command))
        .map(({ id }) => id);
}

export function detectLifecycleScript(
    scripts: Record<string, string> | undefined,
    scriptName: LifecycleScriptName
): LifecycleScriptResult {
    const command = scripts?.[scriptName]?.trim();

    if (!command) {
        return {
            scriptName,
            exists: false,
            suspicious: false,
            matchedPatterns: [],
        };
    }

    const matchedPatterns =
        detectSuspiciousCommandPatterns(command);

    return {
        scriptName,
        exists: true,
        command,
        suspicious: matchedPatterns.length > 0,
        matchedPatterns,
    };
}

export function detectLifecycleScripts(
    scripts: Record<string, string> | undefined
): Record<LifecycleScriptName, LifecycleScriptResult> {
    return {
        preinstall: detectLifecycleScript(
            scripts,
            "preinstall"
        ),
        install: detectLifecycleScript(
            scripts,
            "install"
        ),
        postinstall: detectLifecycleScript(
            scripts,
            "postinstall"
        ),
    };
}

export async function checkLifecycleScripts(
    pkgName: string,
    version: string
): Promise<LifecycleScriptsCheckResult> {
    const pkgDetail = await getPackageDetail(pkgName, version);

    const scripts = detectLifecycleScripts(pkgDetail.scripts);

    const scriptResults = Object.values(scripts);

    return {
        packageName: pkgDetail.name,
        version: pkgDetail.version ?? version,
        hasLifecycleScripts: scriptResults.some(
            result => result.exists
        ),
        hasSuspiciousScripts: scriptResults.some(
            result => result.suspicious
        ),
        scripts,
    };
}

export async function hasLifecycleScripts(
    pkgName: string,
    version: string
): Promise<boolean> {
    const result = await checkLifecycleScripts(
        pkgName,
        version
    );

    return result.hasLifecycleScripts;
}

export async function hasSuspiciousLifecycleScripts(
    pkgName: string,
    version: string
): Promise<boolean> {
    const result = await checkLifecycleScripts(
        pkgName,
        version
    );

    return result.hasSuspiciousScripts;
}
