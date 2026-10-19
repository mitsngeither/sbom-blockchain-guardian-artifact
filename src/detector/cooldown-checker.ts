const NPM_REGISTRY_URL = "https://registry.npmjs.org";
const MS_PER_DAY = 24 * 60 * 60 * 1000;

export interface NpmPackageMetadata {
    name: string;
    versions?: Record<string, unknown>;
    time?: Record<string, string>;
    "dist-tags"?: Record<string, string>;
}

export interface CooldownResult {
    publishedAt: string;
    ageDays: number;
    cooldownDays: number;
    isInCooldown: boolean;
}

export async function getPackageDetail(pkgName: string): Promise<NpmPackageMetadata> {
    const url = `${NPM_REGISTRY_URL}/${encodeURIComponent(pkgName)}`;

    const response = await fetch(url, {
        method: "GET",
        headers: {
            Accept: "application/json",
            "User-Agent": "sbom-handler/1.0",
        },
    });

    if (response.status === 404) {
        throw new Error(`Package not found: ${pkgName}`);
    }

    if (!response.ok) {
        throw new Error(
            `Failed to fetch npm package "${pkgName}": ${response.status} ${response.statusText}`
        );
    }

    return response.json() as Promise<NpmPackageMetadata>;
}

export function calculateCooldown(
    publishedAt: string,
    cooldownDays = 30,
    now = new Date()
): CooldownResult {
    const publishedTime = new Date(publishedAt).getTime();

    if (Number.isNaN(publishedTime)) {
        throw new Error(`Invalid published date: ${publishedAt}`);
    }

    const ageDays = (now.getTime() - publishedTime) / MS_PER_DAY;

    return {
        publishedAt,
        ageDays,
        cooldownDays,
        isInCooldown: ageDays < cooldownDays,
    };
}

export async function checkCooldown(
    pkgName: string,
    version: string,
    cooldownDays = 30
): Promise<CooldownResult> {
    const pkgDetail = await getPackageDetail(pkgName);
    const publishedAt = pkgDetail.time?.[version];

    if (!publishedAt) {
        throw new Error(`Version not found: ${pkgName}@${version}`);
    }

    return calculateCooldown(publishedAt, cooldownDays);
}

export async function isInCooldown(
    pkgName: string,
    version: string,
    cooldownDays = 30
): Promise<boolean> {
    const result = await checkCooldown(pkgName, version, cooldownDays);
    return result.isInCooldown;
}

