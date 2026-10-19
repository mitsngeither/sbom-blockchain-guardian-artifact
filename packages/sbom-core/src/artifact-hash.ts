import crypto from "node:crypto";

interface DistInfo {
    tarball: string;
    integrity?: string;
}

interface NpmRegistryResponse {
    versions?: Record<string, { dist?: DistInfo; }>;
}

async function fetchNpmMetadata(pkgName: string): Promise<NpmRegistryResponse> {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
    const response = await fetch(url, {
        headers: { Accept: "application/json", "User-Agent": "sbom-guardian/1.0" },
    });
    if (!response.ok) {
        throw new Error(`Failed to fetch npm package "${pkgName}": ${response.status}`);
    }
    return response.json() as Promise<NpmRegistryResponse>;
}

export async function computeArtifactHash(
    pkgName: string,
    version: string
): Promise<{ artifactHash: string; npmIntegrity?: string; integrityMatches?: boolean; }> {
    const meta = await fetchNpmMetadata(pkgName);
    const versionData = meta.versions?.[version];

    if (!versionData?.dist?.tarball) {
        throw new Error(`No tarball found for ${pkgName}@${version}`);
    }

    const tarballRes = await fetch(versionData.dist.tarball);
    const buffer = Buffer.from(await tarballRes.arrayBuffer());

    const artifactHash = "0x" + crypto.createHash("sha256").update(buffer).digest("hex");
    const npmIntegrity = versionData.dist.integrity;
    const integrityMatches = npmIntegrity?.startsWith("sha512-")
        ? crypto.createHash("sha512").update(buffer).digest("base64") === npmIntegrity.slice(7)
        : undefined;

    return { artifactHash, npmIntegrity, integrityMatches };
}