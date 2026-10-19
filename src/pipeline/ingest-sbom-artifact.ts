export interface IngestSbomArtifactInput {
    projectId: string;
    version: string;
    sbomContent: string;
    riskScore: number;
    commit?: string;
    txHash: string;
}

/**
 * Stores a reference copy of a submitted SBOM through POST /sbom/ingest so
 * the Verify page can find it. Best effort: failures only log a warning.
 */
export async function ingestSbomArtifact(
    input: IngestSbomArtifactInput,
    apiUrl = process.env.API_URL ?? "http://localhost:5006",
): Promise<void> {
    try {
        const response = await fetch(`${apiUrl}/api/sbom/ingest`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            signal: AbortSignal.timeout(10_000),
            body: JSON.stringify({
                projectId: input.projectId,
                version: input.version,
                sbomContent: input.sbomContent,
                riskScore: input.riskScore,
                commit: input.commit,
                txHash: input.txHash,
            }),
        });

        if (response.ok) {
            console.log(`Stored SBOM artifact reference copy for ${input.projectId}@${input.version}`);
        } else {
            console.warn(
                `Could not store SBOM artifact reference copy: ${response.status} ${response.statusText}`,
            );
        }
    } catch (error) {
        console.warn(
            "Could not store SBOM artifact reference copy: " +
            (error instanceof Error ? error.message : String(error)),
        );
    }
}
