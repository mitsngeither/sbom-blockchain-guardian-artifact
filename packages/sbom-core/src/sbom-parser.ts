import { readFileSync } from "fs";
import path from "path";
import type {
    CycloneDXComponent,
    CycloneDXSBOM,
    FlattenedSBOM,
    FlattenedSBOMComponent,
    SBOMHash,
    SBOMLicense,
} from "./types";

// Relative paths resolve against the current working directory.
export async function parseRawSBOM(filePath: string): Promise<FlattenedSBOM> {
    const content = readFileSync(path.resolve(filePath), "utf-8");

    return parseSBOMContent(content);
}

export function parseSBOMContent(content: string): FlattenedSBOM {
    const raw = JSON.parse(content) as CycloneDXSBOM;

    function flattenLicenseIds(licenses?: SBOMLicense[]): string[] {
        if (!licenses) return [];

        const ids = new Set<string>();

        for (const item of licenses) {
            const id = item.license?.id;
            if (id) ids.add(id);
        }

        return [...ids].sort();
    }

    function flattenLicenseExpressions(licenses?: SBOMLicense[]): string[] {
        if (!licenses) return [];

        const expressions = new Set<string>();

        for (const item of licenses) {
            if (item.expression) expressions.add(item.expression);
        }

        return [...expressions].sort();
    }

    function dedupeHashes(hashes: SBOMHash[]): SBOMHash[] {
        const hashMap = new Map<string, SBOMHash>();

        for (const hash of hashes) {
            hashMap.set(`${hash.alg}:${hash.content}`, hash);
        }

        return [...hashMap.values()].sort((a, b) =>
            `${a.alg}:${a.content}`.localeCompare(`${b.alg}:${b.content}`),
        );
    }

    function normalizeComponentKey(component: CycloneDXComponent): string {
        if (component.purl) return component.purl;

        const packageName = component.group
            ? `${component.group}/${component.name}`
            : component.name;

        return `${packageName}@${component.version ?? "N/A"}`;
    }

    function normalizeIdentity(component: CycloneDXComponent): string {
        return component.group
            ? `${component.group}/${component.name}`
            : component.name;
    }

    const dependencyMap = new Map<string, string[]>();

    for (const dep of raw.dependencies ?? []) {
        dependencyMap.set(dep.ref, dep.dependsOn ?? []);
    }

    const rawComponents = [
        ...(raw.metadata?.component ? [raw.metadata.component] : []),
        ...(raw.components ?? []),
    ];

    const components: FlattenedSBOMComponent[] = rawComponents.map((component) => {
        const key = normalizeComponentKey(component);
        const bomRef = component["bom-ref"] ?? key;
        const externalReferences = component.externalReferences ?? [];
        const externalHashes = externalReferences.flatMap((ref) => ref.hashes ?? []);

        return {
            key,
            identity: normalizeIdentity(component),
            bomRef,
            // Leaf fields must be strings. "" rather than "library" so an untyped
            // component is not pulled into the risk scan.
            type: component.type ?? "",
            name: component.name,
            group: component.group,
            version: component.version ?? "N/A",
            purl: component.purl,
            licenseIds: flattenLicenseIds(component.licenses),
            licenseExpressions: flattenLicenseExpressions(component.licenses),
            hashes: dedupeHashes([...(component.hashes ?? []), ...externalHashes]),
            externalUrls: externalReferences.map((ref) => ref.url).filter(Boolean).sort(),
            dependencies: [],
            capabilities: component.capabilities ?? [],
        };
    });

    const componentMap: Record<string, FlattenedSBOMComponent> = {};
    const componentByBomRef: Record<string, FlattenedSBOMComponent> = {};
    const keyByBomRef = new Map<string, string>();

    for (const component of components) {
        componentMap[component.key] = component;
        componentByBomRef[component.bomRef] = component;
        keyByBomRef.set(component.bomRef, component.key);
    }

    for (const component of components) {
        component.dependencies = (dependencyMap.get(component.bomRef) ?? [])
            .map((dependencyRef) => keyByBomRef.get(dependencyRef) ?? dependencyRef)
            .sort();
    }

    return {
        bomFormat: raw.bomFormat,
        specVersion: raw.specVersion,
        version: raw.version,
        serialNumber: raw.serialNumber,
        timestamp: raw.metadata?.timestamp,
        components,
        componentMap,
        componentByBomRef,
    };
}
