import type { FlattenedSBOM, FlattenedSBOMComponent, SBOMHash } from "./types";

function getMatchKey(component: FlattenedSBOMComponent): string {
    if (component.purl) return stripPurlVersion(component.purl);

    return component.identity;
}

function stripPurlVersion(purl: string): string {
    const lastAtIndex = purl.lastIndexOf('@');
    return lastAtIndex > "pkg:npm/".length ? purl.slice(0, lastAtIndex) : purl;
}

function mappingComponents(sbom: FlattenedSBOM) {
    const map = new Map<string, FlattenedSBOMComponent>;

    for (const component of sbom.components) {
        map.set(getMatchKey(component), component);
    }
    return map;
}

function sameStringArray(a: string[], b: string[]): boolean {
    return a.length === b.length && a.every((value, index) => value === b[index]);
}

function sameHashArray(a: SBOMHash[], b: SBOMHash[]): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
}

export {
    mappingComponents,
    sameStringArray,
    sameHashArray,
};