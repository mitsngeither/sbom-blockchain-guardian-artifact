// Compare two SBOMs by component key:
//   only in new -> added, only in old -> removed,
//   in both with a different version or hash -> changed
import type { ComponentChanges, Differ } from "./differ-type";
import { mappingComponents, sameHashArray, sameStringArray } from "./sbom-utils";
import type { FlattenedSBOM } from "./types";


export function compareSBOMs(s1: FlattenedSBOM, s2: FlattenedSBOM): Differ {
    if (!s1
        || !s2
        || !Object.keys(s1).length
        || !Object.keys(s2).length) throw new Error("sbom1 or sbom2 is not object");
    const s1Map = mappingComponents(s1);
    const s2Map = mappingComponents(s2);
    const merged = new Map([...s1Map.entries(), ...s2Map.entries()]);
    const keys = merged.keys();
    const changed = [],
        removed = [],
        added = [];

    for (const i of keys) {
        const oldComponent = s1Map.get(i);
        const newComponent = s2Map.get(i);

        if (oldComponent && newComponent) {
            const changes: ComponentChanges = {};

            if (oldComponent.version !== newComponent.version) {
                changes.version = {
                    old: oldComponent.version,
                    new: newComponent.version,
                };
            }

            if (!sameStringArray(oldComponent.licenseIds, newComponent.licenseIds)) {
                changes.licenseIds = {
                    old: oldComponent.licenseIds,
                    new: newComponent.licenseIds,
                };
            }
            if (!sameStringArray(oldComponent.licenseExpressions, newComponent.licenseExpressions)) {
                changes.licenseExpressions = {
                    old: oldComponent.licenseExpressions,
                    new: newComponent.licenseExpressions,
                };
            }
            if (!sameHashArray(oldComponent.hashes, newComponent.hashes)) {
                changes.hashes = {
                    old: oldComponent.hashes,
                    new: newComponent.hashes,
                };
            }
            if (!sameStringArray(oldComponent.dependencies, newComponent.dependencies)) {
                changes.dependencies = {
                    old: oldComponent.dependencies,
                    new: newComponent.dependencies,
                };
            }

            if (Object.keys(changes).length > 0) {
                changed.push({
                    key: i,
                    changes
                });
            }
        } else if (oldComponent && !newComponent) {
            removed.push(i);
        } else if (newComponent) {
            added.push(i);
        }
    }
    return {
        changed: changed.sort((a, b) => a.key.localeCompare(b.key)),
        removed: removed.sort(),
        added: added.sort()
    };
}


