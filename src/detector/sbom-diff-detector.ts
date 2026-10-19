import { compareSBOMs } from "@guardian/sbom-core";
import { mappingComponents } from "@guardian/sbom-core";
import type {
    FlattenedSBOM,
    FlattenedSBOMComponent,
} from "@guardian/sbom-core";

export type PackageChangeType = "ADDED" | "CHANGED" | "REMOVED";

export interface PackageChange {
    type: PackageChangeType;
    packageName: string;
    purl?: string;
    previousVersion?: string;
    currentVersion?: string;
    previousComponent?: FlattenedSBOMComponent;
    currentComponent?: FlattenedSBOMComponent;
}

export interface SBOMChangeReport {
    added: PackageChange[];
    changed: PackageChange[];
    removed: PackageChange[];
}

function isLibrary(
    component: FlattenedSBOMComponent | undefined
): component is FlattenedSBOMComponent {
    return component?.type === "library";
}

function sortChanges(changes: PackageChange[]): PackageChange[] {
    return changes.sort((first, second) =>
        first.packageName.localeCompare(second.packageName)
    );
}

function addedChange(
    component: FlattenedSBOMComponent
): PackageChange {
    return {
        type: "ADDED",
        packageName: component.identity,
        purl: component.purl,
        currentVersion: component.version,
        currentComponent: component,
    };
}

export function detectSBOMChanges(
    previousSbom: FlattenedSBOM | undefined,
    currentSbom: FlattenedSBOM
): SBOMChangeReport {
    if (!previousSbom) {
        return {
            added: sortChanges(
                currentSbom.components
                    .filter(isLibrary)
                    .map(addedChange)
            ),
            changed: [],
            removed: [],
        };
    }

    const diff = compareSBOMs(previousSbom, currentSbom);
    const previousComponents = mappingComponents(previousSbom);
    const currentComponents = mappingComponents(currentSbom);

    const added = diff.added.flatMap(key => {
        const currentComponent = currentComponents.get(key);
        return isLibrary(currentComponent)
            ? [addedChange(currentComponent)]
            : [];
    });

    const changed = diff.changed.flatMap(({ key }) => {
        const previousComponent = previousComponents.get(key);
        const currentComponent = currentComponents.get(key);

        if (!isLibrary(currentComponent)) {
            return [];
        }

        return [{
            type: "CHANGED" as const,
            packageName: currentComponent.identity,
            purl: currentComponent.purl,
            previousVersion: previousComponent?.version,
            currentVersion: currentComponent.version,
            previousComponent,
            currentComponent,
        }];
    });

    const removed = diff.removed.flatMap(key => {
        const previousComponent = previousComponents.get(key);

        if (!isLibrary(previousComponent)) {
            return [];
        }

        return [{
            type: "REMOVED" as const,
            packageName: previousComponent.identity,
            purl: previousComponent.purl,
            previousVersion: previousComponent.version,
            previousComponent,
        }];
    });

    return {
        added: sortChanges(added),
        changed: sortChanges(changed),
        removed: sortChanges(removed),
    };
}
