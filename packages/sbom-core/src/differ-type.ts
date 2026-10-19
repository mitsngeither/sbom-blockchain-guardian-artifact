import type { SBOMHash } from "./types";

export type Differ = {
    added: string[];
    changed: {
        key: string;
        changes: ComponentChanges;
    }[];
    removed: string[];
};

export type ComponentChanges = {
    version?: {
        old: string;
        new: string;
    };
    licenseIds?: {
        old: string[];
        new: string[];
    };
    licenseExpressions?: {
        old: string[];
        new: string[];
    };
    hashes?: {
        old: SBOMHash[];
        new: SBOMHash[];
    };
    dependencies?: {
        old: string[];
        new: string[];
    };
};