import { POPULAR_NPM_PACKAGES } from "./data/popular-npm-packages.ts";

export interface TypoMatch {
    referencePackage: string;
    distance: number;
    normalizedDistance: number;
    source: "previous-sbom" | "popular-packages";
}

export interface TypoCheckResult {
    packageName: string;
    normalizedPackageName: string;
    existedPreviously: boolean;
    suspicious: boolean;
    match?: TypoMatch;
}

/**
 * Normalize a package name before comparing.
 *
 * "-" is kept on purpose: dropping it would make "cross-env" and "crossenv"
 * (a real typosquat from 2017) normalize to the same string.
 *
 * Examples:
 * lodash_es   -> lodashes
 * @types/node -> types/node
 */
function normalizePackageName(packageName: string): string {
    return packageName
        .toLowerCase()
        .trim()
        .replace(/^@/, "")
        .replace(/[._]/g, "");
}

/**
 * Levenshtein distance (insert, delete, substitute one character).
 */
export function levenshteinDistance(
    first: string,
    second: string
): number {
    const firstLength = first.length;
    const secondLength = second.length;

    const dp: number[][] = Array.from(
        { length: firstLength + 1 },
        () => Array(secondLength + 1).fill(0)
    );

    for (let i = 0; i <= firstLength; i++) {
        dp[i][0] = i;
    }

    for (let j = 0; j <= secondLength; j++) {
        dp[0][j] = j;
    }

    for (let i = 1; i <= firstLength; i++) {
        for (let j = 1; j <= secondLength; j++) {
            const substitutionCost =
                first[i - 1] === second[j - 1] ? 0 : 1;

            dp[i][j] = Math.min(
                dp[i - 1][j] + 1, // delete
                dp[i][j - 1] + 1, // insert
                dp[i - 1][j - 1] + substitutionCost // replace
            );
        }
    }

    return dp[firstLength][secondLength];
}

interface ClosestPackageMatch {
    referencePackage: string;
    distance: number;
    normalizedDistance: number;
}

/**
 * Closest package name in a reference set.
 */
function findClosestPackage(
    packageName: string,
    referencePackages: readonly string[],
    maxDistance: number,
    maxNormalizedDistance: number
): ClosestPackageMatch | undefined {
    let bestMatch: ClosestPackageMatch | undefined;

    for (const referencePackage of referencePackages) {
        const normalizedReference =
            normalizePackageName(referencePackage);

        if (!normalizedReference) {
            continue;
        }

        // Identical name is not a typo.
        if (normalizedReference === packageName) {
            continue;
        }

        // Length difference alone already exceeds the threshold.
        if (
            Math.abs(
                packageName.length -
                normalizedReference.length
            ) > maxDistance
        ) {
            continue;
        }

        const distance = levenshteinDistance(
            packageName,
            normalizedReference
        );

        if (distance > maxDistance) {
            continue;
        }

        const normalizedDistance =
            distance /
            Math.max(
                packageName.length,
                normalizedReference.length
            );

        if (normalizedDistance > maxNormalizedDistance) {
            continue;
        }

        const currentMatch: ClosestPackageMatch = {
            referencePackage,
            distance,
            normalizedDistance,
        };

        if (
            !bestMatch ||
            currentMatch.distance < bestMatch.distance ||
            (
                currentMatch.distance === bestMatch.distance &&
                currentMatch.normalizedDistance <
                bestMatch.normalizedDistance
            )
        ) {
            bestMatch = currentMatch;
        }
    }

    return bestMatch;
}

/**
 * Typosquatting check.
 *
 * 1. Package already in the previous SBOM: not new, nothing to check.
 * 2. New package: compare against the previous SBOM's packages first.
 * 3. Not close to any of those: compare against the popular-package list.
 */
export function checkPackageTyposquatting(
    packageName: string,
    previousPackageNames: readonly string[],
    popularPackageNames: readonly string[] = POPULAR_NPM_PACKAGES,
    maxDistance = 2,
    maxNormalizedDistance = 0.35
): TypoCheckResult {
    const normalizedName =
        normalizePackageName(packageName);

    if (!normalizedName) {
        throw new Error("Package name is required");
    }

    const existedPreviously = previousPackageNames.some(
        previousPackageName =>
            normalizePackageName(previousPackageName) ===
            normalizedName
    );

    // Already in the previous SBOM; maybe only the version changed.
    if (existedPreviously) {
        return {
            packageName,
            normalizedPackageName: normalizedName,
            existedPreviously: true,
            suspicious: false,
        };
    }

    const isKnownPopularPackage = popularPackageNames.some(
        popularPackageName =>
            normalizePackageName(popularPackageName) ===
            normalizedName
    );

    // An exact reference-set hit is a known package, not a typo of a
    // different nearby package.
    if (isKnownPopularPackage) {
        return {
            packageName,
            normalizedPackageName: normalizedName,
            existedPreviously: false,
            suspicious: false,
        };
    }

    // New package: check the previous SBOM's packages first.
    const previousMatch = findClosestPackage(
        normalizedName,
        previousPackageNames,
        maxDistance,
        maxNormalizedDistance
    );

    if (previousMatch) {
        return {
            packageName,
            normalizedPackageName: normalizedName,
            existedPreviously: false,
            suspicious: true,
            match: {
                ...previousMatch,
                source: "previous-sbom",
            },
        };
    }

    // Not close to any of them: check the popular list.
    const popularMatch = findClosestPackage(
        normalizedName,
        popularPackageNames,
        maxDistance,
        maxNormalizedDistance
    );

    if (popularMatch) {
        return {
            packageName,
            normalizedPackageName: normalizedName,
            existedPreviously: false,
            suspicious: true,
            match: {
                ...popularMatch,
                source: "popular-packages",
            },
        };
    }

    return {
        packageName,
        normalizedPackageName: normalizedName,
        existedPreviously: false,
        suspicious: false,
    };
}
