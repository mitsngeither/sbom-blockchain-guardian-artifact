import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { POPULAR_NPM_PACKAGES } from "../../src/detector/data/popular-npm-packages.ts";
import { checkPackageTyposquatting } from "../../src/detector/typosquat-checker.ts";

describe("POPULAR_NPM_PACKAGES", () => {
    it("contains about one thousand unique package names", () => {
        assert.ok(POPULAR_NPM_PACKAGES.length >= 900);
        assert.ok(POPULAR_NPM_PACKAGES.length <= 1100);
        assert.equal(
            new Set(POPULAR_NPM_PACKAGES).size,
            POPULAR_NPM_PACKAGES.length
        );
    });

    it("covers representative npm ecosystems", () => {
        for (const packageName of [
            "angular",
            "axios",
            "express",
            "lodash",
            "next",
            "react",
            "typescript",
            "vite",
            "vue",
            "webpack",
        ]) {
            assert.ok(
                POPULAR_NPM_PACKAGES.some(
                    referenceName =>
                        referenceName === packageName
                ),
                `missing representative package: ${packageName}`
            );
        }
    });
});

describe("checkPackageTyposquatting", () => {
    it("does not flag an exact popular package name", () => {
        const result = checkPackageTyposquatting("express", []);

        assert.equal(result.suspicious, false);
        assert.equal(result.match, undefined);
    });

    it("flags a nearby popular package and returns distance evidence", () => {
        const result = checkPackageTyposquatting("expresss", []);

        assert.equal(result.suspicious, true);
        assert.equal(result.match?.referencePackage, "express");
        assert.equal(result.match?.distance, 1);
        assert.equal(result.match?.normalizedDistance, 1 / 8);
        assert.equal(result.match?.source, "popular-packages");
    });

    it("prefers a nearby package from the previous SBOM", () => {
        const result = checkPackageTyposquatting(
            "lodahs",
            ["lodash"]
        );

        assert.equal(result.suspicious, true);
        assert.equal(result.match?.referencePackage, "lodash");
        assert.equal(result.match?.source, "previous-sbom");
    });

    it("keeps an unrelated internal package clean", () => {
        const result = checkPackageTyposquatting(
            "company-internal-ledger-adapter",
            []
        );

        assert.equal(result.suspicious, false);
    });

    it("does not treat a hyphen-removal typosquat as the popular package it imitates (CVE-2017 cross-env case)", () => {
        const result = checkPackageTyposquatting("crossenv", []);

        assert.equal(result.suspicious, true);
        assert.equal(result.match?.referencePackage, "cross-env");
    });
});
