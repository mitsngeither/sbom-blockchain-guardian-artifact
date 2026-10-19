import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { PipelineReport } from "../../src/detector/detector-pipeline.ts";
import { applyWorkflowPolicy } from "../../src/pipeline/workflow-policy.ts";

function report(
    mode: "incremental" | "full",
    packages: Array<{ name: string; changeType: string; inCooldown: boolean; }>
): PipelineReport {
    return {
        mode,
        packageReports: packages.map(pkg => ({
            changeType: pkg.changeType,
            risk: {
                packageName: pkg.name,
                evidence: [{
                    detector: "cooldown",
                    details: { isInCooldown: pkg.inCooldown, ageDays: pkg.inCooldown ? 0.08 : 900 },
                }],
            },
        })),
        summary: { decision: "PASS", reasons: ["Overall rating LOW maps to policy decision PASS."] },
    } as unknown as PipelineReport;
}

const fresh = { name: "evil-pkg", changeType: "ADDED", inCooldown: true };
const old = { name: "lodash", changeType: "UNCHANGED", inCooldown: false };

describe("applyWorkflowPolicy", () => {
    it("blocks a newly added dependency inside the cooldown window when diffing against a baseline", () => {
        const result = applyWorkflowPolicy(report("incremental", [old, fresh]), {});

        assert.equal(result.summary.decision, "BLOCK");
    });

    it("blocks any in-cooldown dependency on a full scan when strict mode is requested", () => {
        // Without a baseline, new and old cannot be told apart: fail closed.
        const result = applyWorkflowPolicy(
            report("full", [old, fresh]),
            { COOLDOWN_STRICT_WITHOUT_BASELINE: "true" }
        );

        assert.equal(result.summary.decision, "BLOCK");
        assert.match(result.summary.reasons.at(-1) ?? "", /no recorded baseline/i);
    });

    it("passes a strict full scan when nothing is inside the cooldown window", () => {
        const result = applyWorkflowPolicy(
            report("full", [old]),
            { COOLDOWN_STRICT_WITHOUT_BASELINE: "true" }
        );

        assert.equal(result.summary.decision, "PASS");
    });

    it("keeps the first-ever full scan lenient when strict mode is not requested", () => {
        const result = applyWorkflowPolicy(report("full", [old, fresh]), {});

        assert.equal(result.summary.decision, "PASS");
    });

    it("ignores an unchanged in-cooldown dependency when diffing against a baseline", () => {
        const result = applyWorkflowPolicy(
            report("incremental", [{ name: "already-recorded", changeType: "UNCHANGED", inCooldown: true }]),
            {}
        );

        assert.equal(result.summary.decision, "PASS");
    });

    it("can still be disabled explicitly", () => {
        const result = applyWorkflowPolicy(
            report("full", [fresh]),
            { BLOCK_FRESH_DEPENDENCIES: "false", COOLDOWN_STRICT_WITHOUT_BASELINE: "true" }
        );

        assert.equal(result.summary.decision, "PASS");
    });
});
