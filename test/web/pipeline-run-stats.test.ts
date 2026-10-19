import assert from "node:assert/strict";
import test from "node:test";

import {
  chartLabel,
  summarizeRuns,
} from "../../apps/web/src/app/components/run-stats.ts";
import type { PipelineRun } from "../../apps/web/src/app/components/api-data.ts";

function run(overrides: Partial<PipelineRun>): PipelineRun {
  return {
    id: "1-1",
    repo: "sbom-blockchain-guardian",
    mode: "full",
    commit: "702fa42",
    status: "passed",
    analyzedPackages: 1214,
    risk: 7,
    policy: "PASS",
    onchain: "REGISTERED",
    timestamp: "2026-08-26T09:42:18.000Z",
    ...overrides,
  };
}

test("statistics summarize pass rate and average risk across real runs", () => {
  const stats = summarizeRuns([
    run({ id: "1-1", risk: 7, policy: "PASS", status: "passed" }),
    run({ id: "2-1", risk: 3, policy: "BLOCK", status: "blocked" }),
  ]);

  assert.equal(stats.totalRuns, 2);
  assert.equal(stats.passedRuns, 1);
  assert.equal(stats.blockedRuns, 1);
  assert.equal(stats.passRate, 50);
  assert.equal(stats.avgRisk, 5);
});

// REVIEW counts toward totalRuns and avgRisk, but is neither passed nor blocked.
test("a REVIEW run counts in totalRuns and avgRisk but not passedRuns or blockedRuns", () => {
  const stats = summarizeRuns([
    run({ id: "1-1", risk: 10, policy: "PASS", status: "passed" }),
    run({ id: "2-1", risk: 40, policy: "REVIEW", status: "review" }),
  ]);

  assert.equal(stats.totalRuns, 2);
  assert.equal(stats.passedRuns, 1);
  assert.equal(stats.blockedRuns, 0);
  assert.equal(stats.avgRisk, 25);
});

test("statistics report null rather than zero when no run exists", () => {
  const stats = summarizeRuns([]);

  assert.equal(stats.totalRuns, 0);
  assert.equal(stats.passRate, null);
  assert.equal(stats.avgRisk, null);
});

// FAILED counts toward totalRuns but its sentinel 0 does not enter avgRisk.
test("a FAILED run counts in totalRuns but is excluded from avgRisk", () => {
  const stats = summarizeRuns([
    run({ id: "1-1", risk: 20, policy: "PASS", status: "passed" }),
    run({ id: "2-1", risk: 0, policy: "FAILED", status: "failed" }),
  ]);

  assert.equal(stats.totalRuns, 2);
  assert.equal(stats.avgRisk, 20);
});

test("avgRisk is null when every run is unscored", () => {
  const stats = summarizeRuns([run({ id: "1-1", risk: 0, policy: "FAILED", status: "failed" })]);

  assert.equal(stats.totalRuns, 1);
  assert.equal(stats.avgRisk, null);
});

test("chart labels use the run timestamp, not its position", () => {
  assert.equal(chartLabel("2026-08-26T09:42:18.000Z", 0), "08-26 09:42");
});

test("chart labels fall back to a positional label when a timestamp is missing", () => {
  assert.equal(chartLabel("", 2), "Run 3");
});
