import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const WORKFLOW_PATH =
    ".github/workflows/sbom-blockchain-guardian.yaml";

async function workflow(): Promise<string> {
    return readFile(WORKFLOW_PATH, "utf8");
}

describe("Phase 4 GitHub Actions workflow contract", () => {
    it("generates TypeChain contract types before TypeScript checking", async () => {
        const packageJson = JSON.parse(
            await readFile("package.json", "utf8")
        ) as { scripts?: Record<string, string>; };
        const build = packageJson.scripts?.build ?? "";

        assert.match(build, /hardhat compile/);
        assert.match(build, /tsc --noEmit/);
        assert.ok(
            build.indexOf("hardhat compile") < build.indexOf("tsc --noEmit"),
            "hardhat compile must run before tsc --noEmit"
        );
    });

    it("builds the shared sbom-core package before type-checking against it", async () => {
        const packageJson = JSON.parse(
            await readFile("package.json", "utf8")
        ) as { scripts?: Record<string, string>; };
        const build = packageJson.scripts?.build ?? "";

        // tsc resolves @guardian/sbom-core through its dist/*.d.ts.
        assert.match(build, /@guardian\/sbom-core run build/);
        assert.ok(
            build.indexOf("@guardian/sbom-core") < build.indexOf("tsc --noEmit"),
            "sbom-core must be built before tsc --noEmit"
        );
    });

    it("defines a deterministic Phase 4 test script for CI", async () => {
        const packageJson = JSON.parse(
            await readFile("package.json", "utf8")
        ) as { scripts?: Record<string, string>; };

        assert.match(
            packageJson.scripts?.["test:phase4"] ?? "",
            /node --import=tsx --test/
        );
        assert.match(
            packageJson.scripts?.["test:phase4"] ?? "",
            /test\/pipeline\/workflow-contract\.test\.ts/
        );
        assert.match(
            packageJson.scripts?.["test:phase4"] ?? "",
            /test\/pipeline\/prepare-submission\.test\.ts/
        );
    });

    it("uses the generic guardian Hardhat network contract", async () => {
        const packageJson = JSON.parse(
            await readFile("package.json", "utf8")
        ) as { scripts?: Record<string, string>; };
        const hardhatConfig = await readFile(
            "hardhat.config.ts",
            "utf8"
        );
        const submitScript = await readFile(
            "scripts/pipeline-submit.ts",
            "utf8"
        );

        assert.equal(
            packageJson.scripts?.["pipeline:submit"],
            "hardhat run scripts/pipeline-submit.ts --network guardian"
        );
        assert.match(hardhatConfig, /guardian:\s*\{/);
        assert.match(
            hardhatConfig,
            /configVariable\("RPC_URL"\)/
        );
        assert.match(
            hardhatConfig,
            /configVariable\("PRIVATE_KEY"\)/
        );
        assert.doesNotMatch(submitScript, /SEPOLIA_/);
        assert.match(submitScript, /requireEnv\("RPC_URL"\)/);
        assert.match(
            submitScript,
            /requireEnv\("PRIVATE_KEY"\)/
        );
    });

    it("runs build, deterministic tests, SBOM diff analysis, artifact upload, and policy gate", async () => {
        const source = await workflow();

        for (const requiredText of [
            "risk-analysis:",
            "pnpm --filter=!\"UI SBOM Blockchain Guardian\" run build",
            "pnpm run build",
            "pnpm run test:phase4",
            "pnpm sbom --sbom-format cyclonedx --lockfile-only",
            "pnpm run sbom:merkle",
            "pipeline-artifacts/merkle/current-proof.json",
            "pipeline-artifacts",
            "pnpm --dir previous-source sbom",
            "pnpm run pipeline:risk",
            "actions/upload-artifact@v4",
            "Policy gate",
            "steps.risk.outputs.decision",
        ]) {
            assert.ok(
                source.includes(requiredText),
                `workflow is missing: ${requiredText}`
            );
        }

        assert.doesNotMatch(source, /cyclonedx-npm/);
        assert.doesNotMatch(
            source,
            /pnpm run pipeline:risk --/
        );
    });

    it("commits no private key, not even a throwaway devnet one", async () => {
        // The devnet key comes from DEVNET_PRIVATE_KEY.
        const hardhatConfig = await readFile("hardhat.config.ts", "utf8");
        const runnerDocs = await readFile(
            "docs/self-hosted-runner-setup.md",
            "utf8"
        );
        const privateKeyLiteral = /["'`]0x[0-9a-fA-F]{64}["'`]/;

        assert.doesNotMatch(hardhatConfig, privateKeyLiteral);
        assert.doesNotMatch(runnerDocs, /0x[0-9a-fA-F]{64}/);
        assert.match(hardhatConfig, /process\.env\.DEVNET_PRIVATE_KEY/);
    });

    it("type-checks the workspace root, which a --filter run always skips", async () => {
        const source = await workflow();

        // A --filter build never includes the workspace root.
        assert.match(
            source,
            /^\s*pnpm run build$/m,
            "workflow must invoke the root build so src/, scripts/ and test/ are type-checked"
        );
    });

    it("isolates blockchain secrets in a trusted PASS-only submit job", async () => {
        const source = await workflow();
        const submitJobIndex = source.indexOf("  submit-chain:");

        assert.ok(submitJobIndex > 0, "submit-chain job is missing");
        const analysisSection = source.slice(0, submitJobIndex);
        const submitSection = source.slice(submitJobIndex);

        assert.doesNotMatch(analysisSection, /secrets\./);
        assert.match(submitSection, /needs: risk-analysis/);
        assert.match(submitSection, /needs\.risk-analysis\.outputs\.decision == 'PASS'/);
        assert.match(submitSection, /github\.event_name == 'workflow_dispatch'/);
        assert.match(submitSection, /actions\/download-artifact@v4/);
        assert.match(submitSection, /pnpm run pipeline:propose-approve/);
        assert.match(
            submitSection,
            /runs-on: \[self-hosted, linux, x64, sbom-guardian\]/
        );

        for (const secret of [
            "CONTRACT_ADDRESS",
            "SEPOLIA_RPC_URL",
            "SEPOLIA_PRIVATE_KEY",
            "REVIEWER_1_KEY",
            "REVIEWER_2_KEY",
        ]) {
            assert.ok(
                submitSection.includes(
                    secret + ": " +
                    "${{ secrets." + secret + " }}"
                ),
                `submit job is missing secret reference: ${secret}`
            );
        }

    });

    it("diffs a dispatch against the last recorded commit, and fails closed without one", async () => {
        const source = await workflow();
        const analysis = source.slice(0, source.indexOf("  submit-chain:"));
        const baseline = analysis.slice(
            analysis.indexOf("id: baseline"),
            analysis.indexOf("- name: Checkout baseline revision")
        );

        // The last successful dispatch is the last recorded SBOM.
        assert.match(baseline, /"workflow_dispatch"/);
        assert.match(baseline, /event=workflow_dispatch&status=success/);
        assert.match(baseline, /head_sha/);
        assert.match(baseline, /GH_TOKEN: \$\{\{ github\.token \}\}/);
        // Re-dispatching the recorded commit must not diff it against itself.
        assert.match(baseline, /"\$BASE_SHA" != "\$GITHUB_SHA"/);

        // Fall back to a strict scan if the baseline cannot be checked out.
        assert.match(
            analysis,
            /- name: Checkout baseline revision\s*\n\s*id: baseline_checkout\s*\n\s*continue-on-error: true/
        );
        assert.match(analysis, /steps\.baseline_checkout\.outcome == 'success'/);

        // No baseline on a dispatch: block any in-cooldown dependency.
        const risk = analysis.slice(analysis.indexOf("id: risk"));
        assert.match(
            risk,
            /"\$EVENT_NAME" == "workflow_dispatch" && "\$PREVIOUS_SBOM" == "none"[\s\S]*?export COOLDOWN_STRICT_WITHOUT_BASELINE=true/
        );
    });

    it("exercises both recording paths on Sepolia, EIP-712 after the threshold path", async () => {
        const source = await workflow();
        const submitSection = source.slice(source.indexOf("  submit-chain:"));
        const packageJson = JSON.parse(
            await readFile("package.json", "utf8")
        ) as { scripts?: Record<string, string>; };

        assert.equal(
            packageJson.scripts?.["pipeline:submit:sepolia"],
            "hardhat run scripts/pipeline-submit.ts --network sepolia"
        );

        const threshold = submitSection.indexOf("pnpm run pipeline:propose-approve");
        const eip712 = submitSection.indexOf("pnpm run pipeline:submit:sepolia");

        assert.ok(eip712 > 0, "submit job does not run the EIP-712 path");
        // Sequential: both paths sign with the same key and would race on the nonce.
        assert.ok(threshold > 0 && eip712 > threshold, "EIP-712 path must run after the threshold path");
        // A separate tag keeps the two records and receipts apart.
        assert.match(submitSection.slice(threshold, source.length), /SUBMISSION_TAG: eip712/);
        // pipeline-submit.ts reads generic names; map them to the Sepolia secrets.
        assert.match(submitSection, /RPC_URL: \$\{\{ secrets\.SEPOLIA_RPC_URL \}\}/);
        assert.match(submitSection, /PRIVATE_KEY: \$\{\{ secrets\.SEPOLIA_PRIVATE_KEY \}\}/);
        // An EIP-712 failure must not hide a successful threshold record.
        assert.match(
            submitSection,
            /if: always\(\) && steps\.threshold\.outcome == 'success'\s*\n\s*run: \|\s*\n[\s\S]*?rsync/
        );
    });

    it("runs the full threshold sequence inside the submit script, in order", async () => {
        // Check the on-chain call order inside the script, not just that it runs.
        const script = await readFile(
            "scripts/pipeline-propose-approve.ts",
            "utf8"
        );
        const steps = [
            /const threshold = 2;/,
            /\.proposeSBOM\(/,
            /\.connect\(reviewer1\)\.approveSBOM\(proposalId\)/,
            /\.connect\(reviewer2\)\.approveSBOM\(proposalId\)/,
            /\.executeProposal\(proposalId\)/,
            /\.verifySBOM\(/,
            /if \(!verified\)\s*\{?\s*throw/,
            /writeChainReceipt\(/,
        ];
        let previous = -1;

        for (const step of steps) {
            const index = script.search(step);
            assert.ok(index >= 0, `submit script is missing step: ${step}`);
            assert.ok(index > previous, `submit script step out of order: ${step}`);
            previous = index;
        }
    });

    it("gives the submit job every config variable the sepolia network requires", async () => {
        const source = await workflow();
        const submitSection = source.slice(source.indexOf("  submit-chain:"));
        const hardhatConfig = await readFile("hardhat.config.ts", "utf8");
        const networkStart = hardhatConfig.indexOf("sepolia: {");
        const sepolia = hardhatConfig.slice(
            networkStart,
            hardhatConfig.indexOf("\n    },", networkStart)
        );
        const names = [...sepolia.matchAll(/configVariable\("([A-Z0-9_]+)"\)/g)]
            .map(match => match[1]);

        assert.ok(names.length > 0, "sepolia network has no config variables");

        // Hardhat resolves every configVariable up front, so any the job does not
        // set fails the run. Variables read via process.env are optional.
        for (const name of names) {
            if (sepolia.includes(`process.env.${name}`)) continue;
            assert.ok(
                submitSection.includes(name + ": " + "${{ secrets." + name + " }}"),
                `submit job does not provide required config variable: ${name}`
            );
        }
    });

    it("publishes run history on every event, not only dispatched PASS runs", async () => {
        const content = await workflow();

        assert.match(content, /publish-history:/);

        const job = content.slice(content.indexOf("publish-history:"));

        // Body of publish-history: up to the next top-level job, or end of file.
        const nextJobMatch = job.slice(1).match(/\n {2}[A-Za-z0-9_-]+:/);
        const endOffset = nextJobMatch ? 1 + job.slice(1).indexOf(nextJobMatch[0]) : job.length;
        const body = job.slice(0, endOffset);

        // submit-chain only runs on a PASS dispatch, so BLOCK and push runs need
        // their own path to the dashboard.
        assert.ok(
            !/decision == 'PASS'/.test(body),
            "publish-history must not inherit submit-chain's PASS gate"
        );
        assert.ok(
            !/workflow_dispatch/.test(body),
            "publish-history must not inherit submit-chain's dispatch-only gate"
        );
        assert.match(
            body,
            /if: always\(\) && needs\.risk-analysis\.result != 'cancelled'/,
            "publish-history must run on every event except cancelled risk-analysis"
        );
        // History must accumulate: no --delete.
        assert.ok(
            !/rsync\s+.*--delete/.test(body),
            "publish-history rsync must not delete existing history"
        );
        assert.match(body, /needs: risk-analysis/);
        assert.match(body, /risk\/history\//);
        assert.match(body, /self-hosted/);

        // Retention is enforced on the deployment directory, where history accumulates.
        assert.match(
            body,
            /[Pp]rune/,
            "publish-history must prune the deployment history directory"
        );
        assert.match(
            body,
            /\b50\b/,
            "publish-history must enforce the 50-entry retention limit"
        );
    });

    it("installs dependencies safely with bounded network retries", async () => {
        const source = await workflow();
        const workspace = await readFile(
            "pnpm-workspace.yaml",
            "utf8"
        );
        const installs = source.match(/pnpm install[^\n]*/g) ?? [];

        assert.ok(installs.length >= 2);
        assert.ok(installs.every(command =>
            command.includes("--ignore-scripts") &&
            command.includes("--prefer-offline")
        ));

        for (const requiredSetting of [
            "fetchTimeout: 120000",
            "fetchRetries: 2",
            "fetchRetryMaxtimeout: 30000",
            "networkConcurrency: 8",
        ]) {
            assert.ok(
                workspace.includes(requiredSetting),
                `pnpm workspace is missing: ${requiredSetting}`
            );
        }
    });
});
