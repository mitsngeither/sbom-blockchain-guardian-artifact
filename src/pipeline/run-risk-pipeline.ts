import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import {
    runDetectorPipeline,
    type PipelineReport,
    type PolicyDecision,
} from "../detector/detector-pipeline.ts";
import { parseRawSBOM } from "@guardian/sbom-core";
import { applyWorkflowPolicy } from "./workflow-policy.ts";
import type { FlattenedSBOM } from "@guardian/sbom-core";
import {
    buildRunHistoryEnvelope,
    historyDirFor,
    pruneRunHistory,
    writeRunHistoryEntry,
} from "./run-history.ts";

interface CliArguments {
    currentSbomPath: string;
    previousSbomPath?: string;
    reportPath: string;
}

interface PipelineOutputs {
    score: number;
    rating: string;
    decision: PolicyDecision;
    analyzedPackages: number;
    skippedPackages: number;
}

function parseArguments(): CliArguments {
    const currentSbomPath = process.argv[2];
    const previousArg = process.argv[3];
    const reportPath =
        process.argv[4] ??
        "pipeline-artifacts/risk/risk-report.json";

    if (!currentSbomPath) {
        throw new Error(
            "Usage: pipeline:risk <current-sbom> " +
            "[previous-sbom|none] [report-path]"
        );
    }

    return {
        currentSbomPath,
        previousSbomPath:
            previousArg && previousArg !== "none"
                ? previousArg
                : undefined,
        reportPath,
    };
}

async function readProjectMetadata(): Promise<{
    projectId: string;
    version: string;
}> {
    const packageJsonContent = await readFile(
        "package.json",
        "utf8"
    );

    const packageJson = JSON.parse(packageJsonContent) as {
        name?: string;
        version?: string;
    };

    if (!packageJson.name?.trim()) {
        throw new Error("package.json is missing project name");
    }

    if (!packageJson.version?.trim()) {
        throw new Error("package.json is missing project version");
    }

    return {
        projectId: packageJson.name,
        version: packageJson.version,
    };
}

function excludeSelfComponent(
    sbom: FlattenedSBOM,
    projectId: string
): FlattenedSBOM {
    return {
        ...sbom,
        components: sbom.components.filter(
            component => component.identity !== projectId
        ),
    };
}

function highestRiskScore(report: PipelineReport): number {
    return report.packageReports.reduce(
        (highest, packageReport) =>
            Math.max(
                highest,
                packageReport.risk.riskScore
            ),
        0
    );
}

async function writeGithubOutputs(
    outputs: PipelineOutputs
): Promise<void> {
    const githubOutput = process.env.GITHUB_OUTPUT;

    if (!githubOutput) {
        return;
    }

    await writeFile(
        githubOutput,
        [
            `score=${outputs.score}`,
            `rating=${outputs.rating}`,
            `decision=${outputs.decision}`,
            `analyzed_packages=${outputs.analyzedPackages}`,
            `skipped_packages=${outputs.skippedPackages}`,
        ].join("\n") + "\n",
        {
            flag: "a",
        }
    );
}

async function main(): Promise<void> {
    const args = parseArguments();
    const project = await readProjectMetadata();

    const currentSbom = excludeSelfComponent(
        await parseRawSBOM(args.currentSbomPath),
        project.projectId
    );

    const previousSbom = args.previousSbomPath
        ? excludeSelfComponent(
            await parseRawSBOM(args.previousSbomPath),
            project.projectId
        )
        : undefined;

    const rawReport = await runDetectorPipeline({
        projectId: project.projectId,
        previousVersion: previousSbom
            ? "previous-commit"
            : undefined,
        currentVersion: project.version,
        previousSbom,
        currentSbom,
        mode: previousSbom
            ? "incremental"
            : "full",
    });

    const report = applyWorkflowPolicy(rawReport);
    const score = highestRiskScore(report);

    await mkdir(path.dirname(args.reportPath), {
        recursive: true,
    });

    const envelope = buildRunHistoryEnvelope();
    const stampedReport = { ...report, ...envelope };

    await writeFile(
        args.reportPath,
        JSON.stringify(stampedReport, null, 2),
        "utf8"
    );

    await writeRunHistoryEntry(args.reportPath, report, envelope);
    await pruneRunHistory(historyDirFor(args.reportPath));

    await writeGithubOutputs({
        score,
        rating: report.summary.overallRating,
        decision: report.summary.decision,
        analyzedPackages:
            report.summary.analyzedPackages,
        skippedPackages:
            report.summary.skippedPackages,
    });

    console.log("");
    console.log("=== SBOM RISK PIPELINE RESULT ===");
    console.log(
        `Mode: ${report.mode}`
    );
    console.log(
        `Analyzed packages: ` +
        report.summary.analyzedPackages
    );
    console.log(
        `Skipped packages: ` +
        report.summary.skippedPackages
    );
    console.log(`Highest risk score: ${score}`);
    console.log(
        `Overall rating: ${report.summary.overallRating}`
    );
    console.log(
        `Policy decision: ${report.summary.decision}`
    );

    for (const reason of report.summary.reasons) {
        console.log(`- ${reason}`);
    }

    const notableReports = report.packageReports.filter(
        packageReport =>
            packageReport.risk.riskScore === score ||
            packageReport.risk.rating !== "LOW"
    );

    if (notableReports.length > 0) {
        console.log("");
        console.log("Notable packages:");

        for (const packageReport of notableReports) {
            console.log(
                `- ${packageReport.changeType}: ` +
                `${packageReport.risk.packageName}` +
                `@${packageReport.risk.version} ` +
                `score=${packageReport.risk.riskScore} ` +
                `rating=${packageReport.risk.rating}`
            );
        }
    }
}

main().catch((error: unknown) => {
    console.error(
        error instanceof Error
            ? error.message
            : String(error)
    );

    process.exit(1);
});
