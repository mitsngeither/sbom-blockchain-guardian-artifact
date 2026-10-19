import { mkdir, readdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

export const HISTORY_RETENTION = 50;
const SHORT_SHA_LENGTH = 7;

export interface RunHistoryEnvelope {
    runId: string;
    commit: string;
    timestamp: string;
}

// Entries carry their own commit and run id.
export function buildRunHistoryEnvelope(
    now: Date = new Date()
): RunHistoryEnvelope {
    const timestamp = now.toISOString();
    const githubRunId = process.env.GITHUB_RUN_ID?.trim();
    const attempt = process.env.GITHUB_RUN_ATTEMPT?.trim() || "1";
    const sha = process.env.GITHUB_SHA?.trim();

    const localId =
        "local-" +
        timestamp.replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");

    return {
        runId: githubRunId ? `${githubRunId}-${attempt}` : localId,
        commit: sha ? sha.slice(0, SHORT_SHA_LENGTH) : "local",
        timestamp,
    };
}

export function historyDirFor(reportPath: string): string {
    return path.join(path.dirname(reportPath), "history");
}

export async function writeRunHistoryEntry(
    reportPath: string,
    report: unknown,
    envelope: RunHistoryEnvelope
): Promise<string> {
    const directory = historyDirFor(reportPath);
    const entryPath = path.join(directory, `${envelope.runId}.json`);

    await mkdir(directory, { recursive: true });
    await writeFile(
        entryPath,
        JSON.stringify({ ...(report as object), ...envelope }, null, 2) + "\n",
        "utf8"
    );

    return entryPath;
}

async function entryTimestamp(
    directory: string,
    fileName: string
): Promise<string> {
    try {
        const parsed = JSON.parse(
            await readFile(path.join(directory, fileName), "utf8")
        ) as { timestamp?: unknown };

        return typeof parsed.timestamp === "string" ? parsed.timestamp : "";
    } catch {
        // Corrupt entries sort oldest, so retention removes them first.
        return "";
    }
}

export async function pruneRunHistory(
    historyDir: string,
    keep: number = HISTORY_RETENTION
): Promise<void> {
    let files: string[];

    try {
        files = (await readdir(historyDir)).filter(name =>
            name.endsWith(".json")
        );
    } catch {
        return;
    }

    if (files.length <= keep) {
        return;
    }

    const dated = await Promise.all(
        files.map(async name => ({
            name,
            timestamp: await entryTimestamp(historyDir, name),
        }))
    );

    dated.sort((left, right) =>
        left.timestamp === right.timestamp
            ? left.name.localeCompare(right.name)
            : left.timestamp.localeCompare(right.timestamp)
    );

    await Promise.all(
        dated
            .slice(0, dated.length - keep)
            .map(entry => unlink(path.join(historyDir, entry.name)))
    );
}
