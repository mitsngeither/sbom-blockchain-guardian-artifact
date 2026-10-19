"use client";

import { useState } from "react";
import { AlertTriangle, Boxes, CheckCircle2, Code2, ExternalLink, Layers, Play, ShieldX, TerminalSquare, XCircle } from "lucide-react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { NetworkStatus, RunsData } from "./api-data";
import { StatCard, Tag } from "./Primitives";
import { summarizeRuns } from "./run-stats";
import { cx, onchainColor, pipelineStatusColor, policyColor, riskColor, riskLabel, riskScoreText } from "./utils";
import type { FilterKey, PipelineStatus } from "./types";

type PipelineStatusPanelProps = {
  data: RunsData | null;
  isLoading: boolean;
  error: string | null;
  network: NetworkStatus | null;
};

export function PipelineStatusPanel({ data, isLoading, error, network }: PipelineStatusPanelProps) {
  const [filter, setFilter] = useState<FilterKey>("all");
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const filters: { key: FilterKey; label: string; }[] = [
    { key: "all", label: "ALL" },
    { key: "passed", label: "PASSED" },
    { key: "blocked", label: "BLOCKED" },
    { key: "review", label: "REVIEW" },
    { key: "failed", label: "FAILED" },
  ];

  if (isLoading) return <div className="border border-border bg-card p-4 text-md font-mono text-muted-foreground">Loading CI/CD runs...</div>;
  if (error || !data) return <div className="border border-[#ff3d5a44] bg-[#ff3d5a05] p-4 text-md font-mono text-[#ff3d5a]">{error ?? "CI/CD runs unavailable"}</div>;

  const filtered = data.pipelines.filter((p) => filter === "all" ? true : p.status === filter);
  const stats = summarizeRuns(data.pipelines);
  const defaultNotableRun: RunsData["pipelines"][number] | undefined =
    data.pipelines.find((p) => p.policy === "BLOCK" || p.status === "blocked")
    ?? data.pipelines[0];
  const notableRun = (selectedRunId && data.pipelines.find((p) => p.id === selectedRunId)) || defaultNotableRun;
  const blockLogTitle = notableRun
    ? "POLICY EVIDENCE LOG — " + notableRun.id + " / " + notableRun.repo
    : "POLICY EVIDENCE LOG — no runs loaded";
  const contractTarget = network?.contractAddress
    ? network.contractAddress.slice(0, 6) + "..." + network.contractAddress.slice(-4)
    : "Not configured";
  const blockLogText = notableRun
    ? [
      "[pipeline] Project       : " + notableRun.repo,
      "[pipeline] Run ID        : " + notableRun.id,
      "[pipeline] Mode          : " + notableRun.mode,
      "[pipeline] Packages      : " + notableRun.analyzedPackages,
      "[detector] Risk score    : " + riskScoreText(notableRun.risk) + " (" + riskLabel(notableRun.risk) + ")",
      "[policy]   Decision      : " + notableRun.policy,
      "[chain]    Attestation   : " + notableRun.onchain,
      // Receipts do not record the contract address, so this is the registry configured today.
      "[contract] Registry now  : " + contractTarget,
      "[result]   Status        : " + notableRun.status.toUpperCase(),
      ...(notableRun.reasons && notableRun.reasons.length > 0
        ? ["[policy]   Reasons      :", ...notableRun.reasons.map((reason) => "             - " + reason)]
        : []),
    ].join("\n")
    : "No pipeline artifacts were found.";

  const statusIcon = (s: PipelineStatus) => {
    if (s === "passed") return <CheckCircle2 size={13} className="text-[#00ff9d]" />;
    if (s === "blocked") return <ShieldX size={13} className="text-[#ffb300]" />;
    if (s === "failed") return <XCircle size={13} className="text-[#ff3d5a]" />;
    if (s === "review") return <AlertTriangle size={13} className="text-[#ffb300]" />;
    return <Play size={13} className="text-[#00e5ff] animate-pulse" />;
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          label="Pipeline Runs"
          value={String(stats.totalRuns)}
          sub="from pipeline artifacts"
          icon={TerminalSquare}
        />
        <StatCard
          label="Policy Pass Rate"
          value={stats.passRate === null ? "—" : stats.passRate + "%"}
          sub={stats.passRate === null ? "no real runs yet" : stats.passedRuns + "/" + stats.totalRuns + " PASS"}
          icon={CheckCircle2}
          accent="#00ff9d"
          trend={stats.passedRuns > 0 ? "up" : undefined}
        />
        <StatCard
          label="Avg Risk Score"
          value={stats.avgRisk === null ? "—" : String(stats.avgRisk)}
          sub={stats.avgRisk === null ? "no real runs yet" : "computed from real runs"}
          icon={AlertTriangle}
          accent="#ffb300"
        />
        <StatCard
          label="Blocked Runs"
          value={String(stats.blockedRuns)}
          sub={stats.totalRuns === 0 ? "no real runs yet" : notableRun ? notableRun.repo : "none"}
          icon={ShieldX}
          accent="#ff3d5a"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Risk chart + legend */}
        <div className="border border-border bg-card flex flex-col">
          <div className="px-4 py-3 border-b border-border">
            <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">Risk Score — Recent Runs</span>
          </div>
          <div style={{ height: 148 }} className="px-2 pt-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.riskChart} margin={{ top: 4, right: 8, bottom: 0, left: -24 }}>
                <XAxis dataKey="date" tick={{ fontSize: 9, fontFamily: "JetBrains Mono", fill: "#5a6a85" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 9, fontFamily: "JetBrains Mono", fill: "#5a6a85" }} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{ background: "#0d1117", border: "1px solid #1e2a3a", borderRadius: 0, fontFamily: "JetBrains Mono", fontSize: 11 }}
                  labelStyle={{ color: "#5a6a85" }}
                  formatter={(value) => [value, "Risk"]}
                  itemStyle={{ color: "#ffb300" }}
                />
                <Bar dataKey="risk" radius={0}>
                  {data.riskChart.map((point, i) => (
                    <Cell key={i} fill={riskColor(point.risk) + "66"} stroke={riskColor(point.risk)} strokeWidth={1} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          {/* Legend */}
          <div className="px-4 py-2.5 border-t border-border mt-auto">
            <div className="flex items-center gap-4 flex-wrap">
              {[
                { label: "LOW", range: "1–24", color: "#00ff9d" },
                { label: "MEDIUM", range: "25–49", color: "#ffb300" },
                { label: "HIGH", range: "50–74", color: "#ff8a3d" },
                { label: "CRITICAL", range: "75+", color: "#ff3d5a" },
              ].map(({ label, range, color }) => (
                <div key={label} className="flex items-center gap-1.5">
                  <div className="size-1.5" style={{ background: color }} />
                  <span className="text-[9px] font-mono font-bold tracking-widest" style={{ color }}>{label}</span>
                  <span className="text-[9px] font-mono text-muted-foreground">{range}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Run table */}
        <div className="md:col-span-2 border border-border bg-card">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border gap-3 flex-wrap">
            <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">CI/CD Runs</span>
            <div className="flex gap-1.5 flex-wrap">
              {filters.map(({ key, label }) => (
                <button key={key} onClick={() => setFilter(key)}
                  className={cx(
                    "px-2.5 py-1 text-[10px] font-mono tracking-widest uppercase border transition-colors",
                    filter === key
                      ? "border-[#00e5ff] text-[#00e5ff] bg-[#00e5ff11]"
                      : "border-border text-muted-foreground hover:border-[#1e3a4a]"
                  )}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <div className="divide-y divide-border">
            {filtered.map((p) => {
              const isSelected = p.id === notableRun?.id;
              return (
              <div
                key={p.id}
                role="button"
                aria-pressed={isSelected}
                // Not a toggle: with nothing selected the panel shows the default run, often this same row.
                onClick={() => setSelectedRunId(p.id)}
                className={cx(
                  "px-4 py-3 transition-colors cursor-pointer border-l-2",
                  isSelected
                    ? "bg-[#00e5ff12] border-l-[#00e5ff] shadow-[inset_0_0_0_1px_#00e5ff55]"
                    : "border-l-transparent opacity-60 hover:opacity-100 hover:bg-secondary/30"
                )}>
                {/* Top row: icon + run ID + project + mode + commit + package count */}
                <div className="flex items-center gap-3 flex-wrap">
                  {statusIcon(p.status)}
                  <span className={cx("text-md font-mono min-w-[120px] whitespace-nowrap", isSelected && "font-bold")} style={{ color: pipelineStatusColor(p.status) }}>
                    {p.id}
                  </span>
                  {isSelected && <Tag color="#00e5ff">VIEWING</Tag>}
                  <span className="text-md font-mono text-foreground min-w-[90px] flex-1">{p.repo}</span>
                  <div className="flex items-center gap-3 text-[10px] font-mono text-muted-foreground flex-wrap">
                    <span className="flex items-center gap-1" title="Analysis mode"><Layers size={9} />{p.mode}</span>
                    <span className="flex items-center gap-1"><Code2 size={9} />{p.commit}</span>
                    <span className="flex items-center gap-1" title="Packages analyzed"><Boxes size={9} />{p.analyzedPackages} pkgs</span>
                    {p.runUrl && (
                      <a
                        href={p.runUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="flex items-center gap-1 text-[#00e5ff] hover:underline"
                      >
                        <ExternalLink size={9} />
                        CI run
                      </a>
                    )}
                  </div>
                </div>
                {/* Bottom row: policy + on-chain + risk */}
                <div className="flex items-center gap-4 mt-2 pl-[22px] flex-wrap">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[9px] font-mono tracking-widest text-muted-foreground uppercase">Policy</span>
                    <Tag color={policyColor(p.policy)}>{p.policy}</Tag>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[9px] font-mono tracking-widest text-muted-foreground uppercase">On-chain</span>
                    <Tag color={onchainColor(p.onchain)}>{p.onchain}</Tag>
                  </div>
                  <div className="flex items-center gap-1.5 ml-auto">
                    <span className="text-[10px] font-mono font-bold" style={{ color: riskColor(p.risk) }}>
                      {riskLabel(p.risk)}
                    </span>
                    <div className="w-14 h-1 bg-border relative">
                      <div className="absolute inset-y-0 left-0 transition-all"
                        style={{ width: `${Math.max(0, p.risk)}%`, background: riskColor(p.risk) }} />
                    </div>
                    <span className="text-[10px] font-mono text-muted-foreground w-5 text-right">{riskScoreText(p.risk)}</span>
                  </div>
                </div>
              </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Block log */}
      <div className="border border-[#00e5ff55] bg-[#ffb30005]">
        <div className="flex items-center justify-between gap-2 px-4 py-2.5 border-b border-[#ffb30022]">
          <div className="flex items-center gap-2">
            <ShieldX size={12} className="text-[#ffb300]" />
            <span className="text-md font-mono text-[#ffb300] tracking-widest">{blockLogTitle}</span>
          </div>
          {notableRun?.runUrl && (
            <a
              href={notableRun.runUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-[10px] font-mono tracking-widest uppercase text-[#00e5ff] hover:underline"
            >
              View CI run
              <ExternalLink size={10} />
            </a>
          )}
        </div>
        <pre className="px-4 py-3 text-md font-mono text-muted-foreground leading-relaxed overflow-x-auto whitespace-pre">{blockLogText}</pre>
      </div>
    </div>
  );
}
