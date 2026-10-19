"use client";

import { useState } from "react";
import { CheckCircle2, ChevronRight, Database, GitCommit, MinusCircle, ShieldCheck, Timer, XCircle } from "lucide-react";

import { buildSbomEvidenceEntries, type SbomHistoryData, type SbomHistoryEntry } from "./api-data";
import { Tag } from "./Primitives";
import { cx, integrityColor, lifecycleColor, riskColor, riskLabel, riskScoreText } from "./utils";
import type { LifecycleStatus } from "./types";

type SBOMHistoryProps = {
  data: SbomHistoryData | null;
  isLoading: boolean;
  error: string | null;
  onVerify?: (record: SbomHistoryEntry) => void;
};

export function SBOMHistory({ data, isLoading, error, onVerify }: SBOMHistoryProps) {
  const [selected, setSelected] = useState<string | null>(null);

  if (isLoading) return <div className="border border-border bg-card p-4 text-md font-mono text-muted-foreground">Loading SBOM history...</div>;
  if (error || !data || data.history.length === 0) return <div className="border border-[#ff3d5a44] bg-[#ff3d5a05] p-4 text-md font-mono text-[#ff3d5a]">{error ?? "SBOM history unavailable"}</div>;

  const activeId = selected ?? data.history[0].id;
  const selIdx = data.history.findIndex((s) => s.id === activeId);
  const sel = data.history[selIdx] ?? data.history[0];
  const prev = data.history[selIdx + 1];
  const canVerify = typeof onVerify === "function";
  const evidenceEntries = buildSbomEvidenceEntries(sel, data.source);

  const fmtId = (id: string) => id.replace(/^sbom-/, "SBOM-");
  const diffTitle = prev
    ? `DIFF - ${fmtId(prev.id)} -> ${fmtId(sel.id)}`
    : `ATTESTATION - ${fmtId(sel.id)}`;

  const lifecycleIcon = (lc: LifecycleStatus) => {
    if (lc === "REGISTERED") return <CheckCircle2 size={14} className="text-[#00e5ff]" />;
    if (lc === "APPROVED") return <ShieldCheck size={14} className="text-[#00ff9d]" />;
    if (lc === "REJECTED") return <XCircle size={14} className="text-[#ff3d5a]" />;
    if (lc === "NOT ON CHAIN") return <MinusCircle size={14} className="text-[#5a6a85]" />;
    return <Timer size={14} className="text-[#ffb300]" />;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
      <div className="md:col-span-2 border border-border bg-card">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3">
          <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">SBOM Timeline</span>
          <Tag color={data.source === "contract" ? "#00ff9d" : "#ffb300"}>{data.source.toUpperCase()}</Tag>
        </div>
        <div className="relative">
          <div className="absolute left-[27px] top-0 bottom-0 w-px bg-border" />
          {data.history.map((s) => (
            <button key={s.id} onClick={() => setSelected(s.id)}
              className={cx(
                "w-full text-left px-4 py-3 flex items-start gap-3 border-b border-border transition-colors",
                activeId === s.id ? "bg-[#00e5ff0d]" : "hover:bg-secondary/50"
              )}>
              <div className="relative z-10 mt-0.5 flex-shrink-0">{lifecycleIcon(s.lifecycle)}</div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[12px] font-mono font-semibold text-foreground">{s.projectId}</span>
                  <Tag color={riskColor(s.riskScore)}>{riskLabel(s.riskScore)}</Tag>
                  <Tag color={lifecycleColor(s.lifecycle)}>{s.lifecycle}</Tag>
                </div>
                <div className="text-[10px] font-mono text-muted-foreground mt-0.5">Version: {s.version}</div>
                <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-muted-foreground">
                  <span className="flex items-center gap-1"><GitCommit size={9} />{s.commit}</span>
                  <span className="flex items-center gap-1"><Database size={9} />{s.origin}</span>
                </div>
              </div>
              {activeId === s.id && <ChevronRight size={12} className="text-[#00e5ff] mt-1 flex-shrink-0" />}
            </button>
          ))}
        </div>
      </div>

      <div className="md:col-span-3 border border-border bg-card flex flex-col">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3 flex-wrap">
          <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">{diffTitle}</span>
          <button
            onClick={() => { if (canVerify) onVerify(sel); }}
            disabled={!canVerify}
            title={canVerify ? "Verify this attestation" : "Refresh the page to reconnect the verify action"}
            className={cx(
              "border px-3 py-2 text-[11px] font-mono tracking-widest transition-colors flex items-center gap-2",
              canVerify
                ? "border-[#00e5ff66] text-[#00e5ff] hover:bg-[#00e5ff11]"
                : "border-border text-muted-foreground/40 cursor-not-allowed"
            )}
          >
            <ShieldCheck size={12} /> VERIFY
          </button>
        </div>

        <div className="px-4 py-3 border-b border-border text-md font-mono text-muted-foreground">
          <div className="grid grid-cols-2 gap-x-6 gap-y-1.5">
            <span>Project:   <span className="text-foreground">{sel.projectId}</span></span>
            <span>Version:   <span className="text-foreground">{sel.version}</span></span>
            <span>Risk:      <span className="text-foreground" title={riskLabel(sel.riskScore)}>{riskScoreText(sel.riskScore)}</span></span>
            <span>Status:    <Tag color={lifecycleColor(sel.lifecycle)}>{sel.lifecycle}</Tag></span>
            <span className="col-span-2 truncate">
              SBOM Hash:&nbsp;<span className="text-[#00e5ff]">{sel.sbomHash}</span>
            </span>
            <span className="col-span-2 truncate">
              Merkle Root:&nbsp;<span className="text-[#00e5ff]">{sel.merkleRoot}</span>
            </span>
            <span className="col-span-2 truncate">
              Submitter:&nbsp;<span className="text-foreground">{sel.submitter}</span>
            </span>
            <span>Timestamp: <span className="text-foreground">{sel.date}</span></span>
            <span className="flex items-center gap-1.5 flex-wrap">
              Integrity:&nbsp;<Tag color={integrityColor(sel.integrityCheck)}>{sel.integrityCheck}</Tag>
            </span>
          </div>
        </div>

        <div className="flex-1 overflow-auto">
          <table className="w-full text-md font-mono">
            <thead>
              <tr className="border-b border-border">
                {["Field", "Value", "Source", "Meaning"].map((h) => (
                  <th key={h} className="text-left px-4 py-2 text-muted-foreground font-normal tracking-widest text-[10px] uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {evidenceEntries.map((d, i) => (
                <tr key={i} className="hover:bg-secondary/50 transition-colors">
                  <td className="px-4 py-2 text-foreground">
                    <span className="flex items-center gap-2">
                      <Tag color={d.type === "added" ? "#00ff9d" : d.type === "removed" ? "#ff3d5a" : "#ffb300"}>
                        {d.type === "added" ? "+" : d.type === "removed" ? "-" : "~"}
                      </Tag>
                      {d.pkg}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-[#00e5ff] truncate max-w-[360px]">{d.version}</td>
                  <td className="px-4 py-2 text-foreground">{d.source ?? "—"}</td>
                  <td className="px-4 py-2 text-muted-foreground">{d.meaning ?? d.prev}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
