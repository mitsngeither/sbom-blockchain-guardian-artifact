"use client";

import { useState } from "react";
import type { ElementType, ReactNode } from "react";
import { Copy, TrendingDown, TrendingUp } from "lucide-react";

export function Tag({ children, color = "#00e5ff" }: { children: ReactNode; color?: string; }) {
  return (
    <span
      className="inline-flex items-center px-1.5 py-px text-[10px] font-mono font-semibold tracking-widest border"
      style={{ color, borderColor: color + "44", background: color + "11" }}
    >
      {children}
    </span>
  );
}

export function StatCard({
  label, value, sub, icon: Icon, accent = "#00e5ff", trend,
}: {
  label: string; value: string; sub?: string;
  icon: ElementType; accent?: string; trend?: "up" | "down";
}) {
  return (
    <div className="border border-border bg-card p-5 flex flex-col gap-3 relative overflow-hidden group hover:border-[#1e3a4a] transition-colors duration-200">
      <div className="flex items-start justify-between">
        <span className="text-[10px] font-mono tracking-widest text-muted-foreground uppercase">{label}</span>
        <Icon size={14} style={{ color: accent }} />
      </div>
      <div>
        <div className="text-2xl font-mono font-semibold" style={{ color: accent }}>{value}</div>
        {sub && (
          <div className="flex items-center gap-1 mt-1">
            {trend === "up" && <TrendingUp size={11} className="text-[#00ff9d]" />}
            {trend === "down" && <TrendingDown size={11} className="text-[#ff3d5a]" />}
            <span className="text-md font-mono text-muted-foreground">{sub}</span>
          </div>
        )}
      </div>
      <div className="absolute bottom-0 left-0 h-px w-0 group-hover:w-full transition-all duration-500"
        style={{ background: accent }} />
    </div>
  );
}

export function CopyButton({ text }: { text: string; }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text).catch(() => { });
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      }}
      title="Copy to clipboard"
      className="flex items-center gap-1 text-muted-foreground hover:text-[#00e5ff] transition-colors"
    >
      <Copy size={11} />
      {copied && <span className="text-[9px] text-[#00ff9d]">copied</span>}
    </button>
  );
}
