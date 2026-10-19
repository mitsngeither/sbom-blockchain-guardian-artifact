"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Copy, Database, FileCode2, GitBranch, Hash, Link2, ShieldCheck } from "lucide-react";

import { useGuardianData } from "./components/guardian-data";
import { cx } from "./components/utils";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: Database },
  { href: "/sbom-history", label: "SBOM History", icon: FileCode2 },
  { href: "/verify", label: "Verify SBOM", icon: ShieldCheck },
  { href: "/pipeline", label: "Pipeline Status", icon: GitBranch },
] as const;

export function AppShell({ children }: { children: React.ReactNode; }) {
  const pathname = usePathname();
  const { dashboardData, network } = useGuardianData();
  const [copiedContract, setCopiedContract] = useState(false);
  const [timestamp, setTimestamp] = useState("---- -- -- --:--:-- UTC");

  useEffect(() => {
    const formatter = new Intl.DateTimeFormat("sv-SE", {
      timeZone: "Asia/Bangkok",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });

    setTimestamp(`${formatter.format(new Date())} GMT+7`);
  }, []);

  const contractAddress = network?.contractAddress ?? "";
  const contractShort = contractAddress ? `${contractAddress.slice(0, 6)}...${contractAddress.slice(-4)}` : "Not configured";
  const chainName = network?.chainName ?? "Unknown";
  const isNetworkConfigured = Boolean(network?.configured);
  const activeNavItem = NAV.find((item) => pathname === item.href || pathname.startsWith(`${item.href}/`));

  const copyContract = () => {
    if (!contractAddress) return;
    navigator.clipboard.writeText(contractAddress).catch(() => { });
    setCopiedContract(true);
    setTimeout(() => setCopiedContract(false), 1800);
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col"
      style={{ fontFamily: "'JetBrains Mono', monospace" }}>

      {/* Header */}
      <header className="border-b border-border bg-card flex items-center h-12 px-4 flex-shrink-0 gap-0">
        {/* Logo + subtitle */}
        <div className="flex items-center gap-2.5 mr-6 flex-shrink-0">
          <Link2 size={14} className="text-[#00e5ff]" />
          <div className="flex flex-col leading-none gap-0.5">
            <span className="text-md font-bold tracking-widest text-foreground">SBOM GUARDIAN</span>
            <span className="text-[8px] font-mono tracking-[0.18em] text-muted-foreground">SBOM REGISTRY</span>
          </div>
        </div>

        <nav className="flex items-stretch h-full flex-1 overflow-x-auto">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = activeNavItem?.href === href;
            return (
              <Link key={href} href={href}
                className={cx(
                  "flex items-center gap-2 px-4 h-full text-md tracking-widest border-r border-border transition-colors whitespace-nowrap",
                  active
                    ? "bg-[#00e5ff0d] text-[#00e5ff] border-b-[1.5px] border-b-[#00e5ff]"
                    : "text-muted-foreground hover:text-foreground hover:bg-secondary/60"
                )}>
                <Icon size={12} />
                {label.toUpperCase()}
              </Link>
            );
          })}
        </nav>

        {/* Contract address */}
        <div className="hidden md:flex items-center gap-2 px-4 border-l border-border ml-2 flex-shrink-0">
          <Hash size={11} className="text-muted-foreground" />
          <span className="text-[10px] font-mono text-muted-foreground">Contract:</span>
          <span className="text-[10px] font-mono text-[#00e5ff]">{contractShort}</span>
          <button onClick={copyContract}
            disabled={!contractAddress}
            className="text-muted-foreground hover:text-[#00e5ff] transition-colors disabled:opacity-40 disabled:cursor-not-allowed" title="Copy contract address">
            <Copy size={11} />
          </button>
          {copiedContract && <span className="text-[9px] font-mono text-[#00ff9d]">copied</span>}
        </div>

        {/* Network */}
        <div className="flex items-center gap-2 px-3 border-l border-border ml-2 flex-shrink-0">
          <div className={cx("size-1.5 rounded-full", isNetworkConfigured ? "bg-[#00ff9d] animate-pulse" : "bg-[#ffb300]")} />
          <span className={cx("text-[10px] font-mono tracking-widest", isNetworkConfigured ? "text-[#00ff9d]" : "text-[#ffb300]")}>{isNetworkConfigured ? chainName.toUpperCase() : "DEMO"}</span>
        </div>
      </header>

      {/* Breadcrumb */}
      <div className="border-b border-border px-6 py-2.5 flex items-center gap-3">
        {activeNavItem && (
          <div className="flex items-center gap-2">
            <activeNavItem.icon size={13} className="text-[#00e5ff]" />
            <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">{activeNavItem.label}</span>
          </div>
        )}
        <ChevronRight size={11} className="text-border" />
        <span className="text-md font-mono text-muted-foreground/50">
          {timestamp}
        </span>
      </div>

      {/* Content */}
      <main className="flex-1 p-4 md:p-6 overflow-auto">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t border-border h-7 flex items-center px-4 gap-3 text-[10px] font-mono text-muted-foreground flex-shrink-0 overflow-x-auto">
        <span>Network: <span className="text-[#a855f7]">{isNetworkConfigured ? chainName : "Demo"}</span></span>
        <span className="text-border">|</span>
        <span>Records: <span className="text-foreground">{dashboardData?.totalRecords ?? "—"}</span></span>
        <span className="text-border">|</span>
        <span className="flex items-center gap-1">
          Contract: <span className="text-[#00e5ff] ml-1">{contractShort}</span>
          <button onClick={copyContract} disabled={!contractAddress} className="text-muted-foreground hover:text-[#00e5ff] transition-colors ml-1 disabled:opacity-40 disabled:cursor-not-allowed">
            <Copy size={10} />
          </button>
        </span>
        <span className="text-border">|</span>
        <span>RPC: <span className={isNetworkConfigured ? "text-[#00ff9d]" : "text-[#ffb300]"}>{isNetworkConfigured ? "Connected" : "Not configured"}</span></span>
        <span className="text-border ml-auto">|</span>
        <span>v2.4.1-beta</span>
      </footer>
    </div>
  );
}
