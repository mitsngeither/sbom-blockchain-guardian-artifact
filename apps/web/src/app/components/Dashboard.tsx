import { FileCode2, Layers, Radio, ShieldCheck, Zap } from "lucide-react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { DashboardData } from "./api-data";
import { CopyButton, StatCard, Tag } from "./Primitives";
import { lifecycleColor, riskColor, riskLabel, riskScoreText } from "./utils";

type DashboardProps = {
  data: DashboardData | null;
  isLoading: boolean;
  error: string | null;
};

export function Dashboard({ data, isLoading, error }: DashboardProps) {
  if (isLoading) return <div className="border border-border bg-card p-4 text-md font-mono text-muted-foreground">Loading dashboard data...</div>;
  if (error || !data) return <div className="border border-[#ff3d5a44] bg-[#ff3d5a05] p-4 text-md font-mono text-[#ff3d5a]">{error ?? "Dashboard data unavailable"}</div>;

  const rpcStatus = data.network.configured ? "CONNECTED" : "DEMO";
  const rpcSubtext = data.network.configured ? data.network.chainName : "RPC not configured";
  const contractAddress = data.network.contractAddress;
  const contractShort = contractAddress ? contractAddress.slice(0, 6) + "..." + contractAddress.slice(-4) : "Not configured";
  const verificationRate = data.totalRecords > 0
    ? String(Math.round((data.verifiedRecords / data.totalRecords) * 100)) + "%"
    : "N/A";
  const contractStatus = data.network.configured
    ? data.activeRecords > 0 ? "Active" : "Configured"
    : "Demo only";

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="SBOM Records" value={String(data.totalRecords)} sub={String(data.txns.length) + " artifact(s)"} icon={FileCode2} accent="#00ff9d" />
        <StatCard label="Active Attestations" value={String(data.activeRecords)} sub="matched on-chain records" icon={Layers} />
        <StatCard label="RPC Status" value={rpcStatus} sub={rpcSubtext} icon={Radio} accent={data.network.configured ? "#00ff9d" : "#ffb300"} />
        <StatCard label="Verification Rate" value={verificationRate} sub={String(data.verifiedRecords) + "/" + String(data.totalRecords) + " active"} icon={ShieldCheck} accent="#ffb300" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="md:col-span-2 border border-border bg-card">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">Recent SBOM Artifacts</span>
            <FileCode2 size={13} className="text-muted-foreground" />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-md font-mono">
              <thead>
                <tr className="border-b border-border">
                  {["Project", "Version", "SBOM Hash", "Risk", "Status", "Timestamp"].map((h) => (
                    <th key={h} className="text-left px-4 py-2 text-[10px] font-normal tracking-widest text-muted-foreground uppercase whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {data.txns.map((t, i) => (
                  <tr key={i} className="hover:bg-secondary/50 transition-colors">
                    <td className="px-4 py-2.5 text-foreground whitespace-nowrap">{t.project}</td>
                    <td className="px-4 py-2.5 text-muted-foreground">{t.version}</td>
                    <td className="px-4 py-2.5 text-[#00e5ff]">
                      <span className="block max-w-[200px] truncate" title={t.sbomHash}>{t.sbomHash}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="font-semibold" style={{ color: riskColor(t.risk) }} title={riskLabel(t.risk)}>
                        {riskScoreText(t.risk)}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <Tag color={lifecycleColor(t.status)}>{t.status}</Tag>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground whitespace-nowrap">{t.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="border border-border bg-card">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">Network</span>
            <div className="size-1.5 rounded-full bg-[#00ff9d] animate-pulse" />
          </div>
          <div className="px-4 py-3 space-y-3">
            {([
              { label: "Network", val: data.network.configured ? data.network.chainName : "Prototype demo", color: data.network.configured ? "#a855f7" : "#ffb300" },
              { label: "RPC Status", val: data.network.configured ? "Connected" : "Not configured", color: data.network.configured ? "#00ff9d" : "#ffb300" },
              { label: "SBOM Records", val: String(data.totalRecords), color: undefined },
              { label: "Active Records", val: String(data.activeRecords), color: data.activeRecords > 0 ? "#00ff9d" : undefined },
              { label: "Verified Uploads", val: String(data.verifiedRecords) + "/" + String(data.totalRecords), color: undefined },
              { label: "Contract Status", val: contractStatus, color: data.network.configured ? "#00ff9d" : "#ffb300" },
            ] as { label: string; val: string; color: string | undefined; }[]).map(({ label, val, color }) => (
              <div key={label} className="flex justify-between items-center">
                <span className="text-md font-mono text-muted-foreground">{label}</span>
                <span className="text-md font-mono" style={{ color: color ?? undefined }}>{val}</span>
              </div>
            ))}
          </div>
          <div className="px-4 py-3 border-t border-border">
            <div className="text-[10px] font-mono text-muted-foreground mb-1 tracking-widest uppercase">Contract</div>
            <div className="flex items-center gap-2">
              <span className="text-md font-mono text-[#00e5ff]">{contractShort}</span>
              {contractAddress && <CopyButton text={contractAddress} />}
            </div>
          </div>
        </div>
      </div>

      <div className="border border-border bg-card">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">SBOM Registrations — Last 7 Days</span>
          <Zap size={13} style={{ color: "#00e5ff" }} />
        </div>
        <div className="px-2 py-4" style={{ height: 180 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data.registrations} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="regGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00ff9d" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#00ff9d" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fontSize: 10, fontFamily: "JetBrains Mono", fill: "#5a6a85" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fontFamily: "JetBrains Mono", fill: "#5a6a85" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: "#0d1117", border: "1px solid #1e2a3a", borderRadius: 0, fontFamily: "JetBrains Mono", fontSize: 11 }}
                labelStyle={{ color: "#5a6a85" }}
                formatter={(value) => [value, "Registrations"]}
                itemStyle={{ color: "#00ff9d" }}
              />
              <Area type="monotone" dataKey="count" stroke="#00ff9d" strokeWidth={1.5} fill="url(#regGrad)" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
