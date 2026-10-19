"use client";

import { useCallback, useRef, useState } from "react";
import { AlertTriangle, CloudUpload, Download, FileCode2, RotateCcw, Search, Shield, ShieldCheck, ShieldX } from "lucide-react";

import { fetchStoredArtifactContent, verifyUploadedSbom, type AttestationRecord, type NetworkStatus, type VerifyUploadResult } from "./api-data";
import { computeSbomHashClientSide } from "./sbom-hash";
import { cx } from "./utils";
import type { VerifyState } from "./types";

const PROC_SUBSTEPS: { label: string; note?: string; }[] = [
  { label: "File uploaded" },
  { label: "Parsing SBOM structure" },
  { label: "Computing Keccak-256 hash", note: "Hash Mode: raw artifact content" },
  { label: "Querying smart contract" },
];

const TRACKER_STEPS = [
  "Upload SBOM File",
  "Parse and Compute Keccak-256",
  "Query Guardian smart contract",
  "Verification Result",
];

type VerifySBOMProps = {
  selectedAttestation: AttestationRecord | null;
  onOpenHistory: () => void;
  network: NetworkStatus | null;
};

function resultTone(status: VerifyState): { color: string; title: string; icon: React.ElementType; } {
  if (status === "ATTESTED_VALID") return { color: "#00ff9d", title: "SBOM ATTESTED", icon: ShieldCheck };
  if (status === "MISMATCH") return { color: "#ff3d5a", title: "HASH MISMATCH", icon: ShieldX };
  if (status === "REVOKED") return { color: "#ff3d5a", title: "ATTESTATION REVOKED", icon: ShieldX };
  if (status === "NOT_FOUND") return { color: "#ffb300", title: "ATTESTATION NOT FOUND", icon: AlertTriangle };
  if (status === "STRUCTURE_INVALID") return { color: "#ff3d5a", title: "INVALID SBOM STRUCTURE", icon: AlertTriangle };
  return { color: "#00e5ff", title: "STRUCTURE VALID", icon: ShieldCheck };
}

export function VerifySBOM({ selectedAttestation, onOpenHistory, network }: VerifySBOMProps) {
  const [verifyState, setVerifyState] = useState<VerifyState>("idle");
  const [fileName, setFileName] = useState<string | null>(null);
  const [procStep, setProcStep] = useState(0);
  const [dragging, setDragging] = useState(false);
  const [result, setResult] = useState<VerifyUploadResult | null>(null);
  const [clientHash, setClientHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [referenceError, setReferenceError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const reset = () => {
    setVerifyState("idle");
    setFileName(null);
    setProcStep(0);
    setResult(null);
    setClientHash(null);
    setError(null);
    setReferenceError(null);
    if (fileRef.current) fileRef.current.value = "";
  };

  const verifyContent = useCallback(async (name: string, loadContent: () => Promise<string>) => {
    if (!selectedAttestation) return;

    setFileName(name);
    setResult(null);
    setClientHash(null);
    setError(null);
    setVerifyState("processing");
    setProcStep(1);

    try {
      const sbomContent = await loadContent();
      setProcStep(2);
      // Computed locally so it is not just the server's own value echoed back.
      const hash = computeSbomHashClientSide(sbomContent);
      setClientHash(hash);
      setProcStep(3);
      const response = await verifyUploadedSbom(selectedAttestation, sbomContent);
      setProcStep(4);
      setResult(response);
      setVerifyState(response.status);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Verification failed");
      setVerifyState("STRUCTURE_INVALID");
      setProcStep(4);
    }
  }, [selectedAttestation]);

  const handleFile = useCallback(async (file: File) => {
    await verifyContent(file.name, () => file.text());
  }, [verifyContent]);

  const handleUseReferenceCopy = useCallback(async () => {
    if (!selectedAttestation) return;

    setReferenceError(null);

    try {
      const sbomContent = await fetchStoredArtifactContent(selectedAttestation);

      if (sbomContent === null) {
        setReferenceError("No reference copy stored for this record.");
        return;
      }

      await verifyContent("stored-reference-copy.json", async () => sbomContent);
    } catch (caught) {
      setReferenceError(caught instanceof Error ? caught.message : "Could not load the stored reference copy.");
    }
  }, [selectedAttestation, verifyContent]);

  const handleDownloadReferenceCopy = useCallback(async () => {
    if (!selectedAttestation) return;

    setReferenceError(null);

    try {
      const sbomContent = await fetchStoredArtifactContent(selectedAttestation);

      if (sbomContent === null) {
        setReferenceError("No reference copy stored for this record.");
        return;
      }

      const blob = new Blob([sbomContent], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${selectedAttestation.projectId}-${selectedAttestation.version}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (caught) {
      setReferenceError(caught instanceof Error ? caught.message : "Could not download the stored reference copy.");
    }
  }, [selectedAttestation]);

  const isResultState = verifyState !== "idle" && verifyState !== "processing";

  const trackerDone = (i: number) => {
    if (isResultState) return true;
    if (verifyState === "processing") return procStep > i;
    return false;
  };

  const trackerActive = (i: number) => verifyState === "processing" && procStep === i + 1;

  if (!selectedAttestation) {
    return (
      <div className="border border-border bg-card min-h-[420px] flex items-center justify-center p-6">
        <div className="text-center max-w-md space-y-4">
          <FileCode2 size={38} className="text-muted-foreground mx-auto" />
          <div>
            <div className="text-[15px] font-mono tracking-widest text-foreground uppercase">No attestation selected</div>
            <p className="text-md font-mono text-muted-foreground mt-2">
              Open SBOM History, choose an on-chain record, then upload the SBOM artifact to verify against it.
            </p>
          </div>
          <button onClick={onOpenHistory}
            className="border border-[#00e5ff66] text-[#00e5ff] hover:bg-[#00e5ff11] px-4 py-2 text-md font-mono tracking-widest transition-colors">
            OPEN SBOM HISTORY
          </button>
        </div>
      </div>
    );
  }

  const tone = resultTone(verifyState);
  const ResultIcon = tone.icon;

  return (
    <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
      <div className="md:col-span-2 space-y-3">
        <div className="border border-border bg-card p-5 space-y-3">
          <div className="text-md font-mono tracking-widest text-muted-foreground uppercase">Selected Attestation</div>
          <div className="space-y-2 text-md font-mono">
            <div>
              <div className="text-[9px] tracking-widest text-muted-foreground uppercase">Project</div>
              <div className="text-foreground break-all">{selectedAttestation.projectId}</div>
            </div>
            <div>
              <div className="text-[9px] tracking-widest text-muted-foreground uppercase">Version</div>
              <div className="text-foreground break-all">{selectedAttestation.version}</div>
            </div>
            <div>
              <div className="text-[9px] tracking-widest text-muted-foreground uppercase">On-chain Hash</div>
              <div className="text-[#00e5ff] break-all text-[10px] leading-relaxed">{selectedAttestation.sbomHash}</div>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[9px] tracking-widest text-muted-foreground uppercase">Status</span>
              <span className="text-foreground">{selectedAttestation.status}</span>
            </div>
          </div>
        </div>

        <div className="border border-border bg-card p-5">
          <div className="text-md font-mono tracking-widest text-muted-foreground uppercase mb-4">Upload SBOM</div>

          <div className="flex gap-2 mb-3">
            <button onClick={() => { if (verifyState === "idle") void handleUseReferenceCopy(); }}
              disabled={verifyState !== "idle"}
              className="flex-1 border border-[#00e5ff66] text-[#00e5ff] hover:bg-[#00e5ff11] disabled:opacity-40 disabled:cursor-not-allowed py-2.5 text-[11px] font-mono tracking-widest transition-colors">
              USE STORED REFERENCE COPY
            </button>
            <button onClick={() => { if (verifyState === "idle") void handleDownloadReferenceCopy(); }}
              disabled={verifyState !== "idle"}
              title="Download stored reference copy"
              className="border border-border text-muted-foreground hover:border-[#1e3a4a] hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed px-3 transition-colors flex items-center justify-center">
              <Download size={14} />
            </button>
          </div>
          {referenceError && (
            <p className="text-[10px] font-mono text-[#ffb300] mb-3">{referenceError}</p>
          )}

          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) void handleFile(f); }}
            onClick={() => { if (verifyState === "idle") fileRef.current?.click(); }}
            className={cx(
              "border-2 border-dashed flex flex-col items-center justify-center py-10 transition-colors",
              verifyState === "idle" ? "cursor-pointer" : "cursor-default opacity-60",
              dragging ? "border-[#00e5ff] bg-[#00e5ff0a]" : "border-border hover:border-[#1e3a4a]"
            )}>
            <CloudUpload size={28} className={dragging ? "text-[#00e5ff]" : "text-muted-foreground"} />
            <span className="text-md font-mono text-muted-foreground mt-3 text-center">
              {fileName ?? "Drop CycloneDX JSON SBOM"}
            </span>
            <span className="text-[10px] font-mono text-muted-foreground/60 mt-1">or click to browse</span>
          </div>
          <input ref={fileRef} type="file" accept=".json,.cyclonedx,.txt" className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) void handleFile(f); }} />
        </div>

        <div className="border border-border bg-card p-5 space-y-4">
          <div className="text-md font-mono tracking-widest text-muted-foreground uppercase">Progress</div>
          {TRACKER_STEPS.map((label, i) => (
            <div key={i} className="flex items-center gap-3">
              <div className={cx(
                "size-5 flex items-center justify-center border text-[10px] font-mono font-bold flex-shrink-0 transition-all",
                trackerDone(i) ? "border-[#00ff9d] text-[#00ff9d] bg-[#00ff9d11]" :
                  trackerActive(i) ? "border-[#00e5ff] text-[#00e5ff] bg-[#00e5ff11]" :
                    "border-border text-muted-foreground"
              )}>
                {trackerDone(i) ? "✓" : trackerActive(i) ? "..." : i + 1}
              </div>
              <span className={cx(
                "text-[12px] font-mono leading-tight flex-1",
                trackerDone(i) ? "text-[#00ff9d]" :
                  trackerActive(i) ? "text-[#00e5ff]" :
                    "text-muted-foreground"
              )}>{label}</span>
            </div>
          ))}
        </div>

        {isResultState && (
          <button onClick={reset}
            className="w-full border border-border text-muted-foreground hover:border-[#1e3a4a] py-3 text-[12px] font-mono tracking-widest transition-colors flex items-center justify-center gap-2">
            <RotateCcw size={12} /> VERIFY ANOTHER FILE
          </button>
        )}
      </div>

      <div className="md:col-span-3 border border-border bg-card flex flex-col min-h-[520px]">
        <div className="px-4 py-3 border-b border-border">
          <span className="text-md font-mono tracking-widest text-muted-foreground uppercase">Verification Details</span>
        </div>

        {verifyState === "idle" && (
          <div className="flex-1 flex items-center justify-center text-muted-foreground/30">
            <div className="text-center space-y-2">
              <Shield size={36} className="mx-auto" />
              <p className="text-[12px] font-mono">Awaiting SBOM artifact upload</p>
            </div>
          </div>
        )}

        {verifyState === "processing" && (
          <div className="p-5 space-y-5 flex-1">
            <div>
              <div className="text-[9px] font-mono tracking-widest text-muted-foreground uppercase mb-1">File</div>
              <div className="text-[12px] font-mono text-foreground">{fileName}</div>
            </div>
            <div>
              <div className="text-[9px] font-mono tracking-widest text-muted-foreground uppercase mb-2">Processing</div>
              <div className="space-y-1">
                {PROC_SUBSTEPS.map((sub, i) => {
                  const done = procStep > i + 1;
                  const active = procStep === i + 1;
                  return (
                    <div key={i} className={cx(
                      "flex items-start gap-3 px-3 py-2 border transition-colors",
                      done ? "border-[#00ff9d22] bg-[#00ff9d06]" :
                        active ? "border-[#00e5ff33] bg-[#00e5ff08]" :
                          "border-transparent"
                    )}>
                      <span className={cx(
                        "text-[10px] font-mono font-bold flex-shrink-0 mt-0.5 w-3",
                        done ? "text-[#00ff9d]" : active ? "text-[#00e5ff]" : "text-muted-foreground/30"
                      )}>
                        {done ? "✓" : active ? ">" : "·"}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className={cx(
                          "text-[12px] font-mono",
                          done ? "text-[#00ff9d]" : active ? "text-[#00e5ff]" : "text-muted-foreground/40"
                        )}>{sub.label}</div>
                        {sub.note && (done || active) && (
                          <div className="text-[10px] font-mono text-muted-foreground/60 mt-0.5">{sub.note}</div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {isResultState && (
          <div className="p-5 space-y-5 flex-1">
            <div className="border px-5 py-4" style={{ borderColor: tone.color, backgroundColor: tone.color + "08" }}>
              <div className="flex items-center gap-3 mb-1">
                <ResultIcon size={20} style={{ color: tone.color }} className="flex-shrink-0" />
                <span className="text-[15px] font-mono font-bold tracking-widest" style={{ color: tone.color }}>{tone.title}</span>
              </div>
              <p className="text-md font-mono pl-9" style={{ color: tone.color + "b3" }}>
                {result?.message ?? error ?? "Verification failed."}
              </p>
            </div>

            <div className="space-y-3 text-md font-mono">
              {([
                { label: "File Name", val: fileName ?? "-", cyan: false },
                { label: "Project ID", val: selectedAttestation.projectId, cyan: false },
                { label: "Version", val: selectedAttestation.version, cyan: false },
                { label: "Computed Hash (browser)", val: clientHash ?? "-", cyan: true },
                { label: "Computed Hash (server)", val: result?.computedHash ?? "-", cyan: true },
                { label: "On-chain Hash", val: result?.onChainHash ?? selectedAttestation.sbomHash, cyan: true },
                { label: "Record Status", val: result?.record?.status ?? selectedAttestation.status, cyan: false },
                { label: "Contract Address", val: network?.contractAddress || "Not configured", cyan: true },
              ] as { label: string; val: string; cyan: boolean; }[]).map(({ label, val, cyan }) => (
                <div key={label} className="flex flex-col gap-0.5">
                  <span className="text-[9px] tracking-widest text-muted-foreground uppercase">{label}</span>
                  <span className={cx("break-all leading-snug", cyan ? "text-[#00e5ff]" : "text-foreground")}>{val}</span>
                </div>
              ))}
            </div>

            {(verifyState === "NOT_FOUND" || verifyState === "MISMATCH") && (
              <button onClick={onOpenHistory}
                className="flex items-center gap-2 border border-[#ffb30066] text-[#ffb300] hover:bg-[#ffb30011] px-4 py-2 text-md font-mono tracking-widest transition-colors">
                <Search size={11} /> CHOOSE ANOTHER RECORD
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
