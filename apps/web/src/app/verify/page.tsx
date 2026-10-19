"use client";

import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { useGuardianData } from "../components/guardian-data";
import { VerifySBOM } from "../components/VerifySbom";

function VerifyPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { sbomHistoryData, isLoadingApiData, network } = useGuardianData();

  const projectId = searchParams.get("projectId");
  const version = searchParams.get("version");
  const requestedRecord = Boolean(projectId && version);
  const selectedAttestation = requestedRecord
    ? sbomHistoryData?.history.find(
      (record) => record.projectId === projectId && record.version === version,
    ) ?? null
    : null;

  // Deep link: history not loaded yet.
  if (requestedRecord && !selectedAttestation && isLoadingApiData) {
    return (
      <div className="border border-border bg-card min-h-[420px] flex items-center justify-center p-6">
        <p className="text-md font-mono text-muted-foreground">Loading attestation…</p>
      </div>
    );
  }

  return (
    <VerifySBOM
      selectedAttestation={selectedAttestation}
      onOpenHistory={() => router.push("/sbom-history")}
      network={network}
    />
  );
}

export default function VerifyPage() {
  return (
    <Suspense fallback={null}>
      <VerifyPageContent />
    </Suspense>
  );
}
