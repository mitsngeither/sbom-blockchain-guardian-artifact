"use client";

import { useRouter } from "next/navigation";

import type { SbomHistoryEntry } from "../components/api-data";
import { useGuardianData } from "../components/guardian-data";
import { SBOMHistory } from "../components/SbomHistory";

export default function SbomHistoryPage() {
  const router = useRouter();
  const { sbomHistoryData, isLoadingApiData, apiError } = useGuardianData();

  const openVerifyForRecord = (record: SbomHistoryEntry) => {
    const query = new URLSearchParams({ projectId: record.projectId, version: record.version });
    router.push(`/verify?${query.toString()}`);
  };

  return (
    <SBOMHistory
      data={sbomHistoryData}
      isLoading={isLoadingApiData}
      error={apiError}
      onVerify={openVerifyForRecord}
    />
  );
}
