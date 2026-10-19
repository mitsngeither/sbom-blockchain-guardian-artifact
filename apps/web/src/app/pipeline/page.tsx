"use client";

import { useGuardianData } from "../components/guardian-data";
import { PipelineStatusPanel } from "../components/PipelineStatusPanel";

export default function PipelinePage() {
  const { runsData, isLoadingApiData, apiError, network } = useGuardianData();

  return <PipelineStatusPanel data={runsData} isLoading={isLoadingApiData} error={apiError} network={network} />;
}
