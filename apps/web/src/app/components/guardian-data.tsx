"use client";

import { createContext, useContext, useEffect, useState } from "react";

import {
  fetchDashboardData,
  fetchRunsData,
  fetchSbomHistoryData,
  type DashboardData,
  type NetworkStatus,
  type RunsData,
  type SbomHistoryData,
} from "./api-data";

type GuardianData = {
  dashboardData: DashboardData | null;
  runsData: RunsData | null;
  sbomHistoryData: SbomHistoryData | null;
  network: NetworkStatus | null;
  isLoadingApiData: boolean;
  apiError: string | null;
};

const GuardianDataContext = createContext<GuardianData | null>(null);

/** Loads dashboard, runs and history once and shares them across the pages. */
export function GuardianDataProvider({ children }: { children: React.ReactNode; }) {
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [runsData, setRunsData] = useState<RunsData | null>(null);
  const [sbomHistoryData, setSbomHistoryData] = useState<SbomHistoryData | null>(null);
  const [isLoadingApiData, setIsLoadingApiData] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);

  useEffect(() => {
    let isActive = true;

    async function loadApiData() {
      try {
        const [dashboard, runs, sbomHistory] = await Promise.all([
          fetchDashboardData(),
          fetchRunsData(),
          fetchSbomHistoryData(),
        ]);

        if (!isActive) return;
        setDashboardData(dashboard);
        setRunsData(runs);
        setSbomHistoryData(sbomHistory);
        setApiError(null);
      } catch (error) {
        if (!isActive) return;
        setApiError(error instanceof Error ? error.message : "Failed to load API data");
      } finally {
        if (isActive) setIsLoadingApiData(false);
      }
    }

    loadApiData();

    return () => {
      isActive = false;
    };
  }, []);

  const network = sbomHistoryData?.network ?? null;

  return (
    <GuardianDataContext.Provider
      value={{ dashboardData, runsData, sbomHistoryData, network, isLoadingApiData, apiError }}>
      {children}
    </GuardianDataContext.Provider>
  );
}

export function useGuardianData(): GuardianData {
  const context = useContext(GuardianDataContext);
  if (!context) {
    throw new Error("useGuardianData must be used within GuardianDataProvider");
  }
  return context;
}
