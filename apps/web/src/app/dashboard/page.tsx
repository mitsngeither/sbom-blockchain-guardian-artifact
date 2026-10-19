"use client";

import { Dashboard } from "../components/Dashboard";
import { useGuardianData } from "../components/guardian-data";

export default function DashboardPage() {
  const { dashboardData, isLoadingApiData, apiError } = useGuardianData();

  return <Dashboard data={dashboardData} isLoading={isLoadingApiData} error={apiError} />;
}
