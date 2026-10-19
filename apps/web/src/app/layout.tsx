import type { Metadata } from "next";
import "./globals.css";
import { AppShell } from "./AppShell";
import { GuardianDataProvider } from "./components/guardian-data";

export const metadata: Metadata = {
  title: "SBOM Blockchain Guardian",
  description: "Blockchain SBOM Registry",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body>
        <GuardianDataProvider>
          <AppShell>{children}</AppShell>
        </GuardianDataProvider>
      </body>
    </html>
  );
}