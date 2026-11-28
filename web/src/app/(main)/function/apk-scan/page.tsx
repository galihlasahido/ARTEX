"use client";

import * as React from "react";

import { AlertTriangleIcon, Loader2Icon, SmartphoneIcon, UploadIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import type { ApkScanReport, ApkSeverity } from "@/lib/types";
import { cn } from "@/lib/utils";

const SEVERITY_ORDER: ApkSeverity[] = ["high", "medium", "low", "info"];

function severityClass(sev: string): string {
  switch (sev) {
    case "high":
      return "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30";
    case "medium":
      return "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30";
    case "low":
      return "bg-sky-500/15 text-sky-600 dark:text-sky-400 border-sky-500/30";
    default:
      return "bg-muted text-muted-foreground border-border";
  }
}

export default function ApkScanPage() {
  const [file, setFile] = React.useState<File | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [report, setReport] = React.useState<ApkScanReport | null>(null);
  const [error, setError] = React.useState("");

  async function runScan() {
    if (!file) return;
    setLoading(true);
    setError("");
    setReport(null);
    try {
      setReport(await api.scanApk(file));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  const missingTools = report
    ? Object.entries(report.meta?.tools ?? {})
        .filter(([, present]) => !present)
        .map(([name]) => name)
    : [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-4 p-4">
      <div className="flex items-center gap-2">
        <SmartphoneIcon className="size-5 text-muted-foreground" />
        <div>
          <h1 className="text-lg font-semibold">{t("APK Scan")}</h1>
          <p className="text-sm text-muted-foreground">{t("Static security scan of an Android APK")}</p>
        </div>
      </div>

      <Card className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
        <input
          type="file"
          accept=".apk,application/vnd.android.package-archive"
          onChange={(e) => {
            setFile(e.target.files?.[0] ?? null);
            setReport(null);
            setError("");
          }}
          className="block w-full text-sm file:mr-3 file:rounded-md file:border-0 file:bg-primary file:px-3 file:py-1.5 file:text-primary-foreground hover:file:opacity-90"
        />
        <Button onClick={runScan} disabled={!file || loading} className="shrink-0">
          {loading ? <Loader2Icon className="size-4 animate-spin" /> : <UploadIcon className="size-4" />}
          {loading ? t("Scanning…") : t("Scan")}
        </Button>
      </Card>

      {loading && (
        <p className="text-sm text-muted-foreground">
          {t("Decompiling and analyzing — this can take a minute for a large APK.")}
        </p>
      )}

      {error && (
        <Card className="border-red-500/30 bg-red-500/10 p-4 text-sm text-red-600 dark:text-red-400">
          {t("Scan failed: {error}", { error })}
        </Card>
      )}

      {report && (
        <div className="space-y-4">
          {/* App + summary */}
          <Card className="grid grid-cols-2 gap-3 p-4 sm:grid-cols-4">
            <Info label={t("Package")} value={report.app?.package || "—"} />
            <Info label={t("Version")} value={report.app?.version_name || "—"} />
            <Info label={t("Min SDK")} value={report.app?.min_sdk ? String(report.app.min_sdk) : "—"} />
            <Info label={t("Target SDK")} value={report.app?.target_sdk ? String(report.app.target_sdk) : "—"} />
          </Card>

          <div className="flex flex-wrap items-center gap-2">
            {SEVERITY_ORDER.map((sev) => {
              const n = report.summary?.by_severity?.[sev] ?? 0;
              if (!n) return null;
              return (
                <Badge key={sev} variant="outline" className={cn("capitalize", severityClass(sev))}>
                  {n} {sev}
                </Badge>
              );
            })}
            <span className="text-sm text-muted-foreground">
              {t("{n} findings", { n: String(report.summary?.findings ?? report.findings.length) })}
            </span>
          </div>

          {missingTools.length > 0 && (
            <p className="flex items-center gap-1.5 text-sm text-amber-600 dark:text-amber-400">
              <AlertTriangleIcon className="size-4" />
              {t("Some tools were unavailable ({tools}); results may be partial.", { tools: missingTools.join(", ") })}
            </p>
          )}

          {/* Findings */}
          <Card className="p-0">
            {report.findings.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground">{t("No findings.")}</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">{t("Severity")}</TableHead>
                    <TableHead>{t("Finding")}</TableHead>
                    <TableHead className="w-36">{t("Reference")}</TableHead>
                    <TableHead>{t("Location")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.findings.map((f, i) => (
                    <TableRow key={`${f.id}-${i}`}>
                      <TableCell>
                        <Badge variant="outline" className={cn("capitalize", severityClass(f.severity))}>
                          {f.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium">{f.title}</div>
                        {f.evidence && (
                          <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={f.evidence}>
                            {f.evidence}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-xs">
                        <div>{f.cwe}</div>
                        <div className="text-muted-foreground">{f.masvs}</div>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {f.file}
                        {f.line > 0 ? `:${f.line}` : ""}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Card>

          {/* Endpoints */}
          {report.endpoints.length > 0 && (
            <Card className="p-4">
              <h2 className="mb-2 text-sm font-semibold">
                {t("Endpoints")} ({report.endpoints.length})
              </h2>
              <ul className="space-y-1 font-mono text-xs text-muted-foreground">
                {report.endpoints.map((u) => (
                  <li key={u} className="truncate" title={u}>
                    {u}
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {/* Certificate */}
          {report.certificates.length > 0 && (
            <Card className="p-4">
              <h2 className="mb-2 text-sm font-semibold">{t("Certificate")}</h2>
              <ul className="space-y-1 font-mono text-xs text-muted-foreground">
                {report.certificates.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="truncate font-medium" title={value}>
        {value}
      </div>
    </div>
  );
}
