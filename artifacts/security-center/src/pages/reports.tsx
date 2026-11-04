import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Building2, Download, FileSpreadsheet, FileText, Loader2, Monitor } from "lucide-react";
import { getListReportsQueryKey, useCreateReport, useListDevices, useListReports, type ReportExportInputType } from "@workspace/api-client-react";
import { useT } from "@/i18n";
import { canAnalyze, usePageMeta, useRole } from "@/lib/session";
import { errMsg, fmtBytes, fmtDate } from "@/lib/format";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { EmptyState, ErrorState, PageHeader, Panel, Pill, SkeletonRows } from "@/components/app/primitives";

const KINDS: { type: ReportExportInputType; title: string; desc: string; icon: typeof FileText }[] = [
  { type: "DEVICE_PDF", title: "Device report", desc: "One device: posture checks with evidence, findings, CVE matches and coverage.", icon: Monitor },
  { type: "ORGANIZATION_PDF", title: "Organization report", desc: "Fleet summary for leadership or auditors, with coverage caveats.", icon: Building2 },
  { type: "FINDINGS_CSV", title: "Findings export", desc: "All findings with provenance, as CSV for spreadsheets or ticketing.", icon: FileSpreadsheet },
];

export default function Reports() {
  const t = useT();
  usePageMeta(t("reports.title"), t("reports.description"));
  const role = useRole();
  const qc = useQueryClient();
  const { toast } = useToast();
  const [kind, setKind] = useState<ReportExportInputType>("ORGANIZATION_PDF");
  const [deviceId, setDeviceId] = useState("");
  const devices = useListDevices();
  const reports = useListReports();
  const create = useCreateReport({
    mutation: {
      onSuccess: (r) => {
        void qc.invalidateQueries({ queryKey: getListReportsQueryKey() });
        toast({ title: r.status === "COMPLETED" ? "Report ready" : "Report failed", description: r.error ?? r.summary, variant: r.status === "FAILED" ? "destructive" : undefined });
      },
      onError: (e) => toast({ title: "Could not generate report", description: errMsg(e), variant: "destructive" }),
    },
  });

  return (
    <div>
      <PageHeader eyebrow="Exports" title={t("reports.title")} description={t("reports.description")} />
      <div className="grid gap-5 xl:grid-cols-[380px_1fr]">
        <Panel title="Generate">
          <div className="space-y-2">
            {KINDS.map((k) => (
              <button key={k.type} data-testid={`button-kind-${k.type}`} onClick={() => setKind(k.type)} className={cn("flex w-full gap-3 rounded-xl border p-3.5 text-left transition-colors", kind === k.type ? "border-violet bg-violet/10" : "border-border hover:bg-white/[0.03]")}>
                <k.icon className={cn("mt-0.5 size-4 shrink-0", kind === k.type ? "text-violet" : "text-muted-foreground")} />
                <span>
                  <span className="block text-[13px] font-medium">{k.title}</span>
                  <span className="block text-xs text-muted-foreground">{k.desc}</span>
                </span>
              </button>
            ))}
          </div>
          {kind === "DEVICE_PDF" && (
            <select data-testid="select-report-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} className="mt-4 h-9 w-full rounded-lg border border-input bg-card px-2.5 text-[13px] outline-none focus:border-violet">
              <option value="">Select a device…</option>
              {devices.data?.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          )}
          {canAnalyze(role) ? (
            <button
              data-testid="button-generate-report"
              disabled={create.isPending || (kind === "DEVICE_PDF" && !deviceId)}
              onClick={() => create.mutate({ data: kind === "DEVICE_PDF" ? { type: kind, deviceId } : { type: kind } })}
              className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground disabled:opacity-50"
            >
              {create.isPending && <Loader2 className="size-4 animate-spin" />} Generate
            </button>
          ) : (
            <p className="mt-4 text-xs text-muted-foreground">Viewers can download existing reports but cannot generate new ones.</p>
          )}
        </Panel>
        <Panel title="Previous exports" bodyClassName="p-0">
          {reports.isLoading ? (
            <div className="p-5"><SkeletonRows rows={5} cols={4} /></div>
          ) : reports.isError ? (
            <div className="p-5"><ErrorState error={reports.error} onRetry={() => void reports.refetch()} /></div>
          ) : !reports.data?.length ? (
            <EmptyState icon={<FileText className="size-5" />} title="No reports generated yet" body="Exports you generate appear here with their author and timestamp." />
          ) : (
            <ul className="divide-y hairline">
              {reports.data.map((r) => (
                <li key={r.id} className="flex items-center gap-4 px-5 py-3.5" data-testid={`row-report-${r.id}`}>
                  <span className="grid size-9 shrink-0 place-items-center rounded-lg border hairline bg-white/[0.03] font-mono text-[10px] text-cyan">{r.format}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 text-[13px] font-medium">
                      {r.type.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase())}
                      {r.deviceName && <span className="font-normal text-muted-foreground">· {r.deviceName}</span>}
                      <Pill tone={r.status === "COMPLETED" ? "ok" : "crit"}>{r.status}</Pill>
                    </div>
                    <div className="truncate text-xs text-muted-foreground">{r.error ?? r.summary}</div>
                    <div className="font-mono text-[11px] text-muted-foreground">{fmtDate(r.createdAt)} · {r.createdByEmail} · {fmtBytes(r.sizeBytes)}</div>
                  </div>
                  {r.downloadPath && r.status === "COMPLETED" && (
                    <a href={r.downloadPath} target="_blank" rel="noreferrer" data-testid={`link-download-${r.id}`} className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs hover:bg-white/[0.04]">
                      <Download className="size-3.5" /> Download
                    </a>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
