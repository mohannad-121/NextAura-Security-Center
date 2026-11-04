import { useMemo, useState } from "react";
import { Search, ShieldCheck } from "lucide-react";
import { FindingStatus, Severity, useListFindings, type ListFindingsParams } from "@workspace/api-client-react";
import { useT } from "@/i18n";
import { usePageMeta } from "@/lib/session";
import { fmtDate, fmtRel } from "@/lib/format";
import { Caveat, EmptyState, ErrorState, FilterSelect, PageHeader, Panel, Pill, SeverityPill, SkeletonRows } from "@/components/app/primitives";
import { FindingSheet, findingStatusTone } from "@/components/app/finding-sheet";

export default function Findings() {
  const t = useT();
  usePageMeta(t("findings.title"), t("findings.description"));
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [status, setStatus] = useState<FindingStatus | "">("OPEN");
  const [sel, setSel] = useState<string | null>(null);
  const params = useMemo<ListFindingsParams>(() => {
    const p: ListFindingsParams = {};
    if (search.trim()) p.search = search.trim();
    if (severity) p.severity = severity;
    if (status) p.status = status;
    return p;
  }, [search, severity, status]);
  const q = useListFindings(params);

  return (
    <div>
      <PageHeader eyebrow="Detection" title={t("findings.title")} description={t("findings.description")} />
      <Caveat className="mb-4">{t("findings.ackCaveat")}</Caveat>
      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap gap-2 border-b hairline p-3.5">
          <div className="relative min-w-[220px] flex-1">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input data-testid="input-search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search title, rule or device" className="h-9 w-full rounded-lg border border-input bg-card pl-8 pr-3 text-[13px] outline-none focus:border-violet" />
          </div>
          <FilterSelect testId="select-severity" value={severity} onChange={setSeverity} options={Object.values(Severity)} allLabel="Any severity" />
          <FilterSelect testId="select-status" value={status} onChange={setStatus} options={Object.values(FindingStatus)} allLabel="Any status" />
        </div>
        {q.isLoading ? (
          <div className="p-5"><SkeletonRows rows={8} cols={5} /></div>
        ) : q.isError ? (
          <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
        ) : !q.data?.length ? (
          <EmptyState
            icon={<ShieldCheck className="size-5" />}
            title={status === "OPEN" && !severity && !search ? "No high-severity findings observed" : t("findings.empty")}
            body="Findings only arise from checks that could be observed. Review device coverage before concluding a device is clean."
          />
        ) : (
          <div className="overflow-x-auto scroll-thin">
            <table className="w-full min-w-[860px] text-[13px]">
              <thead>
                <tr className="eyebrow border-b hairline text-left">
                  <th className="px-5 py-3 font-normal">Severity</th>
                  <th className="px-3 py-3 font-normal">Finding</th>
                  <th className="px-3 py-3 font-normal">Device</th>
                  <th className="px-3 py-3 font-normal">Status</th>
                  <th className="px-3 py-3 font-normal">First seen</th>
                  <th className="px-5 py-3 text-right font-normal">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {q.data.map((f) => (
                  <tr key={f.id} onClick={() => setSel(f.id)} data-testid={`row-finding-${f.id}`} className="cursor-pointer border-b hairline transition-colors last:border-0 hover:bg-white/[0.025]">
                    <td className="px-5 py-3"><SeverityPill s={f.severity} /></td>
                    <td className="px-3 py-3">
                      <div className="font-medium">{f.title}</div>
                      <div className="font-mono text-[11px] text-muted-foreground">{f.ruleId}</div>
                    </td>
                    <td className="px-3 py-3 text-muted-foreground">{f.deviceName}</td>
                    <td className="px-3 py-3"><Pill tone={findingStatusTone(f.status)}>{f.status.replace(/_/g, " ")}</Pill></td>
                    <td className="px-3 py-3 text-xs text-muted-foreground">{fmtDate(f.firstSeenAt)}</td>
                    <td className="px-5 py-3 text-right font-mono text-xs text-muted-foreground">{fmtRel(f.lastSeenAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="border-t hairline px-5 py-2.5 font-mono text-[11px] text-muted-foreground">{q.data.length} findings</div>
          </div>
        )}
      </Panel>
      <FindingSheet id={sel} onClose={() => setSel(null)} />
    </div>
  );
}
