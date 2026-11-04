import { useMemo, useState } from "react";
import { Link } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { Bug, ExternalLink, Loader2, RefreshCw, Search } from "lucide-react";
import {
  MatchConfidence,
  Severity,
  getGetVulnerabilityIntelligenceStatusQueryKey,
  getListVulnerabilitiesQueryKey,
  useGetVulnerabilityIntelligenceStatus,
  useListDevices,
  useListVulnerabilities,
  useRefreshVulnerabilityIntelligence,
  type ListVulnerabilitiesParams,
  type VulnerabilityMatch,
} from "@workspace/api-client-react";
import { useT } from "@/i18n";
import { canAnalyze, usePageMeta, useRole } from "@/lib/session";
import { errMsg, fmtDate, fmtDay, fmtRel } from "@/lib/format";
import { useToast } from "@/hooks/use-toast";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Caveat, EmptyState, ErrorState, FilterSelect, KV, PageHeader, Panel, Pill, SeverityPill, SkeletonRows, confidenceTone } from "@/components/app/primitives";

export default function Vulnerabilities() {
  const t = useT();
  usePageMeta(t("vulns.title"), t("vulns.description"));
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [mc, setMc] = useState<MatchConfidence | "">("");
  const [kevOnly, setKevOnly] = useState(false);
  const [deviceId, setDeviceId] = useState("");
  const [sel, setSel] = useState<VulnerabilityMatch | null>(null);
  const devices = useListDevices();
  const params = useMemo<ListVulnerabilitiesParams>(() => {
    const p: ListVulnerabilitiesParams = {};
    if (search.trim()) p.search = search.trim();
    if (severity) p.severity = severity;
    if (mc) p.matchConfidence = mc;
    if (kevOnly) p.kevOnly = true;
    if (deviceId) p.deviceId = deviceId;
    return p;
  }, [search, severity, mc, kevOnly, deviceId]);
  const q = useListVulnerabilities(params);

  return (
    <div>
      <PageHeader eyebrow="Intelligence" title={t("vulns.title")} description={t("vulns.description")} />
      <IntelPanel />
      <Panel className="mt-5" bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b hairline p-3.5">
          <div className="relative min-w-[220px] flex-1">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input data-testid="input-search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="CVE, vendor or product" className="h-9 w-full rounded-lg border border-input bg-card pl-8 pr-3 text-[13px] outline-none focus:border-violet" />
          </div>
          <FilterSelect testId="select-severity" value={severity} onChange={setSeverity} options={Object.values(Severity)} allLabel="Any severity" />
          <FilterSelect testId="select-confidence" value={mc} onChange={setMc} options={Object.values(MatchConfidence)} allLabel="Any match confidence" />
          <select data-testid="select-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} className="h-9 max-w-[200px] rounded-lg border border-input bg-card px-2.5 text-[13px] outline-none focus:border-violet">
            <option value="">All devices</option>
            {devices.data?.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
          <label className="flex h-9 items-center gap-2 px-1 text-[12px] text-muted-foreground">
            <Switch checked={kevOnly} onCheckedChange={setKevOnly} data-testid="switch-kev" /> Known exploited only
          </label>
        </div>
        {q.isLoading ? (
          <div className="p-5"><SkeletonRows rows={8} cols={6} /></div>
        ) : q.isError ? (
          <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
        ) : !q.data?.length ? (
          <EmptyState icon={<Bug className="size-5" />} title="No CVE matches" body="No installed software matched cached intelligence with these filters. Matching is limited by inventory completeness and feed freshness." />
        ) : (
          <div className="overflow-x-auto scroll-thin">
            <table className="w-full min-w-[920px] text-[13px]">
              <thead>
                <tr className="eyebrow border-b hairline text-left">
                  <th className="px-5 py-3 font-normal">CVE</th>
                  <th className="px-3 py-3 font-normal">Severity · CVSS</th>
                  <th className="px-3 py-3 font-normal">Software</th>
                  <th className="px-3 py-3 font-normal">Device</th>
                  <th className="px-3 py-3 font-normal">Match</th>
                  <th className="px-5 py-3 font-normal">KEV</th>
                </tr>
              </thead>
              <tbody>
                {q.data.map((v) => (
                  <tr key={v.id} onClick={() => setSel(v)} data-testid={`row-vuln-${v.id}`} className="cursor-pointer border-b hairline transition-colors last:border-0 hover:bg-white/[0.025]">
                    <td className="px-5 py-3 font-mono text-xs">{v.cveId}</td>
                    <td className="px-3 py-3"><div className="flex items-center gap-2"><SeverityPill s={v.severity} /><span className="font-mono text-xs tabular text-muted-foreground">{v.cvssScore?.toFixed(1) ?? "—"}</span></div></td>
                    <td className="px-3 py-3">{v.vendor} {v.product} <span className="font-mono text-xs text-muted-foreground">{v.installedVersion}</span></td>
                    <td className="px-3 py-3 text-muted-foreground">{v.deviceName}</td>
                    <td className="px-3 py-3"><Pill tone={confidenceTone(v.matchConfidence)} dot={false}>{v.matchConfidence}</Pill></td>
                    <td className="px-5 py-3">{v.knownExploited ? <Pill tone="crit">Exploited</Pill> : <span className="text-xs text-muted-foreground">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <Sheet open={!!sel} onOpenChange={(o) => !o && setSel(null)}>
        <SheetContent className="w-full overflow-y-auto border-l border-border bg-[#11152a] sm:max-w-[560px] scroll-thin">
          {sel && (
            <div className="space-y-6">
              <div>
                <div className="flex flex-wrap gap-2">
                  <SeverityPill s={sel.severity} />
                  <Pill tone={confidenceTone(sel.matchConfidence)} dot={false}>{sel.matchConfidence} match</Pill>
                  {sel.knownExploited && <Pill tone="crit">CISA KEV · added {fmtDay(sel.kevDateAdded)}</Pill>}
                </div>
                <SheetTitle className="mt-3 font-mono text-lg">{sel.cveId}</SheetTitle>
                <SheetDescription className="mt-1 text-[13px]">
                  {sel.vendor} {sel.product} on <Link href={`/devices/${sel.deviceId}`} className="text-cyan hover:underline">{sel.deviceName}</Link>
                </SheetDescription>
              </div>
              <p className="text-[13px] leading-relaxed text-slate-300">{sel.description}</p>
              <dl>
                <KV label="Installed version" mono>{sel.installedVersion}</KV>
                <KV label="Affected range" mono>{sel.affectedRange}</KV>
                <KV label="CVSS" mono>{sel.cvssScore ?? "UNKNOWN"}</KV>
                <KV label="Vector" mono>{sel.cvssVector ?? "—"}</KV>
                <KV label="Published">{fmtDay(sel.publishedAt)}</KV>
                <KV label="First seen">{fmtDate(sel.firstSeenAt)}</KV>
                <KV label="Last seen">{fmtDate(sel.lastSeenAt)}</KV>
              </dl>
              <section>
                <div className="eyebrow mb-2">Why matched & limitations</div>
                <Caveat>{sel.matchReason}</Caveat>
              </section>
              <section>
                <div className="eyebrow mb-2">Remediation</div>
                <p className="text-[13px] text-slate-300">{sel.remediation}</p>
              </section>
              {sel.references.length > 0 && (
                <section>
                  <div className="eyebrow mb-2">References</div>
                  <ul className="space-y-1.5">
                    {sel.references.map((r) => (
                      <li key={r}>
                        <a href={r} target="_blank" rel="noreferrer noopener" className="inline-flex max-w-full items-center gap-1.5 break-all text-xs text-cyan hover:underline">
                          <ExternalLink className="size-3 shrink-0" /> {r}
                        </a>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function IntelPanel() {
  const role = useRole();
  const qc = useQueryClient();
  const { toast } = useToast();
  const q = useGetVulnerabilityIntelligenceStatus({ query: { queryKey: getGetVulnerabilityIntelligenceStatusQueryKey(), refetchInterval: (query) => (query.state.data?.refreshInProgress ? 5000 : false) } });
  const refresh = useRefreshVulnerabilityIntelligence({
    mutation: {
      onSuccess: (data) => {
        qc.setQueryData(getGetVulnerabilityIntelligenceStatusQueryKey(), data);
        void qc.invalidateQueries({ queryKey: getListVulnerabilitiesQueryKey() });
        toast({ title: "Intelligence refresh started" });
      },
      onError: (e) => toast({ title: "Refresh not started", description: errMsg(e), variant: "destructive" }),
    },
  });
  const s = q.data;
  const blocked = !!s?.nextAllowedRefreshAt && new Date(s.nextAllowedRefreshAt).getTime() > Date.now();
  return (
    <Panel
      title="Intelligence feed status"
      subtitle="NVD CVE cache and CISA Known Exploited Vulnerabilities catalog"
      actions={
        canAnalyze(role) && s ? (
          <button
            data-testid="button-refresh-intel"
            disabled={blocked || s.refreshInProgress || refresh.isPending}
            onClick={() => refresh.mutate()}
            title={blocked ? `Next refresh allowed ${fmtRel(s.nextAllowedRefreshAt)}` : undefined}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs hover:bg-white/[0.04] disabled:opacity-50"
          >
            {s.refreshInProgress || refresh.isPending ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}
            {s.refreshInProgress ? "Refreshing" : blocked ? `Available ${fmtRel(s.nextAllowedRefreshAt)}` : "Refresh intelligence"}
          </button>
        ) : undefined
      }
    >
      {q.isLoading ? (
        <SkeletonRows rows={2} cols={4} />
      ) : q.isError || !s ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-xl border hairline bg-background/40 p-3.5">
            <div className="flex items-center justify-between"><span className="eyebrow">NVD</span><Pill tone={s.nvdLastError ? "crit" : s.nvdLastSyncAt ? "ok" : "neutral"}>{s.nvdLastError ? "Error" : s.nvdLastSyncAt ? "Synced" : "Never synced"}</Pill></div>
            <div className="mt-2 text-xl font-semibold tabular">{s.nvdCachedCves.toLocaleString()} <span className="text-xs font-normal text-muted-foreground">cached CVEs</span></div>
            <div className="mt-1 text-[11px] text-muted-foreground">Last sync {fmtRel(s.nvdLastSyncAt)} · API key {s.nvdConfigured ? "configured" : "not configured (lower rate limit)"}</div>
            {s.nvdLastError && <div className="mt-1 font-mono text-[11px] text-crit">{s.nvdLastError}</div>}
          </div>
          <div className="rounded-xl border hairline bg-background/40 p-3.5">
            <div className="flex items-center justify-between"><span className="eyebrow">CISA KEV</span><Pill tone={s.kevLastError ? "crit" : s.kevLastSyncAt ? "ok" : "neutral"}>{s.kevLastError ? "Error" : s.kevLastSyncAt ? "Synced" : "Never synced"}</Pill></div>
            <div className="mt-2 text-xl font-semibold tabular">{s.kevCatalogEntries.toLocaleString()} <span className="text-xs font-normal text-muted-foreground">entries</span></div>
            <div className="mt-1 text-[11px] text-muted-foreground">Last sync {fmtRel(s.kevLastSyncAt)}</div>
            {s.kevLastError && <div className="mt-1 font-mono text-[11px] text-crit">{s.kevLastError}</div>}
          </div>
          <div className="rounded-xl border hairline bg-background/40 p-3.5">
            <span className="eyebrow">Last match run</span>
            <div className="mt-2 text-sm">{fmtDate(s.lastMatchRunAt)}</div>
            <div className="mt-1 text-[11px] text-muted-foreground">Refresh is rate-limited to protect upstream feeds.</div>
          </div>
        </div>
      )}
    </Panel>
  );
}
