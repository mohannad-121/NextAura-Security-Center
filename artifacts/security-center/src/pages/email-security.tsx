import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Loader2, MailSearch } from "lucide-react";
import { getListEmailDomainAuditsQueryKey, useListEmailDomainAudits, useRunEmailDomainAudit, type DnsCheckResult, type EmailDomainAudit } from "@workspace/api-client-react";
import { useT } from "@/i18n";
import { canAnalyze, usePageMeta, useRole } from "@/lib/session";
import { errMsg, fmtDate } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Caveat, CheckPill, EmptyState, ErrorState, PageHeader, Panel, SkeletonRows } from "@/components/app/primitives";

export default function EmailSecurity() {
  const t = useT();
  usePageMeta(t("email.title"), t("email.description"));
  const role = useRole();
  const qc = useQueryClient();
  const [domain, setDomain] = useState("");
  const [selectors, setSelectors] = useState("");
  const [current, setCurrent] = useState<EmailDomainAudit | null>(null);
  const history = useListEmailDomainAudits();
  const run = useRunEmailDomainAudit({
    mutation: {
      onSuccess: (a) => {
        setCurrent(a);
        void qc.invalidateQueries({ queryKey: getListEmailDomainAuditsQueryKey() });
      },
    },
  });
  const shown = current ?? history.data?.[0] ?? null;

  return (
    <div>
      <PageHeader eyebrow="Domain" title={t("email.title")} description={t("email.description")} />
      <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
        <div className="space-y-5">
          {canAnalyze(role) && (
            <Panel title="Run audit">
              <form
                className="flex flex-col gap-3 md:flex-row"
                onSubmit={(e) => {
                  e.preventDefault();
                  const sels = selectors.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean).slice(0, 10);
                  if (domain.trim().length >= 3) run.mutate({ data: { domain: domain.trim().toLowerCase(), ...(sels.length ? { dkimSelectors: sels } : {}) } });
                }}
              >
                <input data-testid="input-domain" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" className="h-9 flex-1 rounded-lg border border-input bg-card px-3 font-mono text-[13px] outline-none focus:border-violet" />
                <input data-testid="input-selectors" value={selectors} onChange={(e) => setSelectors(e.target.value)} placeholder="DKIM selectors (optional): google, selector1" className="h-9 flex-1 rounded-lg border border-input bg-card px-3 text-[13px] outline-none focus:border-violet" />
                <button data-testid="button-run-audit" disabled={run.isPending || domain.trim().length < 3} className="inline-flex h-9 items-center justify-center gap-2 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground disabled:opacity-50">
                  {run.isPending && <Loader2 className="size-4 animate-spin" />} Audit
                </button>
              </form>
              {run.isError && <p className="mt-2 text-xs text-crit">{errMsg(run.error)}</p>}
            </Panel>
          )}
          {run.isPending ? (
            <Panel><SkeletonRows rows={6} cols={3} /></Panel>
          ) : shown ? (
            <AuditResult a={shown} />
          ) : history.isLoading ? (
            <Panel><SkeletonRows rows={4} cols={3} /></Panel>
          ) : (
            <Panel><EmptyState icon={<MailSearch className="size-5" />} title="No domain audited yet" body="Enter a domain to check its SPF, DMARC and DKIM records." /></Panel>
          )}
        </div>
        <Panel title="History" bodyClassName="p-0">
          {history.isLoading ? (
            <div className="p-5"><SkeletonRows rows={4} cols={1} /></div>
          ) : history.isError ? (
            <div className="p-5"><ErrorState error={history.error} onRetry={() => void history.refetch()} /></div>
          ) : !history.data?.length ? (
            <p className="p-5 text-xs text-muted-foreground">No audits yet.</p>
          ) : (
            <ul className="divide-y hairline">
              {history.data.map((a) => (
                <li key={a.id}>
                  <button onClick={() => setCurrent(a)} data-testid={`row-audit-${a.id}`} className={cn("flex w-full items-center justify-between gap-2 px-5 py-3 text-left hover:bg-white/[0.025]", shown?.id === a.id && "bg-white/[0.03]")}>
                    <span className="min-w-0">
                      <span className="block truncate font-mono text-xs">{a.domain}</span>
                      <span className="block text-[11px] text-muted-foreground">{fmtDate(a.checkedAt)}</span>
                    </span>
                    <CheckPill s={a.overallStatus} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

function AuditResult({ a }: { a: EmailDomainAudit }) {
  return (
    <div className="space-y-5">
      <Caveat tone="warn"><span className="font-medium">Limitations: </span>{a.limitations}</Caveat>
      <Panel title={<span className="font-mono">{a.domain}</span>} subtitle={`Checked ${fmtDate(a.checkedAt)} by ${a.checkedByEmail}`} actions={<CheckPill s={a.overallStatus} />}>
        <div className="space-y-4">
          <DnsBlock name="SPF" r={a.spf} />
          <DnsBlock name="DMARC" r={a.dmarc} />
          {a.dkim.length ? a.dkim.map((d) => <DnsBlock key={d.selector} name={`DKIM · ${d.selector}`} r={d} />) : <p className="text-xs text-muted-foreground">No DKIM selectors checked. DKIM selectors cannot be discovered from DNS; supply them to test.</p>}
          <div>
            <div className="eyebrow mb-1.5">MX records</div>
            {a.mx.length ? <ul className="space-y-1 font-mono text-xs">{a.mx.map((m) => <li key={m}>{m}</li>)}</ul> : <p className="text-xs text-unknown">None found</p>}
          </div>
        </div>
      </Panel>
    </div>
  );
}

function DnsBlock({ name, r }: { name: string; r: DnsCheckResult }) {
  return (
    <div className="rounded-xl border hairline bg-background/40 p-4">
      <div className="flex items-center justify-between">
        <span className="text-[13px] font-semibold">{name}</span>
        <CheckPill s={r.status} />
      </div>
      <pre className="mt-2 whitespace-pre-wrap break-all rounded-lg border hairline bg-background/60 p-2.5 font-mono text-xs text-cyan">{r.record ?? "No record found"}</pre>
      <p className="mt-2 text-[13px] text-slate-300">{r.evaluation}</p>
      {r.recommendations.length > 0 && (
        <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-muted-foreground">
          {r.recommendations.map((x, i) => <li key={i}>{x}</li>)}
        </ul>
      )}
    </div>
  );
}
