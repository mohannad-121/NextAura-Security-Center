import { useState } from "react";
import { Link } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import {
  FindingStatus,
  getGetDashboardSummaryQueryKey,
  getGetFindingQueryKey,
  getListFindingsQueryKey,
  useGetFinding,
  useUpdateFinding,
  type Finding,
} from "@workspace/api-client-react";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { canAnalyze, useRole } from "@/lib/session";
import { useT } from "@/i18n";
import { errMsg, fmtDate } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Caveat, ErrorState, KV, Pill, SeverityPill, SkeletonRows, confidenceTone, type Tone } from "./primitives";

export const findingStatusTone = (s: FindingStatus): Tone =>
  ({ OPEN: "crit", ACKNOWLEDGED: "warn", RESOLVED: "ok", FALSE_POSITIVE: "neutral" } as const)[s];

export function FindingSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full overflow-y-auto border-l border-border bg-[#11152a] p-0 sm:max-w-[560px] scroll-thin">
        {id && <FindingBody id={id} />}
      </SheetContent>
    </Sheet>
  );
}

function FindingBody({ id }: { id: string }) {
  const q = useGetFinding(id, { query: { enabled: !!id, queryKey: getGetFindingQueryKey(id) } });
  if (q.isLoading)
    return (
      <div className="p-6">
        <SheetTitle className="sr-only">Loading finding</SheetTitle>
        <SkeletonRows rows={10} cols={2} />
      </div>
    );
  if (q.isError || !q.data)
    return (
      <div className="p-6">
        <SheetTitle className="sr-only">Error</SheetTitle>
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      </div>
    );
  return <FindingDetail f={q.data} />;
}

function FindingDetail({ f }: { f: Finding }) {
  const t = useT();
  const role = useRole();
  const qc = useQueryClient();
  const { toast } = useToast();
  const [note, setNote] = useState("");
  const update = useUpdateFinding({
    mutation: {
      onSuccess: (data) => {
        qc.setQueryData(getGetFindingQueryKey(f.id), data);
        void qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
        void qc.invalidateQueries({ queryKey: getGetDashboardSummaryQueryKey() });
        setNote("");
        toast({ title: `Finding marked ${data.status.replace(/_/g, " ").toLowerCase()}`, description: "Dashboard record updated. The endpoint was not changed." });
      },
      onError: (e) => toast({ title: "Status not changed", description: errMsg(e), variant: "destructive" }),
    },
  });

  return (
    <div>
      <div className="border-b hairline p-6 pb-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityPill s={f.severity} />
          <Pill tone={findingStatusTone(f.status)}>{f.status.replace(/_/g, " ")}</Pill>
          <Pill tone={confidenceTone(f.confidence)} dot={false}>
            {f.confidence} confidence
          </Pill>
        </div>
        <SheetTitle className="mt-3 text-lg font-semibold leading-snug tracking-tight">{f.title}</SheetTitle>
        <SheetDescription className="mt-1 text-[13px] text-muted-foreground">
          <Link href={`/devices/${f.deviceId}`} className="text-cyan hover:underline">
            {f.deviceName}
          </Link>{" "}
          · Rule <span className="font-mono">{f.ruleId}</span>
        </SheetDescription>
      </div>
      <div className="space-y-6 p-6">
        <p className="text-[13px] leading-relaxed text-slate-300">{f.description}</p>
        <section>
          <div className="eyebrow mb-2">Evidence</div>
          <pre className="whitespace-pre-wrap rounded-lg border hairline bg-background/60 p-3 font-mono text-xs text-cyan">{f.evidence}</pre>
          <div className="mt-1.5 text-[11px] text-muted-foreground">Source: {f.detectionSource}</div>
        </section>
        <section>
          <div className="eyebrow mb-2">Manual remediation</div>
          <p className="text-[13px] leading-relaxed text-slate-300">{f.remediation}</p>
        </section>
        <section>
          <div className="eyebrow mb-1">Provenance</div>
          <dl>
            <KV label="Collector" mono>{f.collectorId ?? "UNKNOWN"}</KV>
            <KV label="Raw status" mono>{f.rawStatus ?? "UNKNOWN"}</KV>
            <KV label="Assessment" mono>{f.assessmentId ?? "UNKNOWN"}</KV>
            <KV label="Collector version" mono>{f.collectorVersion ?? "UNKNOWN"}</KV>
            <KV label="First seen">{fmtDate(f.firstSeenAt)}</KV>
            <KV label="Last seen">{fmtDate(f.lastSeenAt)}</KV>
            {f.statusChangedAt && (
              <KV label="Status changed">
                {fmtDate(f.statusChangedAt)} by {f.statusChangedByEmail ?? "unknown"}
              </KV>
            )}
          </dl>
        </section>
        <section className="rounded-xl border hairline bg-white/[0.02] p-4">
          <div className="eyebrow mb-3">Status</div>
          <Caveat>{t("findings.ackCaveat")}</Caveat>
          {canAnalyze(role) ? (
            <>
              <Textarea
                data-testid="input-finding-note"
                value={note}
                onChange={(e) => setNote(e.target.value.slice(0, 1000))}
                placeholder="Optional note for the audit log"
                className="mt-3 min-h-[72px] text-[13px]"
              />
              <div className="mt-3 grid grid-cols-2 gap-2">
                {Object.values(FindingStatus).map((s) => (
                  <button
                    key={s}
                    disabled={s === f.status || update.isPending}
                    data-testid={`button-status-${s}`}
                    onClick={() => update.mutate({ id: f.id, data: { status: s, ...(note.trim() ? { note: note.trim() } : {}) } })}
                    className={cn(
                      "inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-colors disabled:cursor-not-allowed",
                      s === f.status ? "border-violet/40 bg-violet/15 text-foreground" : "border-border hover:bg-white/[0.04] disabled:opacity-50",
                    )}
                  >
                    {update.isPending && update.variables?.data.status === s && <Loader2 className="size-3 animate-spin" />}
                    {s === f.status ? "Current: " : "Mark "}
                    {s.replace(/_/g, " ").toLowerCase()}
                  </button>
                ))}
              </div>
            </>
          ) : (
            <p className="mt-3 text-xs text-muted-foreground">Viewers cannot change finding status.</p>
          )}
        </section>
      </div>
    </div>
  );
}
