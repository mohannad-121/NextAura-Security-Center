import { useMemo, useState, type ReactNode } from "react";
import { Link, useLocation, useParams } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Ban, Loader2, Radar, ShieldCheck } from "lucide-react";
import {
  CollectorId,
  getGetDeviceQueryKey,
  getListDeviceAssessmentRequestsQueryKey,
  getListDeviceAssessmentsQueryKey,
  getListDeviceChecksQueryKey,
  getListDeviceSoftwareQueryKey,
  getListDeviceStartupItemsQueryKey,
  getListDeviceThreatsQueryKey,
  getListDevicesQueryKey,
  getListFindingsQueryKey,
  getListVulnerabilitiesQueryKey,
  useGetDevice,
  useListDeviceAssessmentRequests,
  useListDeviceAssessments,
  useListDeviceChecks,
  useListDeviceSoftware,
  useListDeviceStartupItems,
  useListDeviceThreats,
  useListFindings,
  useListVulnerabilities,
  useRequestDeviceAssessment,
  useRevokeDevice,
  type DeviceDetail,
  type SecurityCheck,
} from "@workspace/api-client-react";
import { canAdmin, canAnalyze, usePageMeta, useRole } from "@/lib/session";
import { useT } from "@/i18n";
import { errMsg, fmtDate, fmtRel, humanize } from "@/lib/format";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Caveat,
  CheckPill,
  EmptyState,
  ErrorState,
  KV,
  Meter,
  Panel,
  Pill,
  SeverityPill,
  SkeletonBlock,
  SkeletonRows,
  checkTone,
  confidenceTone,
  coverageTone,
  reliabilityTone,
  toneDot,
} from "@/components/app/primitives";
import { FindingSheet, findingStatusTone } from "@/components/app/finding-sheet";
import { OsGlyph } from "./devices";

const COLLECTOR_DESC: Record<CollectorId, string> = {
  SYSTEM_INFO: "Hostname, OS version, hardware model, CPU and memory",
  SECURITY_POSTURE: "Encryption, firewall, update and OS support checks",
  ANTIVIRUS_STATUS: "Antivirus product state, real-time protection, definitions, detection history",
  SOFTWARE_INVENTORY: "Installed applications and versions",
  STARTUP_INVENTORY: "Run keys, scheduled tasks, services, launch agents and login items",
  SAFE_NETWORK_SUMMARY: "Listening-port count and network adapter summary (no traffic content)",
};

export default function DeviceDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id ?? "";
  const q = useGetDevice(id, { query: { enabled: !!id, queryKey: getGetDeviceQueryKey(id) } });
  usePageMeta(q.data ? q.data.name : "Device", "Device posture, evidence, software, vulnerabilities and agent health.");

  if (q.isLoading)
    return (
      <div className="space-y-5">
        <SkeletonBlock className="h-24" />
        <div className="grid gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonBlock key={i} className="h-28" />
          ))}
        </div>
        <SkeletonBlock className="h-96" />
      </div>
    );
  if (q.isError || !q.data)
    return (
      <div className="mx-auto max-w-lg pt-10">
        <ErrorState error={q.error} onRetry={() => void q.refetch()} title={(q.error as { status?: number } | null)?.status === 404 ? "Device not found" : "We could not load this device."} />
        <Link href="/devices" className="mt-4 block text-center text-xs text-cyan">
          Back to devices
        </Link>
      </div>
    );
  return <Detail d={q.data} />;
}

function Detail({ d }: { d: DeviceDetail }) {
  const t = useT();
  const role = useRole();
  const [reqOpen, setReqOpen] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const revoked = d.status === "REVOKED";

  return (
    <div>
      <Link href="/devices" className="mb-4 inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground" data-testid="link-back">
        <ArrowLeft className="size-3.5" /> Devices
      </Link>
      <div className="rise mb-6 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <OsGlyph os={d.osType} className="size-4" />
            <span className="eyebrow">
              {d.operatingSystem.name} {d.operatingSystem.version} · {d.architecture}
            </span>
          </div>
          <h1 className="mt-1.5 text-[26px] font-semibold tracking-tight" data-testid="text-device-name">
            {d.name}
          </h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Pill tone={d.isOnline ? "ok" : "neutral"}>{d.isOnline ? "Online" : "Offline"}</Pill>
            <Pill tone={reliabilityTone(d.agentReliability)}>{d.agentReliability.replace(/_/g, " ")}</Pill>
            {revoked && <Pill tone="crit">Revoked</Pill>}
            <span className="text-xs text-muted-foreground">
              Last heartbeat {fmtRel(d.lastSeenAt, "never")} · Enrolled {fmtDate(d.enrolledAt)}
            </span>
          </div>
        </div>
        {!revoked && (
          <div className="flex gap-2">
            {canAnalyze(role) && (
              <button
                onClick={() => setReqOpen(true)}
                data-testid="button-request-assessment"
                className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-medium text-primary-foreground transition hover:brightness-110"
              >
                <Radar className="size-4" /> Request assessment
              </button>
            )}
            {canAdmin(role) && (
              <button
                onClick={() => setRevokeOpen(true)}
                data-testid="button-revoke"
                className="inline-flex items-center gap-2 rounded-lg border border-crit/40 px-3.5 py-2 text-sm text-crit transition-colors hover:bg-crit/10"
              >
                <Ban className="size-4" /> Revoke
              </button>
            )}
          </div>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="glass rise rounded-2xl p-4">
          <div className="eyebrow">Risk score</div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-[28px] font-semibold tabular" data-testid="text-risk-score">
              {d.riskScore ?? <span className="text-unknown">—</span>}
            </span>
            <span className="text-xs text-muted-foreground">/ 100</span>
            <SeverityPill s={d.riskLevel} />
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground">{t("common.lowScoreCaveat")}</div>
        </div>
        <div className="glass rise rise-1 rounded-2xl p-4">
          <div className="eyebrow">Evidence coverage</div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-[28px] font-semibold tabular" data-testid="text-coverage">
              {Math.round(d.coveragePercent)}%
            </span>
            <Pill tone={coverageTone(d.coverageStatus)}>{d.coverageStatus}</Pill>
          </div>
          <div className="mt-2.5">
            <Meter value={d.coveragePercent} tone={coverageTone(d.coverageStatus)} />
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground">Share of checks that produced an observable result.</div>
        </div>
        <div className="glass rise rise-2 rounded-2xl p-4">
          <div className="eyebrow">Check outcomes</div>
          <div className="mt-2 flex items-baseline gap-4">
            <div>
              <span className="text-[28px] font-semibold tabular text-crit">{d.failedCheckCount}</span>
              <span className="ml-1 text-xs text-muted-foreground">failed</span>
            </div>
            <div>
              <span className="text-[28px] font-semibold tabular text-unknown">{d.unknownCheckCount}</span>
              <span className="ml-1 text-xs text-muted-foreground">not observed</span>
            </div>
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground">Not-observed checks are never counted as passing.</div>
        </div>
        <div className="glass rise rise-3 rounded-2xl p-4">
          <div className="eyebrow">Open findings</div>
          <div className="mt-2 text-[28px] font-semibold tabular">
            {d.openFindings.CRITICAL + d.openFindings.HIGH + d.openFindings.MEDIUM + d.openFindings.LOW + d.openFindings.INFO}
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground">
            {d.openFindings.CRITICAL} critical · {d.openFindings.HIGH} high · {d.openFindings.MEDIUM} medium
          </div>
        </div>
      </div>

      <Tabs defaultValue="overview" className="mt-6">
        <div className="overflow-x-auto scroll-thin">
          <TabsList className="h-auto gap-1 rounded-xl border hairline bg-sidebar p-1">
            {[
              ["overview", "Overview"],
              ["posture", "Security posture"],
              ["findings", "Findings"],
              ["vulns", "Vulnerabilities"],
              ["software", "Software"],
              ["startup", "Startup items"],
              ["threats", "Threat history"],
              ["assessments", "Assessments"],
              ["agent", "Agent health"],
            ].map(([v, l]) => (
              <TabsTrigger key={v} value={v} data-testid={`tab-${v}`} className="rounded-lg px-3 py-1.5 text-[12.5px] data-[state=active]:bg-card data-[state=active]:text-foreground">
                {l}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value="overview" className="mt-5">
          <Overview d={d} />
        </TabsContent>
        <TabsContent value="posture" className="mt-5">
          <Posture id={d.id} />
        </TabsContent>
        <TabsContent value="findings" className="mt-5">
          <DeviceFindings id={d.id} />
        </TabsContent>
        <TabsContent value="vulns" className="mt-5">
          <DeviceVulns id={d.id} />
        </TabsContent>
        <TabsContent value="software" className="mt-5">
          <Software id={d.id} />
        </TabsContent>
        <TabsContent value="startup" className="mt-5">
          <Startup id={d.id} />
        </TabsContent>
        <TabsContent value="threats" className="mt-5">
          <Threats id={d.id} />
        </TabsContent>
        <TabsContent value="assessments" className="mt-5">
          <Assessments id={d.id} />
        </TabsContent>
        <TabsContent value="agent" className="mt-5">
          <AgentHealth d={d} />
        </TabsContent>
      </Tabs>

      <RequestDialog id={d.id} open={reqOpen} onOpenChange={setReqOpen} />
      <RevokeDialog d={d} open={revokeOpen} onOpenChange={setRevokeOpen} />
    </div>
  );
}

function Overview({ d }: { d: DeviceDetail }) {
  const os = d.operatingSystem;
  const av = d.antivirus;
  const avTone = av.status === "ACTIVE" || av.status === "THIRD_PARTY" ? "ok" : av.status === "DISABLED" ? "crit" : av.status === "PASSIVE" ? "warn" : "neutral";
  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <Panel title="Operating system">
        <dl>
          <KV label="Name">{os.name}</KV>
          <KV label="Version" mono>{os.version}</KV>
          <KV label="Build" mono>{os.build ?? "UNKNOWN"}</KV>
          <KV label="Architecture" mono>{os.architecture}</KV>
          <KV label="Vendor support">
            <CheckPill s={os.supportStatus} />
          </KV>
        </dl>
        <p className="mt-3 text-xs text-muted-foreground">{os.supportEvidence}</p>
      </Panel>
      <Panel title="Hardware">
        <dl>
          <KV label="Model">{d.hardware.model ?? <span className="text-unknown">UNKNOWN</span>}</KV>
          <KV label="CPU">{d.hardware.cpuModel ?? <span className="text-unknown">UNKNOWN</span>}</KV>
          <KV label="Memory" mono>{d.hardware.totalRamMb != null ? `${(d.hardware.totalRamMb / 1024).toFixed(1)} GB` : "UNKNOWN"}</KV>
          <KV label="Serial (last 4)" mono>{d.hardware.serialRedacted ?? "UNKNOWN"}</KV>
          <KV label="Agent version" mono>v{d.agentVersion}</KV>
        </dl>
      </Panel>
      <Panel title="Antivirus status">
        <dl>
          <KV label="Product">{av.product ?? <span className="text-unknown">UNKNOWN</span>}</KV>
          <KV label="State">
            <Pill tone={avTone}>{av.status.replace(/_/g, " ")}</Pill>
          </KV>
          <KV label="Real-time protection">
            <CheckPill s={av.realTimeProtection} />
          </KV>
          <KV label="Definitions age" mono>{av.definitionsAgeDays != null ? `${av.definitionsAgeDays} days` : "UNKNOWN"}</KV>
          <KV label="Last update">{fmtDate(av.lastDefinitionUpdate)}</KV>
          <KV label="Source" mono>{av.source ?? "UNKNOWN"}</KV>
        </dl>
        <Caveat className="mt-3">{av.note}</Caveat>
      </Panel>
      {d.latestAssessment && (
        <Panel title="Latest assessment" className="lg:col-span-3" subtitle={`Received ${fmtDate(d.latestAssessment.receivedAt)}`}>
          <CheckCountBar counts={d.latestAssessment.checkCounts} />
        </Panel>
      )}
    </div>
  );
}

function CheckCountBar({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts);
  const total = entries.reduce((a, [, v]) => a + v, 0) || 1;
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-full bg-white/[0.05]">
        {entries.map(([k, v]) => (v ? <div key={k} className={toneDot[checkTone(k)]} style={{ width: `${(v / total) * 100}%`, opacity: checkTone(k) === "neutral" ? 0.6 : 0.9 }} /> : null))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2">
        {entries.map(([k, v]) => (
          <div key={k} className="flex items-center gap-2 text-xs">
            <span className={cn("size-1.5 rounded-full", toneDot[checkTone(k)])} />
            <span className="text-muted-foreground">{k.replace(/_/g, " ")}</span>
            <span className="font-mono tabular">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Posture({ id }: { id: string }) {
  const q = useListDeviceChecks(id, { query: { enabled: !!id, queryKey: getListDeviceChecksQueryKey(id) } });
  const groups = useMemo(() => {
    const m = new Map<string, SecurityCheck[]>();
    for (const c of q.data ?? []) m.set(c.category, [...(m.get(c.category) ?? []), c]);
    return [...m.entries()];
  }, [q.data]);
  if (q.isLoading) return <Panel><SkeletonRows rows={8} cols={3} /></Panel>;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  if (!groups.length) return <Panel><EmptyState icon={<ShieldCheck className="size-5" />} title="No checks collected yet" body="Posture checks appear after the agent completes its first SECURITY_POSTURE collection." /></Panel>;
  return (
    <div className="space-y-5">
      {groups.map(([cat, checks]) => (
        <Panel key={cat} title={humanize(cat)} subtitle={`${checks.length} checks`} bodyClassName="p-0">
          <ul className="divide-y hairline">
            {checks.map((c) => (
              <CheckRow key={c.id} c={c} />
            ))}
          </ul>
        </Panel>
      ))}
    </div>
  );
}

function CheckRow({ c }: { c: SecurityCheck }) {
  const [open, setOpen] = useState(false);
  const neutral = checkTone(c.status) === "neutral";
  return (
    <li data-testid={`row-check-${c.id}`}>
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-3 px-5 py-3 text-left transition-colors hover:bg-white/[0.02]">
        <CheckPill s={c.status} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13px] font-medium">{c.title}</span>
          <span className="block truncate font-mono text-[11px] text-muted-foreground">{c.checkId}</span>
        </span>
        <span className="hidden font-mono text-[11px] text-muted-foreground md:block" title={fmtDate(c.collectedAt)}>
          {fmtRel(c.collectedAt)}
        </span>
      </button>
      {open && (
        <div className="grid gap-4 border-t hairline bg-background/30 px-5 py-4 md:grid-cols-2">
          <div>
            <div className="eyebrow mb-1.5">Evidence</div>
            <pre className="whitespace-pre-wrap rounded-lg border hairline bg-background/60 p-2.5 font-mono text-xs text-cyan">{c.evidence || "—"}</pre>
            {c.unavailableReason && (
              <div className={cn("mt-2 rounded-lg border border-dashed p-2.5 text-xs", neutral ? "border-unknown/40 text-slate-300" : "border-warn/30 text-amber-100")}>
                <span className="font-medium">Why unavailable: </span>
                {c.unavailableReason}
              </div>
            )}
          </div>
          <dl>
            <KV label="Collected">{fmtDate(c.collectedAt)}</KV>
            <KV label="Data source" mono>{c.dataSource}</KV>
            <KV label="Confidence">
              <Pill tone={confidenceTone(c.confidence)} dot={false}>{c.confidence}</Pill>
            </KV>
            <KV label="Required permissions">{c.requiredPermissions}</KV>
            <KV label="Collector" mono>{c.collectorId} v{c.collectorVersion}</KV>
          </dl>
        </div>
      )}
    </li>
  );
}

function DeviceFindings({ id }: { id: string }) {
  const params = { deviceId: id };
  const q = useListFindings(params, { query: { queryKey: getListFindingsQueryKey(params) } });
  const [sel, setSel] = useState<string | null>(null);
  return (
    <Panel title="Findings for this device" bodyClassName="p-0">
      {q.isLoading ? (
        <div className="p-5"><SkeletonRows rows={5} cols={4} /></div>
      ) : q.isError ? (
        <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
      ) : !q.data?.length ? (
        <EmptyState title="No high-severity findings observed" body="No rule has produced a finding for this device. Review coverage above: unobserved checks cannot produce findings." />
      ) : (
        <ul className="divide-y hairline">
          {q.data.map((f) => (
            <li key={f.id}>
              <button onClick={() => setSel(f.id)} data-testid={`row-finding-${f.id}`} className="flex w-full items-center gap-3 px-5 py-3 text-left transition-colors hover:bg-white/[0.025]">
                <SeverityPill s={f.severity} />
                <span className="min-w-0 flex-1 truncate text-[13px]">{f.title}</span>
                <Pill tone={findingStatusTone(f.status)}>{f.status.replace(/_/g, " ")}</Pill>
                <span className="hidden font-mono text-[11px] text-muted-foreground md:block">{fmtRel(f.lastSeenAt)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <FindingSheet id={sel} onClose={() => setSel(null)} />
    </Panel>
  );
}

function DeviceVulns({ id }: { id: string }) {
  const params = { deviceId: id };
  const q = useListVulnerabilities(params, { query: { queryKey: getListVulnerabilitiesQueryKey(params) } });
  return (
    <Panel title="Vulnerability findings" subtitle="Installed software matched to published CVEs" bodyClassName="p-0">
      {q.isLoading ? (
        <div className="p-5"><SkeletonRows rows={5} cols={5} /></div>
      ) : q.isError ? (
        <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
      ) : !q.data?.length ? (
        <EmptyState title="No CVE matches recorded" body="Matching depends on software inventory and the cached intelligence feed. Absence of a match is not proof that no vulnerability exists." />
      ) : (
        <div className="overflow-x-auto scroll-thin">
          <table className="w-full min-w-[720px] text-[13px]">
            <thead>
              <tr className="eyebrow border-b hairline text-left">
                <th className="px-5 py-2.5 font-normal">CVE</th>
                <th className="px-3 py-2.5 font-normal">Software</th>
                <th className="px-3 py-2.5 font-normal">Severity</th>
                <th className="px-3 py-2.5 font-normal">Match</th>
                <th className="px-5 py-2.5 font-normal">KEV</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((v) => (
                <tr key={v.id} className="border-b hairline last:border-0">
                  <td className="px-5 py-2.5 font-mono text-xs">{v.cveId}</td>
                  <td className="px-3 py-2.5">
                    {v.product} <span className="font-mono text-xs text-muted-foreground">{v.installedVersion}</span>
                  </td>
                  <td className="px-3 py-2.5"><SeverityPill s={v.severity} /></td>
                  <td className="px-3 py-2.5"><Pill tone={confidenceTone(v.matchConfidence)} dot={false}>{v.matchConfidence}</Pill></td>
                  <td className="px-5 py-2.5">{v.knownExploited ? <Pill tone="crit">Known exploited</Pill> : <span className="text-xs text-muted-foreground">No</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="border-t hairline px-5 py-2.5">
            <Link href="/vulnerabilities" className="text-xs text-cyan hover:underline">Open full vulnerability view</Link>
          </div>
        </div>
      )}
    </Panel>
  );
}

function SimpleTable({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto scroll-thin">
      <table className="w-full min-w-[720px] text-[13px]">
        <thead>
          <tr className="eyebrow border-b hairline text-left">
            {head.map((h, i) => (
              <th key={h} className={cn("py-2.5 font-normal", i === 0 ? "px-5" : "px-3")}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function Software({ id }: { id: string }) {
  const q = useListDeviceSoftware(id, { query: { enabled: !!id, queryKey: getListDeviceSoftwareQueryKey(id) } });
  const [s, setS] = useState("");
  const rows = (q.data ?? []).filter((x) => !s || `${x.name} ${x.vendor ?? ""}`.toLowerCase().includes(s.toLowerCase()));
  return (
    <Panel
      title="Software inventory"
      subtitle={q.data ? `${q.data.length} items · collected ${fmtRel(q.data[0]?.collectedAt)}` : undefined}
      actions={<input value={s} onChange={(e) => setS(e.target.value)} data-testid="input-software-search" placeholder="Filter" className="h-8 w-40 rounded-lg border border-input bg-card px-2.5 text-xs outline-none focus:border-violet" />}
      bodyClassName="p-0"
    >
      {q.isLoading ? (
        <div className="p-5"><SkeletonRows rows={8} cols={4} /></div>
      ) : q.isError ? (
        <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
      ) : !q.data?.length ? (
        <EmptyState title="No software inventory yet" body="Appears after a SOFTWARE_INVENTORY collection completes." />
      ) : (
        <SimpleTable head={["Name", "Vendor", "Version", "Installed", "Source", "CVEs"]}>
          {rows.map((x) => (
            <tr key={x.id} className="border-b hairline last:border-0">
              <td className="px-5 py-2.5 font-medium">{x.name}</td>
              <td className="px-3 py-2.5 text-muted-foreground">{x.vendor ?? "—"}</td>
              <td className="px-3 py-2.5 font-mono text-xs">{x.version ?? "UNKNOWN"}</td>
              <td className="px-3 py-2.5 text-xs text-muted-foreground">{fmtDate(x.installedAt)}</td>
              <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground">{x.source}</td>
              <td className="px-3 py-2.5">{x.vulnerabilityCount ? <Pill tone="high">{x.vulnerabilityCount}</Pill> : <span className="text-xs text-muted-foreground">0</span>}</td>
            </tr>
          ))}
        </SimpleTable>
      )}
    </Panel>
  );
}

function Startup({ id }: { id: string }) {
  const q = useListDeviceStartupItems(id, { query: { enabled: !!id, queryKey: getListDeviceStartupItemsQueryKey(id) } });
  return (
    <Panel title="Startup persistence inventory" subtitle="Locations that launch software automatically. User directories are redacted." bodyClassName="p-0">
      {q.isLoading ? (
        <div className="p-5"><SkeletonRows rows={6} cols={4} /></div>
      ) : q.isError ? (
        <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
      ) : !q.data?.length ? (
        <EmptyState title="No startup items collected yet" body="Appears after a STARTUP_INVENTORY collection completes." />
      ) : (
        <SimpleTable head={["Name", "Kind", "Location", "Publisher", "Enabled", "Collected"]}>
          {q.data.map((x) => (
            <tr key={x.id} className="border-b hairline last:border-0">
              <td className="px-5 py-2.5 font-medium">{x.name}</td>
              <td className="px-3 py-2.5"><Pill tone="violet" dot={false}>{x.kind.replace(/_/g, " ")}</Pill></td>
              <td className="max-w-[320px] truncate px-3 py-2.5 font-mono text-[11px] text-muted-foreground" title={x.location}>{x.location}</td>
              <td className="px-3 py-2.5 text-muted-foreground">{x.publisher ?? <span className="text-unknown">UNKNOWN</span>}</td>
              <td className="px-3 py-2.5 text-xs">{x.enabled == null ? <span className="text-unknown">UNKNOWN</span> : x.enabled ? "Yes" : "No"}</td>
              <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground">{fmtRel(x.collectedAt)}</td>
            </tr>
          ))}
        </SimpleTable>
      )}
    </Panel>
  );
}

function Threats({ id }: { id: string }) {
  const q = useListDeviceThreats(id, { query: { enabled: !!id, queryKey: getListDeviceThreatsQueryKey(id) } });
  return (
    <Panel title="Detected threat history" subtitle="As reported by the device's own antivirus product" bodyClassName="p-0">
      {q.isLoading ? (
        <div className="p-5"><SkeletonRows rows={4} cols={4} /></div>
      ) : q.isError ? (
        <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
      ) : !q.data?.length ? (
        <EmptyState title="No detections reported by the antivirus product" body="This reflects only what the installed antivirus product exposes. It is not an independent malware scan." />
      ) : (
        <SimpleTable head={["Threat", "Severity", "Detected", "Action taken", "Product", "Source"]}>
          {q.data.map((x) => (
            <tr key={x.id} className="border-b hairline last:border-0">
              <td className="px-5 py-2.5 font-mono text-xs">{x.threatName}</td>
              <td className="px-3 py-2.5 text-xs">{x.severity ?? <span className="text-unknown">UNKNOWN</span>}</td>
              <td className="px-3 py-2.5 text-xs text-muted-foreground">{fmtDate(x.detectedAt)}</td>
              <td className="px-3 py-2.5 text-xs">{x.actionTaken ?? <span className="text-unknown">UNKNOWN</span>}</td>
              <td className="px-3 py-2.5 text-xs">{x.product}</td>
              <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground">{x.source}</td>
            </tr>
          ))}
        </SimpleTable>
      )}
    </Panel>
  );
}

function Assessments({ id }: { id: string }) {
  const q = useListDeviceAssessments(id, { query: { enabled: !!id, queryKey: getListDeviceAssessmentsQueryKey(id) } });
  return (
    <Panel title="Assessment history" bodyClassName="p-0">
      {q.isLoading ? (
        <div className="p-5"><SkeletonRows rows={5} cols={5} /></div>
      ) : q.isError ? (
        <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
      ) : !q.data?.length ? (
        <EmptyState title="Never assessed" body="The first assessment runs automatically after enrollment." />
      ) : (
        <SimpleTable head={["Completed", "Trigger", "Result", "Collectors", "Coverage", "Risk", "Agent"]}>
          {q.data.map((a) => (
            <tr key={a.id} className="border-b hairline last:border-0">
              <td className="px-5 py-2.5 text-xs">{fmtDate(a.completedAt)}</td>
              <td className="px-3 py-2.5 text-xs text-muted-foreground">{a.trigger.toLowerCase()}</td>
              <td className="px-3 py-2.5"><Pill tone={a.status === "COMPLETE" ? "ok" : a.status === "PARTIAL" ? "warn" : "crit"}>{a.status}</Pill></td>
              <td className="px-3 py-2.5 text-xs">
                <span className="text-ok">{a.collectorsSucceeded.length}</span> / {a.collectorsRequested.length}
                {a.collectorsFailed.length > 0 && <span className="ml-1 text-crit" title={a.collectorsFailed.join(", ")}>({a.collectorsFailed.length} failed)</span>}
              </td>
              <td className="px-3 py-2.5 font-mono text-xs tabular">{Math.round(a.coveragePercent)}%</td>
              <td className="px-3 py-2.5 font-mono text-xs tabular">{a.riskScore ?? "—"}</td>
              <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground">v{a.agentVersion}</td>
            </tr>
          ))}
        </SimpleTable>
      )}
    </Panel>
  );
}

function AgentHealth({ d }: { d: DeviceDetail }) {
  const h = d.agentHealth;
  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_1.4fr]">
      <Panel title="Agent health">
        <dl>
          <KV label="Reliability"><Pill tone={reliabilityTone(h.reliability)}>{h.reliability.replace(/_/g, " ")}</Pill></KV>
          <KV label="Last heartbeat">{fmtDate(h.lastHeartbeatAt)}</KV>
          <KV label="Heartbeat interval" mono>{h.heartbeatIntervalMinutes} min</KV>
          <KV label="Missed heartbeats" mono>{h.consecutiveMissedHeartbeats}</KV>
          <KV label="Agent version" mono>v{h.agentVersion}</KV>
          <KV label="Supported version">{h.supportedVersion ? <Pill tone="ok">Supported</Pill> : <Pill tone="warn">Below minimum</Pill>}</KV>
        </dl>
      </Panel>
      <Panel title="Recent collector errors">
        {!h.lastCollectorErrors.length ? (
          <p className="text-sm text-muted-foreground">No collector errors reported.</p>
        ) : (
          <ul className="space-y-2.5">
            {h.lastCollectorErrors.map((e, i) => (
              <li key={i} className="rounded-lg border border-dashed border-unknown/40 p-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs">{e.collectorId}</span>
                  <span className="font-mono text-[11px] text-muted-foreground">{fmtDate(e.occurredAt)}</span>
                </div>
                <p className="mt-1 text-xs text-slate-300">{e.message}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

function RequestDialog({ id, open, onOpenChange }: { id: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [sel, setSel] = useState<CollectorId[]>(["SECURITY_POSTURE", "ANTIVIRUS_STATUS"]);
  const reqs = useListDeviceAssessmentRequests(id, { query: { enabled: !!id && open, queryKey: getListDeviceAssessmentRequestsQueryKey(id) } });
  const m = useRequestDeviceAssessment({
    mutation: {
      onSuccess: () => {
        void qc.invalidateQueries({ queryKey: getListDeviceAssessmentRequestsQueryKey(id) });
        toast({ title: "Assessment requested", description: "The agent will pick this up at its next heartbeat." });
      },
      onError: (e) => toast({ title: "Request failed", description: errMsg(e), variant: "destructive" }),
    },
  });
  const pending = (reqs.data ?? []).filter((r) => ["PENDING", "DELIVERED", "ACKNOWLEDGED"].includes(r.status));
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl border-border bg-[#11152a]">
        <DialogHeader>
          <DialogTitle>Request assessment</DialogTitle>
          <DialogDescription>
            Choose from the six fixed collectors compiled into the agent. The agent pulls this request at its next heartbeat; nothing is pushed to the device.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          {Object.values(CollectorId).map((c) => (
            <label key={c} className="flex cursor-pointer items-start gap-3 rounded-lg border hairline p-2.5 transition-colors hover:bg-white/[0.02]">
              <Checkbox
                data-testid={`checkbox-collector-${c}`}
                checked={sel.includes(c)}
                onCheckedChange={(v) => setSel((s) => (v ? [...s, c] : s.filter((x) => x !== c)))}
                className="mt-0.5"
              />
              <span>
                <span className="block font-mono text-xs">{c}</span>
                <span className="block text-xs text-muted-foreground">{COLLECTOR_DESC[c]}</span>
              </span>
            </label>
          ))}
        </div>
        <div>
          <div className="eyebrow mb-2">Pending requests</div>
          {reqs.isLoading ? (
            <SkeletonRows rows={2} cols={3} />
          ) : !pending.length ? (
            <p className="text-xs text-muted-foreground">None pending.</p>
          ) : (
            <ul className="space-y-1.5">
              {pending.map((r) => (
                <li key={r.id} className="flex items-center justify-between rounded-lg border hairline px-3 py-2 text-xs">
                  <span className="truncate font-mono">{r.collectors.join(", ")}</span>
                  <span className="ml-3 flex shrink-0 items-center gap-2">
                    <Pill tone="info">{r.status}</Pill>
                    <span className="text-muted-foreground">expires {fmtRel(r.expiresAt)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <DialogFooter>
          <button onClick={() => onOpenChange(false)} className="rounded-lg border border-border px-3.5 py-2 text-sm hover:bg-white/[0.04]">
            Close
          </button>
          <button
            disabled={!sel.length || m.isPending}
            data-testid="button-submit-request"
            onClick={() => m.mutate({ id, data: { collectors: sel } })}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
          >
            {m.isPending && <Loader2 className="size-4 animate-spin" />} Request {sel.length} collector{sel.length === 1 ? "" : "s"}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RevokeDialog({ d, open, onOpenChange }: { d: DeviceDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const m = useRevokeDevice({
    mutation: {
      onSuccess: () => {
        void qc.invalidateQueries({ queryKey: getGetDeviceQueryKey(d.id) });
        void qc.invalidateQueries({ queryKey: getListDevicesQueryKey() });
        toast({ title: "Device revoked", description: `${d.name} can no longer authenticate.` });
        onOpenChange(false);
        setLocation("/devices");
      },
      onError: (e) => toast({ title: "Revocation failed", description: errMsg(e), variant: "destructive" }),
    },
  });
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="border-border bg-[#11152a]">
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke {d.name}?</AlertDialogTitle>
          <AlertDialogDescription>
            The agent's credentials are invalidated and further reports are rejected. Historical evidence is retained per your retention policy. The software is not
            uninstalled remotely — remove it from the device manually.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            data-testid="button-confirm-revoke"
            onClick={(e) => {
              e.preventDefault();
              m.mutate({ id: d.id });
            }}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {m.isPending ? "Revoking…" : "Revoke device"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
