import { Link, useLocation } from "wouter";
import { Activity, ArrowUpRight, HeartPulse, KeyRound, MonitorPlay, Plus, Radar, ShieldOff, Zap } from "lucide-react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useGetDashboardActivity, useGetDashboardSummary, type ActivityEventType, type DashboardSummary } from "@workspace/api-client-react";
import { useT } from "@/i18n";
import { canAdmin, usePageMeta, useRole } from "@/lib/session";
import { fmtDate, fmtRel } from "@/lib/format";
import {
  Caveat,
  EmptyState,
  ErrorState,
  PageHeader,
  Panel,
  Pill,
  SkeletonBlock,
  SkeletonRows,
  StatTile,
  reliabilityTone,
  toneDot,
  toneHex,
  type Tone,
} from "@/components/app/primitives";
import { cn } from "@/lib/utils";

const ACT_ICON: Record<ActivityEventType, typeof Activity> = {
  HEARTBEAT: HeartPulse,
  ASSESSMENT: Radar,
  ENROLLMENT: KeyRound,
  REQUEST: Zap,
  REVOCATION: ShieldOff,
};

export default function Dashboard() {
  const t = useT();
  usePageMeta(t("dashboard.title"), t("dashboard.description"));
  const role = useRole();
  const summary = useGetDashboardSummary();
  const activity = useGetDashboardActivity({ limit: 14 });
  const s = summary.data;

  const enrollBtn = canAdmin(role) ? (
    <Link href="/devices/enroll" data-testid="link-enroll" className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-medium text-primary-foreground transition hover:brightness-110">
      <Plus className="size-4" /> Enroll device
    </Link>
  ) : undefined;

  return (
    <div>
      <PageHeader
        eyebrow={s ? `Generated ${fmtDate(s.generatedAt)}` : "Fleet"}
        title={t("dashboard.title")}
        description={t("dashboard.description")}
        actions={enrollBtn}
      />
      {summary.isLoading ? (
        <DashSkeleton />
      ) : summary.isError || !s ? (
        <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />
      ) : s.totalDevices === 0 ? (
        <Panel>
          <EmptyState
            icon={<MonitorPlay className="size-5" />}
            title={t("dashboard.emptyTitle") + " — enroll your first device"}
            body={t("dashboard.emptyBody")}
            action={enrollBtn ?? <span className="text-xs text-muted-foreground">Ask an Owner or Admin to enroll a device.</span>}
          />
        </Panel>
      ) : (
        <Body s={s} />
      )}

      {!summary.isLoading && s && s.totalDevices > 0 && (
        <Panel className="mt-5" title="Recent activity" subtitle="Authenticated agent events and administrator actions">
          {activity.isLoading ? (
            <SkeletonRows rows={5} cols={3} />
          ) : activity.isError ? (
            <ErrorState error={activity.error} onRetry={() => void activity.refetch()} />
          ) : !activity.data?.length ? (
            <p className="text-sm text-muted-foreground">No activity recorded yet.</p>
          ) : (
            <ol className="divide-y hairline">
              {activity.data.map((e) => {
                const Icon = ACT_ICON[e.type];
                return (
                  <li key={e.id} className="flex items-center gap-3 py-2.5" data-testid={`row-activity-${e.id}`}>
                    <span className="grid size-7 shrink-0 place-items-center rounded-lg border hairline bg-white/[0.03]">
                      <Icon className="size-3.5 text-cyan" />
                    </span>
                    <div className="min-w-0 flex-1 text-[13px]">
                      {e.deviceId ? (
                        <Link href={`/devices/${e.deviceId}`} className="font-medium text-foreground hover:text-cyan">
                          {e.deviceName}
                        </Link>
                      ) : null}
                      <span className="text-muted-foreground">{e.deviceId ? " · " : ""}{e.summary}</span>
                    </div>
                    <time className="shrink-0 font-mono text-[11px] text-muted-foreground" title={fmtDate(e.occurredAt)}>
                      {fmtRel(e.occurredAt)}
                    </time>
                  </li>
                );
              })}
            </ol>
          )}
        </Panel>
      )}
    </div>
  );
}

function Body({ s }: { s: DashboardSummary }) {
  const t = useT();
  const [, setLocation] = useLocation();
  const sev = s.openFindingsBySeverity;
  const sevData: { k: string; v: number; tone: Tone }[] = [
    { k: "Critical", v: sev.CRITICAL, tone: "crit" },
    { k: "High", v: sev.HIGH, tone: "high" },
    { k: "Medium", v: sev.MEDIUM, tone: "warn" },
    { k: "Low", v: sev.LOW, tone: "info" },
    { k: "Info", v: sev.INFO, tone: "neutral" },
  ];
  const highOpen = sev.CRITICAL + sev.HIGH;
  const rel = s.agentReliability;
  const relRows = (["HEALTHY", "DEGRADED", "OFFLINE", "NEVER_REPORTED", "REVOKED"] as const).map((k) => ({ k, v: rel[k], tone: reliabilityTone(k) }));
  const relTotal = relRows.reduce((a, r) => a + r.v, 0) || 1;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatTile label="Enrolled devices" value={s.totalDevices} testId="text-total-devices" hint={`${s.neverAssessedDevices} never assessed`} accent="violet" />
        <StatTile
          label="Online"
          value={
            <span>
              {s.onlineDevices}
              <span className="text-base text-muted-foreground"> / {s.offlineDevices} offline</span>
            </span>
          }
          testId="text-online-devices"
          hint={`Heartbeat within the last ${s.onlineThresholdMinutes} min`}
          accent="ok"
        />
        <StatTile label="Require attention" value={s.devicesRequiringAttention} testId="text-attention" hint="High risk, failing checks or stale evidence" accent={s.devicesRequiringAttention ? "warn" : undefined} />
        <StatTile
          label="Known exploited CVEs"
          value={s.vulnerabilities.knownExploited}
          testId="text-kev"
          hint={`${s.vulnerabilities.total} matches on ${s.vulnerabilities.affectedDevices} devices`}
          accent={s.vulnerabilities.knownExploited ? "crit" : undefined}
        />
      </div>

      {s.neverAssessedDevices > 0 && (
        <Caveat tone="warn">
          {s.neverAssessedDevices} of {s.totalDevices} devices have not completed an assessment. Totals below are partial until they report.
        </Caveat>
      )}

      <div className="grid gap-5 xl:grid-cols-[1.35fr_1fr]">
        <Panel
          title="Open findings by severity"
          subtitle={highOpen === 0 ? t("dashboard.noHigh") : `${highOpen} critical or high findings open`}
          actions={
            <Link href="/findings" className="inline-flex items-center gap-1 text-xs text-cyan hover:underline" data-testid="link-findings">
              All findings <ArrowUpRight className="size-3" />
            </Link>
          }
        >
          <div className="h-[210px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevData} layout="vertical" margin={{ left: 0, right: 24, top: 4, bottom: 4 }}>
                <XAxis type="number" allowDecimals={false} tick={{ fill: "#7F889C", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="k" width={64} tick={{ fill: "#C5CBDA", fontSize: 12 }} axisLine={false} tickLine={false} />
                <Tooltip
                  cursor={{ fill: "rgba(255,255,255,0.03)" }}
                  contentStyle={{ background: "#131728", border: "1px solid #2A3150", borderRadius: 10, fontSize: 12 }}
                  labelStyle={{ color: "#F8FAFC" }}
                  itemStyle={{ color: "#C5CBDA" }}
                />
                <Bar dataKey="v" name="Open" radius={[0, 6, 6, 0]} barSize={16}>
                  {sevData.map((d) => (
                    <Cell key={d.k} fill={toneHex[d.tone]} fillOpacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <Caveat className="mt-3">{t("dashboard.coverageCaveat")}</Caveat>
        </Panel>

        <div className="grid gap-5">
          <Panel title="Vulnerability overview" subtitle="Software matched against NVD and CISA KEV">
            <div className="grid grid-cols-3 gap-3">
              {[
                ["Confirmed", s.vulnerabilities.confirmed, "violet"],
                ["Probable", s.vulnerabilities.probable, "info"],
                ["Possible", s.vulnerabilities.possible, "neutral"],
              ].map(([k, v, tone]) => (
                <div key={k as string} className="rounded-xl border hairline bg-background/40 p-3">
                  <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                    <span className={cn("size-1.5 rounded-full", toneDot[tone as Tone])} />
                    {k}
                  </div>
                  <div className="mt-1 text-xl font-semibold tabular">{v as number}</div>
                </div>
              ))}
            </div>
            <Link href="/vulnerabilities" className="mt-3 inline-flex items-center gap-1 text-xs text-cyan hover:underline">
              Review matches <ArrowUpRight className="size-3" />
            </Link>
          </Panel>
          <Panel title="Agent reliability" subtitle="From authenticated heartbeats only">
            <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-white/[0.05]">
              {relRows.map((r) => (r.v ? <div key={r.k} className={toneDot[r.tone]} style={{ width: `${(r.v / relTotal) * 100}%` }} title={`${r.k}: ${r.v}`} /> : null))}
            </div>
            <ul className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
              {relRows.map((r) => (
                <li key={r.k} className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-muted-foreground">
                    <span className={cn("size-1.5 rounded-full", toneDot[r.tone])} />
                    {r.k.replace(/_/g, " ").toLowerCase()}
                  </span>
                  <span className="font-mono tabular text-foreground">{r.v}</span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>

      <Panel title="Latest assessments" subtitle="Most recent completed collections" bodyClassName="p-0">
        {s.latestAssessments.length === 0 ? (
          <p className="p-5 text-sm text-muted-foreground">No assessments have been received yet.</p>
        ) : (
          <div className="overflow-x-auto scroll-thin">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="eyebrow border-b hairline text-left">
                  <th className="px-5 py-2.5 font-normal">Device</th>
                  <th className="px-3 py-2.5 font-normal">Result</th>
                  <th className="px-3 py-2.5 font-normal">Trigger</th>
                  <th className="px-3 py-2.5 font-normal">Coverage</th>
                  <th className="px-3 py-2.5 font-normal">Risk score</th>
                  <th className="px-5 py-2.5 text-right font-normal">Completed</th>
                </tr>
              </thead>
              <tbody>
                {s.latestAssessments.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => setLocation(`/devices/${a.deviceId}`)}
                    className="cursor-pointer border-b hairline transition-colors last:border-0 hover:bg-white/[0.025]"
                    data-testid={`row-assessment-${a.id}`}
                  >
                    <td className="px-5 py-2.5 font-medium">{a.deviceName}</td>
                    <td className="px-3 py-2.5">
                      <Pill tone={a.status === "COMPLETE" ? "ok" : a.status === "PARTIAL" ? "warn" : "crit"}>{a.status}</Pill>
                    </td>
                    <td className="px-3 py-2.5 text-muted-foreground">{a.trigger.toLowerCase()}</td>
                    <td className="px-3 py-2.5 font-mono tabular">{Math.round(a.coveragePercent)}%</td>
                    <td className="px-3 py-2.5 font-mono tabular">{a.riskScore ?? <span className="text-unknown">UNKNOWN</span>}</td>
                    <td className="px-5 py-2.5 text-right font-mono text-xs text-muted-foreground" title={fmtDate(a.completedAt)}>
                      {fmtRel(a.completedAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function DashSkeleton() {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <SkeletonBlock key={i} className="h-[112px]" />
        ))}
      </div>
      <div className="grid gap-5 xl:grid-cols-[1.35fr_1fr]">
        <SkeletonBlock className="h-[330px]" />
        <SkeletonBlock className="h-[330px]" />
      </div>
      <SkeletonBlock className="h-64" />
    </div>
  );
}
