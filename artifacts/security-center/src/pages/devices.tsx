import { useMemo, useState } from "react";
import { Link, useLocation } from "wouter";
import { Apple, MonitorPlay, Plus, Search, X } from "lucide-react";
import { OsType, RiskLevel, useListDevices, type ListDevicesParams } from "@workspace/api-client-react";
import { useT } from "@/i18n";
import { canAdmin, usePageMeta, useRole } from "@/lib/session";
import { fmtDate, fmtRel } from "@/lib/format";
import {
  EmptyState,
  ErrorState,
  FilterSelect,
  Meter,
  PageHeader,
  Panel,
  Pill,
  SevCounts,
  SeverityPill,
  SkeletonRows,
  coverageTone,
  reliabilityTone,
} from "@/components/app/primitives";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

export function OsGlyph({ os, className }: { os: OsType; className?: string }) {
  return os === "MACOS" ? (
    <Apple className={cn("size-3.5 text-muted-foreground", className)} />
  ) : (
    <svg viewBox="0 0 16 16" className={cn("size-3.5 text-muted-foreground", className)} fill="currentColor" aria-hidden>
      <path d="M1 2.5 7 1.7v5.8H1zm7-.9L15 .6v6.9H8zM1 8.5h6v5.8l-6-.8zm7 0h7v6.9l-7-1z" />
    </svg>
  );
}

export default function Devices() {
  const t = useT();
  usePageMeta(t("devices.title"), t("devices.description"));
  const role = useRole();
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [osType, setOsType] = useState<OsType | "">("");
  const [riskLevel, setRiskLevel] = useState<RiskLevel | "">("");
  const [online, setOnline] = useState<"" | "true" | "false">("");
  const [after, setAfter] = useState("");
  const [includeRevoked, setIncludeRevoked] = useState(false);

  const params = useMemo<ListDevicesParams>(() => {
    const p: ListDevicesParams = {};
    if (search.trim()) p.search = search.trim();
    if (osType) p.osType = osType;
    if (riskLevel) p.riskLevel = riskLevel;
    if (online) p.online = online === "true";
    if (after) p.lastAssessmentAfter = new Date(after).toISOString();
    if (includeRevoked) p.includeRevoked = true;
    return p;
  }, [search, osType, riskLevel, online, after, includeRevoked]);
  const filtered = Object.keys(params).length > 0;
  const q = useListDevices(params);

  const reset = () => {
    setSearch("");
    setOsType("");
    setRiskLevel("");
    setOnline("");
    setAfter("");
    setIncludeRevoked(false);
  };

  return (
    <div>
      <PageHeader
        eyebrow="Fleet"
        title={t("devices.title")}
        description={t("devices.description")}
        actions={
          canAdmin(role) && (
            <Link href="/devices/enroll" data-testid="link-enroll" className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-medium text-primary-foreground transition hover:brightness-110">
              <Plus className="size-4" /> Enroll device
            </Link>
          )
        }
      />
      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b hairline p-3.5">
          <div className="relative min-w-[220px] flex-1">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              data-testid="input-search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search hostname, OS version, agent version"
              className="h-9 w-full rounded-lg border border-input bg-card pl-8 pr-3 text-[13px] outline-none placeholder:text-muted-foreground/70 focus:border-violet"
            />
          </div>
          <FilterSelect testId="select-os" value={osType} onChange={setOsType} options={Object.values(OsType)} allLabel="All OS" />
          <FilterSelect testId="select-risk" value={riskLevel} onChange={setRiskLevel} options={Object.values(RiskLevel)} allLabel="Any risk" />
          <select
            data-testid="select-online"
            value={online}
            onChange={(e) => setOnline(e.target.value as "" | "true" | "false")}
            className="h-9 rounded-lg border border-input bg-card px-2.5 text-[13px] outline-none focus:border-violet"
          >
            <option value="">Online & offline</option>
            <option value="true">Online</option>
            <option value="false">Offline</option>
          </select>
          <label className="flex h-9 items-center gap-2 rounded-lg border border-input bg-card px-2.5 text-[12px] text-muted-foreground">
            Assessed after
            <input data-testid="input-assessed-after" type="date" value={after} onChange={(e) => setAfter(e.target.value)} className="bg-transparent text-[13px] text-foreground outline-none [color-scheme:dark]" />
          </label>
          <label className="flex h-9 items-center gap-2 px-1 text-[12px] text-muted-foreground">
            <Switch checked={includeRevoked} onCheckedChange={setIncludeRevoked} data-testid="switch-include-revoked" />
            Include revoked
          </label>
          {filtered && (
            <button onClick={reset} data-testid="button-reset-filters" className="inline-flex h-9 items-center gap-1 rounded-lg px-2 text-xs text-muted-foreground hover:text-foreground">
              <X className="size-3.5" /> Reset
            </button>
          )}
        </div>

        {q.isLoading ? (
          <div className="p-5">
            <SkeletonRows rows={8} cols={6} />
          </div>
        ) : q.isError ? (
          <div className="p-5">
            <ErrorState error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : !q.data?.length ? (
          filtered ? (
            <EmptyState title={t("devices.noMatch")} body="Adjust or reset the filters above." action={<button onClick={reset} className="rounded-lg border border-border px-3 py-1.5 text-xs hover:bg-white/[0.04]">Reset filters</button>} />
          ) : (
            <EmptyState
              icon={<MonitorPlay className="size-5" />}
              title={`${t("devices.emptyTitle")} — enroll your first device`}
              body={t("devices.emptyBody")}
              action={
                canAdmin(role) ? (
                  <Link href="/devices/enroll" className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-medium text-primary-foreground">
                    <Plus className="size-4" /> Enroll device
                  </Link>
                ) : undefined
              }
            />
          )
        ) : (
          <div className="overflow-x-auto scroll-thin">
            <table className="w-full min-w-[980px] text-[13px]">
              <thead>
                <tr className="eyebrow border-b hairline text-left">
                  <th className="px-5 py-3 font-normal">Device</th>
                  <th className="px-3 py-3 font-normal">Heartbeat</th>
                  <th className="px-3 py-3 font-normal">Risk</th>
                  <th className="px-3 py-3 font-normal">Coverage</th>
                  <th className="px-3 py-3 font-normal">Open findings</th>
                  <th className="px-3 py-3 font-normal">Agent</th>
                  <th className="px-5 py-3 text-right font-normal">Last assessment</th>
                </tr>
              </thead>
              <tbody>
                {q.data.map((d) => (
                  <tr
                    key={d.id}
                    onClick={() => setLocation(`/devices/${d.id}`)}
                    data-testid={`row-device-${d.id}`}
                    className={cn("cursor-pointer border-b hairline transition-colors last:border-0 hover:bg-white/[0.025]", d.status === "REVOKED" && "opacity-60")}
                  >
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2.5">
                        <OsGlyph os={d.osType} />
                        <div className="min-w-0">
                          <div className="truncate font-medium text-foreground">{d.name}</div>
                          <div className="truncate font-mono text-[11px] text-muted-foreground">
                            {d.osVersion}
                            {d.osBuild ? ` · ${d.osBuild}` : ""} · {d.architecture}
                          </div>
                        </div>
                        {d.status === "REVOKED" && <Pill tone="crit">Revoked</Pill>}
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2">
                        <span className={cn("size-2 rounded-full", d.isOnline ? "bg-ok" : "bg-unknown/60")} />
                        <span className={d.isOnline ? "text-foreground" : "text-muted-foreground"}>{d.isOnline ? "Online" : "Offline"}</span>
                      </div>
                      <div className="mt-0.5 font-mono text-[11px] text-muted-foreground" title={fmtDate(d.lastSeenAt)}>
                        {fmtRel(d.lastSeenAt, "No heartbeat")}
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2">
                        <SeverityPill s={d.riskLevel} />
                        <span className="font-mono text-xs tabular text-muted-foreground">{d.riskScore ?? "—"}</span>
                      </div>
                    </td>
                    <td className="w-[150px] px-3 py-3">
                      <div className="flex items-center justify-between font-mono text-[11px]">
                        <span className="tabular">{Math.round(d.coveragePercent)}%</span>
                        <span className="text-muted-foreground">{d.coverageStatus}</span>
                      </div>
                      <div className="mt-1">
                        <Meter value={d.coveragePercent} tone={coverageTone(d.coverageStatus)} />
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <SevCounts c={d.openFindings} />
                    </td>
                    <td className="px-3 py-3">
                      <Pill tone={reliabilityTone(d.agentReliability)}>{d.agentReliability.replace(/_/g, " ")}</Pill>
                      <div className="mt-1 font-mono text-[11px] text-muted-foreground">v{d.agentVersion}</div>
                    </td>
                    <td className="px-5 py-3 text-right font-mono text-xs text-muted-foreground" title={fmtDate(d.lastAssessmentAt)}>
                      {fmtRel(d.lastAssessmentAt, "Never assessed")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="border-t hairline px-5 py-2.5 font-mono text-[11px] text-muted-foreground">{q.data.length} devices</div>
          </div>
        )}
      </Panel>
    </div>
  );
}
