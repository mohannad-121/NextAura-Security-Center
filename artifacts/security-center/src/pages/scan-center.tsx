import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { Ban, Download, Loader2, Radar, ShieldCheck } from "lucide-react";
import { useListDevices } from "@workspace/api-client-react";
import { canAnalyze, usePageMeta, useRole } from "@/lib/session";
import {
  Caveat,
  EmptyState,
  ErrorState,
  PageHeader,
  Panel,
  Pill,
  SkeletonRows,
} from "@/components/app/primitives";

type ScanStatus =
  | "QUEUED"
  | "WAITING_FOR_AGENT"
  | "RUNNING"
  | "COMPLETED"
  | "PARTIAL"
  | "FAILED"
  | "CANCELLED"
  | "EXPIRED";
type ScanJob = {
  id: string;
  scanType: "SECURITY_ASSESSMENT" | "APPROVED_SCOPE_FILES";
  status: ScanStatus;
  collectors: string[];
  createdAt: string;
  expiresAt: string;
  targets: Record<string, number>;
};
type Scope = {
  deviceId: string;
  deviceName: string;
  scopeId: string;
  label: string;
  enabled: boolean;
  lastReportedAt: string;
};
type Detail = {
  job: ScanJob;
  targets: Array<{
    id: string;
    deviceId: string;
    deviceName: string;
    osType: string;
    status: ScanStatus;
    stage: string;
    scopeId: string | null;
    filesObserved: number;
    evidenceCount: number;
    collectorFailures: Array<{ collectorId: string; reason: string }>;
    error: string | null;
  }>;
  evidence: Array<{
    id: string;
    deviceId: string;
    fileName: string;
    sha256: string;
    detectedType: string;
    classification: string;
    severity: string;
    confidence: string;
    detectorId: string;
    detectorVersion: string;
    evidenceSource: string;
    limitations: string[];
    observedAt: string;
  }>;
};

const collectors = [
  "SYSTEM_INFO",
  "SECURITY_POSTURE",
  "ANTIVIRUS_STATUS",
  "SOFTWARE_INVENTORY",
  "STARTUP_INVENTORY",
  "SAFE_NETWORK_SUMMARY",
] as const;

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok)
    throw new Error(
      `${response.status}: ${(await response.json().catch(() => null))?.message ?? response.statusText}`,
    );
  return response.json() as Promise<T>;
}

function statusTone(
  status: ScanStatus,
): "ok" | "warn" | "crit" | "info" | "neutral" {
  if (status === "COMPLETED") return "ok";
  if (status === "FAILED" || status === "EXPIRED") return "crit";
  if (status === "PARTIAL" || status === "CANCELLED") return "warn";
  if (status === "RUNNING") return "info";
  return "neutral";
}

export default function ScanCenter() {
  usePageMeta(
    "Scan Center",
    "Authorized read-only assessments across enrolled company devices.",
  );
  const role = useRole();
  const qc = useQueryClient();
  const devices = useListDevices({ includeRevoked: false });
  const scopes = useQuery({
    queryKey: ["scan-scopes"],
    queryFn: () => api<Scope[]>("/api/scan-scopes"),
  });
  const jobs = useQuery({
    queryKey: ["scan-jobs"],
    queryFn: () => api<ScanJob[]>("/api/scan-jobs"),
    refetchInterval: 15_000,
  });
  const [selectedJob, setSelectedJob] = useState<string | null>(null);
  const detail = useQuery({
    queryKey: ["scan-job", selectedJob],
    queryFn: () => api<Detail>(`/api/scan-jobs/${selectedJob}`),
    enabled: !!selectedJob,
    refetchInterval: 10_000,
  });
  const [scanType, setScanType] = useState<ScanJob["scanType"]>(
    "SECURITY_ASSESSMENT",
  );
  const [selectedDevices, setSelectedDevices] = useState<string[]>([]);
  const [selectedCollectors, setSelectedCollectors] = useState<string[]>([
    "SECURITY_POSTURE",
    "ANTIVIRUS_STATUS",
    "STARTUP_INVENTORY",
  ]);
  const [targetScopes, setTargetScopes] = useState<Record<string, string>>({});
  const activeDevices = devices.data ?? [];
  const eligible = useMemo(
    () =>
      selectedDevices.filter(
        (id) => scanType === "SECURITY_ASSESSMENT" || !!targetScopes[id],
      ),
    [selectedDevices, scanType, targetScopes],
  );
  const create = useMutation({
    mutationFn: () =>
      api<ScanJob>("/api/scan-jobs", {
        method: "POST",
        body: JSON.stringify({
          scanType,
          collectors:
            scanType === "SECURITY_ASSESSMENT" ? selectedCollectors : [],
          targets: eligible.map((deviceId) => ({
            deviceId,
            ...(scanType === "APPROVED_SCOPE_FILES"
              ? { scopeId: targetScopes[deviceId] }
              : {}),
          })),
          expiresInHours: 24,
        }),
      }),
    onSuccess: (job) => {
      setSelectedJob(job.id);
      setSelectedDevices([]);
      void qc.invalidateQueries({ queryKey: ["scan-jobs"] });
    },
  });
  const cancel = useMutation({
    mutationFn: (id: string) =>
      api(`/api/scan-jobs/${id}/cancel`, { method: "POST" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scan-jobs"] });
      void qc.invalidateQueries({ queryKey: ["scan-job", selectedJob] });
    },
  });

  return (
    <div>
      <PageHeader
        eyebrow="Fleet operations"
        title="Scan Center"
        description="Request fixed, audited, read-only assessments from authenticated agents and review genuine stages, evidence, and visibility gaps."
      />
      <Caveat className="mb-4">
        The server sends operation and scope IDs only—never commands or
        filesystem paths. RUNNING appears only after an agent acknowledges work.
        No findings observed is not proof that a device is clean.
      </Caveat>
      {canAnalyze(role) && (
        <Panel title="New authorized scan" className="mb-4">
          <div className="grid gap-4 lg:grid-cols-[220px_1fr]">
            <div>
              <label
                htmlFor="scan-type"
                className="mb-1.5 block text-xs font-medium"
              >
                Scan type
              </label>
              <select
                id="scan-type"
                value={scanType}
                onChange={(e) =>
                  setScanType(e.target.value as ScanJob["scanType"])
                }
                className="h-11 w-full rounded-lg border border-input bg-card px-3 text-sm"
              >
                <option value="SECURITY_ASSESSMENT">
                  Security posture collectors
                </option>
                <option value="APPROVED_SCOPE_FILES">
                  Approved-folder static analysis
                </option>
              </select>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                File scopes require local administrator consent. The dashboard
                cannot create or expand them.
              </p>
            </div>
            <div>
              {scanType === "SECURITY_ASSESSMENT" && (
                <fieldset className="mb-4">
                  <legend className="mb-1.5 text-xs font-medium">
                    Fixed collectors
                  </legend>
                  <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                    {collectors.map((collector) => (
                      <label
                        key={collector}
                        className="flex min-h-11 cursor-pointer items-center gap-2 rounded-lg border hairline px-3 text-xs"
                      >
                        <input
                          type="checkbox"
                          checked={selectedCollectors.includes(collector)}
                          onChange={(e) =>
                            setSelectedCollectors((current) =>
                              e.target.checked
                                ? [...current, collector]
                                : current.filter(
                                    (value) => value !== collector,
                                  ),
                            )
                          }
                        />
                        <span className="font-mono">{collector}</span>
                      </label>
                    ))}
                  </div>
                </fieldset>
              )}
              <fieldset>
                <legend className="mb-1.5 flex items-center justify-between text-xs font-medium">
                  <span>Company devices</span>
                  <button
                    type="button"
                    className="min-h-11 cursor-pointer px-2 text-cyan underline-offset-2 hover:underline"
                    onClick={() =>
                      setSelectedDevices(
                        activeDevices.map((device) => device.id),
                      )
                    }
                  >
                    Select all
                  </button>
                </legend>
                {devices.isLoading ? (
                  <SkeletonRows rows={3} cols={2} />
                ) : (
                  <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
                    {activeDevices.map((device) => {
                      const deviceScopes = (scopes.data ?? []).filter(
                        (scope) => scope.deviceId === device.id,
                      );
                      return (
                        <div
                          key={device.id}
                          className="rounded-lg border hairline p-3"
                        >
                          <label className="flex min-h-11 cursor-pointer items-center gap-3">
                            <input
                              type="checkbox"
                              checked={selectedDevices.includes(device.id)}
                              onChange={(e) =>
                                setSelectedDevices((current) =>
                                  e.target.checked
                                    ? [...current, device.id]
                                    : current.filter(
                                        (value) => value !== device.id,
                                      ),
                                )
                              }
                            />
                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-sm font-medium">
                                {device.name}
                              </span>
                              <span className="text-xs text-muted-foreground">
                                {device.osType} · last seen{" "}
                                {device.lastSeenAt
                                  ? new Date(device.lastSeenAt).toLocaleString()
                                  : "never"}
                              </span>
                            </span>
                          </label>
                          {scanType === "APPROVED_SCOPE_FILES" &&
                            selectedDevices.includes(device.id) && (
                              <div className="mt-2">
                                <label
                                  htmlFor={`scope-${device.id}`}
                                  className="sr-only"
                                >
                                  Approved scope for {device.name}
                                </label>
                                <select
                                  id={`scope-${device.id}`}
                                  value={targetScopes[device.id] ?? ""}
                                  onChange={(e) =>
                                    setTargetScopes((current) => ({
                                      ...current,
                                      [device.id]: e.target.value,
                                    }))
                                  }
                                  className="h-11 w-full rounded-lg border border-input bg-card px-3 text-sm"
                                >
                                  <option value="">
                                    Select a locally approved scope
                                  </option>
                                  {deviceScopes.map((scope) => (
                                    <option
                                      key={scope.scopeId}
                                      value={scope.scopeId}
                                    >
                                      {scope.label}
                                    </option>
                                  ))}
                                </select>
                                {!deviceScopes.length && (
                                  <p className="mt-1 text-xs text-warn">
                                    No enabled scope has been reported by this
                                    agent.
                                  </p>
                                )}
                              </div>
                            )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </fieldset>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  disabled={
                    !eligible.length ||
                    create.isPending ||
                    (scanType === "SECURITY_ASSESSMENT" &&
                      !selectedCollectors.length)
                  }
                  onClick={() => create.mutate()}
                  className="inline-flex min-h-11 cursor-pointer items-center gap-2 rounded-lg bg-violet px-4 text-sm font-medium text-white transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {create.isPending ? (
                    <Loader2
                      aria-hidden="true"
                      className="size-4 animate-spin motion-reduce:animate-none"
                    />
                  ) : (
                    <Radar aria-hidden="true" className="size-4" />
                  )}
                  Request scan for {eligible.length} device
                  {eligible.length === 1 ? "" : "s"}
                </button>
                <span
                  role="status"
                  aria-atomic="true"
                  className="text-xs text-muted-foreground"
                >
                  {selectedDevices.length - eligible.length > 0
                    ? `${selectedDevices.length - eligible.length} selected device(s) need a scope.`
                    : "Ready targets have all required inputs."}
                </span>
              </div>
              {create.error && (
                <p className="mt-2 text-xs text-crit">{String(create.error)}</p>
              )}
            </div>
          </div>
        </Panel>
      )}
      <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <Panel title="Assessment history" bodyClassName="p-0">
          {jobs.isLoading ? (
            <div className="p-4">
              <SkeletonRows rows={6} cols={2} />
            </div>
          ) : jobs.isError ? (
            <div className="p-4">
              <ErrorState error={jobs.error} />
            </div>
          ) : !jobs.data?.length ? (
            <EmptyState
              icon={<ShieldCheck aria-hidden="true" className="size-5" />}
              title="No centralized scans yet"
              body="Request a supported assessment to begin collecting authenticated evidence."
            />
          ) : (
            <div className="divide-y divide-border">
              {jobs.data.map((job) => (
                <button
                  key={job.id}
                  onClick={() => setSelectedJob(job.id)}
                  aria-pressed={selectedJob === job.id}
                  className="block min-h-16 w-full cursor-pointer px-4 py-3 text-left transition hover:bg-white/[0.03] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium">
                      {job.scanType === "SECURITY_ASSESSMENT"
                        ? "Security assessment"
                        : "Approved-scope files"}
                    </span>
                    <Pill tone={statusTone(job.status)}>{job.status}</Pill>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">
                    {new Date(job.createdAt).toLocaleString()} ·{" "}
                    {Object.values(job.targets).reduce((a, b) => a + b, 0)}{" "}
                    target(s)
                  </div>
                </button>
              ))}
            </div>
          )}
        </Panel>
        <Panel title="Scan evidence">
          {!selectedJob ? (
            <EmptyState
              icon={<Radar aria-hidden="true" className="size-5" />}
              title="Select an assessment"
              body="Review per-device stages, collector failures, file metadata, and coverage limitations."
            />
          ) : detail.isLoading ? (
            <SkeletonRows rows={6} cols={3} />
          ) : detail.isError ? (
            <ErrorState error={detail.error} />
          ) : (
            detail.data && (
              <div className="space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div role="status" aria-atomic="true">
                    <Pill tone={statusTone(detail.data.job.status)}>
                      {detail.data.job.status}
                    </Pill>
                    <p className="mt-2 text-xs text-muted-foreground">
                      Exact stages are agent-reported; percentages are
                      intentionally not estimated.
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <a
                      href={`/api/scan-jobs/${selectedJob}/report`}
                      className="inline-flex min-h-11 cursor-pointer items-center gap-2 rounded-lg border border-border px-3 text-sm hover:bg-white/[0.04]"
                    >
                      <Download aria-hidden="true" className="size-4" />
                      PDF report
                    </a>
                    {!["COMPLETED", "FAILED", "CANCELLED", "EXPIRED"].includes(
                      detail.data.job.status,
                    ) &&
                      canAnalyze(role) && (
                        <button
                          onClick={() => cancel.mutate(selectedJob)}
                          disabled={cancel.isPending}
                          className="inline-flex min-h-11 cursor-pointer items-center gap-2 rounded-lg border border-warn/40 px-3 text-sm text-warn hover:bg-warn/10 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <Ban aria-hidden="true" className="size-4" />
                          Cancel waiting work
                        </button>
                      )}
                  </div>
                </div>
                <div>
                  <h3 className="eyebrow mb-2">Device stages</h3>
                  <div className="space-y-2">
                    {detail.data.targets.map((target) => (
                      <div
                        key={target.id}
                        className="rounded-lg border hairline p-3"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <Link
                            href={`/devices/${target.deviceId}`}
                            className="text-sm font-medium hover:text-cyan"
                          >
                            {target.deviceName}
                          </Link>
                          <Pill tone={statusTone(target.status)}>
                            {target.status}
                          </Pill>
                        </div>
                        <p className="mt-1 text-xs">{target.stage}</p>
                        <p className="mt-1 text-[11px] text-muted-foreground">
                          Files observed: {target.filesObserved} · evidence
                          records: {target.evidenceCount}
                        </p>
                        {target.collectorFailures.length > 0 && (
                          <ul className="mt-2 space-y-1 text-xs text-warn">
                            {target.collectorFailures.map((failure) => (
                              <li key={failure.collectorId}>
                                {failure.collectorId}: {failure.reason}
                              </li>
                            ))}
                          </ul>
                        )}
                        {target.error && (
                          <p className="mt-2 text-xs text-crit">
                            {target.error}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h3 className="eyebrow mb-2">
                    File evidence and visibility records
                  </h3>
                  {!detail.data.evidence.length ? (
                    <p className="text-sm text-muted-foreground">
                      No file evidence was submitted for this scan type or
                      scope.
                    </p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full min-w-[760px] text-left text-xs">
                        <thead className="text-muted-foreground">
                          <tr>
                            <th className="pb-2">File</th>
                            <th>Classification</th>
                            <th>Detector</th>
                            <th>SHA-256</th>
                            <th>Observed</th>
                          </tr>
                        </thead>
                        <tbody>
                          {detail.data.evidence.map((item) => (
                            <tr
                              key={item.id}
                              className="border-t border-border"
                            >
                              <td className="py-2.5">
                                <div className="font-medium">
                                  {item.fileName}
                                </div>
                                <div className="text-muted-foreground">
                                  {item.detectedType} · {item.severity}/
                                  {item.confidence}
                                </div>
                              </td>
                              <td>
                                <Pill
                                  tone={
                                    item.classification ===
                                    "CONFIRMED_DETECTION"
                                      ? "crit"
                                      : item.classification ===
                                          "SUSPICIOUS_INDICATOR"
                                        ? "warn"
                                        : "neutral"
                                  }
                                >
                                  {item.classification}
                                </Pill>
                              </td>
                              <td>
                                {item.detectorId} v{item.detectorVersion}
                              </td>
                              <td
                                className="max-w-[180px] truncate font-mono"
                                title={item.sha256}
                              >
                                {item.sha256}
                              </td>
                              <td>
                                {new Date(item.observedAt).toLocaleString()}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
                <div className="rounded-lg border border-dashed border-warn/35 bg-warn/[0.04] p-3 text-xs leading-relaxed text-muted-foreground">
                  Coverage limitations remain evidence: encrypted archives,
                  unsupported formats, permission failures, time/file limits,
                  offline agents, and unreported scopes prevent a clean
                  conclusion. Link relevant findings and evidence from this scan
                  to an{" "}
                  <Link href="/incidents" className="text-cyan hover:underline">
                    incident investigation
                  </Link>
                  .
                </div>
              </div>
            )
          )}
        </Panel>
      </div>
    </div>
  );
}
