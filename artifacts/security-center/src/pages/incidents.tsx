import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileSearch, Plus } from "lucide-react";
import { usePageMeta, useRole, canAnalyze } from "@/lib/session";
import {
  Caveat,
  EmptyState,
  ErrorState,
  PageHeader,
  Panel,
  Pill,
  SeverityPill,
  SkeletonRows,
  severityTone,
} from "@/components/app/primitives";

type Incident = {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: string;
  confidence: string;
  summary: string;
  evidenceLimitations: string[];
  recommendedActions: string[];
  updatedAt: string;
};
type Detail = {
  incident: Incident;
  devices: Array<{ id: string; name: string; osType: string }>;
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    evidence: string;
    status: string;
  }>;
  files: Array<{
    id: string;
    fileName: string;
    sha256: string;
    detectedType: string;
    classification: string;
    signatureMetadata: string;
    limitations: string[];
  }>;
  timeline: Array<{
    id: string;
    occurredAt: string;
    title: string;
    evidence: string;
    source: string;
  }>;
};

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

export default function Incidents() {
  usePageMeta(
    "Incident investigations",
    "Evidence-driven incident timelines, suspicious file metadata, and response guidance.",
  );
  const role = useRole();
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<Incident["severity"]>("HIGH");
  const [analysis, setAnalysis] = useState("");
  const list = useQuery({
    queryKey: ["incidents"],
    queryFn: () => api<Incident[]>("/api/incidents"),
  });
  const detail = useQuery({
    queryKey: ["incident", selected],
    queryFn: () => api<Detail>(`/api/incidents/${selected}`),
    enabled: Boolean(selected),
  });
  const create = useMutation({
    mutationFn: () =>
      api<Incident>("/api/incidents", {
        method: "POST",
        body: JSON.stringify({
          title,
          severity,
          confidence: "MEDIUM",
          summary: "Investigation opened; evidence collection is incomplete.",
          evidenceLimitations: [
            "No conclusion is valid until associated evidence and coverage gaps are reviewed.",
          ],
          recommendedActions: [
            "Preserve the original attachment without opening it.",
            "Review antivirus history and persistence findings on associated devices.",
          ],
        }),
      }),
    onSuccess: (incident) => {
      setTitle("");
      setSelected(incident.id);
      void qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
  const addFile = useMutation({
    mutationFn: () => {
      const parsed = JSON.parse(analysis) as Record<string, unknown>;
      return api(`/api/incidents/${selected}/files`, {
        method: "POST",
        body: JSON.stringify(parsed),
      });
    },
    onSuccess: () => {
      setAnalysis("");
      void qc.invalidateQueries({ queryKey: ["incident", selected] });
    },
  });
  return (
    <div>
      <PageHeader
        eyebrow="Detection"
        title="Incident investigations"
        description="Correlate actual endpoint findings, suspicious-file metadata, timelines, confidence, and evidence limitations."
      />
      <Caveat className="mb-4">
        NO_FINDINGS_OBSERVED does not mean clean. NextAura stores metadata and
        evidence only; it does not upload, execute, mount, delete, or quarantine
        suspicious files.
      </Caveat>
      {canAnalyze(role) && (
        <Panel title="Open an investigation" className="mb-4">
          <div className="flex flex-wrap gap-2">
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Incident title"
              className="h-9 min-w-[260px] flex-1 rounded-lg border border-input bg-card px-3 text-sm"
            />
            <select
              value={severity}
              onChange={(e) =>
                setSeverity(e.target.value as Incident["severity"])
              }
              className="h-9 rounded-lg border border-input bg-card px-3 text-sm"
            >
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
            <button
              disabled={!title.trim() || create.isPending}
              onClick={() => create.mutate()}
              className="inline-flex h-9 items-center gap-2 rounded-lg bg-violet px-3 text-sm font-medium text-white"
            >
              <Plus className="size-4" />
              Create
            </button>
          </div>
          {create.error && (
            <p className="mt-2 text-xs text-crit">{String(create.error)}</p>
          )}
        </Panel>
      )}
      <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
        <Panel title="Investigations" bodyClassName="p-0">
          {list.isLoading ? (
            <div className="p-4">
              <SkeletonRows rows={6} cols={2} />
            </div>
          ) : list.isError ? (
            <div className="p-4">
              <ErrorState error={list.error} />
            </div>
          ) : !list.data?.length ? (
            <EmptyState
              icon={<FileSearch className="size-5" />}
              title="No incidents recorded"
              body="Create an investigation only when there is a real question or evidence to track."
            />
          ) : (
            <div>
              {list.data.map((i) => (
                <button
                  key={i.id}
                  onClick={() => setSelected(i.id)}
                  className={`block w-full border-b hairline p-4 text-left hover:bg-white/[0.03] ${selected === i.id ? "bg-violet/10" : ""}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{i.title}</span>
                    <SeverityPill s={i.severity} />
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <Pill tone={i.status === "CLOSED" ? "ok" : "violet"}>
                      {i.status}
                    </Pill>
                    <span className="text-xs text-muted-foreground">
                      Confidence {i.confidence}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </Panel>
        <Panel title={detail.data?.incident.title ?? "Investigation evidence"}>
          {!selected ? (
            <EmptyState
              icon={<FileSearch className="size-5" />}
              title="Select an incident"
              body="Review evidence, file metadata, timeline, limitations, and response guidance."
            />
          ) : detail.isLoading ? (
            <SkeletonRows rows={8} cols={2} />
          ) : detail.isError ? (
            <ErrorState error={detail.error} />
          ) : (
            detail.data && (
              <div className="space-y-5">
                <div className="flex flex-wrap gap-2">
                  <SeverityPill s={detail.data.incident.severity} />
                  <Pill tone="violet">{detail.data.incident.status}</Pill>
                  <Pill tone="info">
                    {detail.data.incident.confidence} confidence
                  </Pill>
                  <a
                    className="ml-auto text-sm text-cyan hover:underline"
                    href={`/api/incidents/${selected}/report`}
                  >
                    Download PDF report
                  </a>
                </div>
                <p className="text-sm text-muted-foreground">
                  {detail.data.incident.summary}
                </p>
                <Evidence
                  title={`Associated devices (${detail.data.devices.length})`}
                >
                  {detail.data.devices.map((device) => (
                    <div
                      key={device.id}
                      className="rounded-lg border hairline p-3 text-sm"
                    >
                      {device.name}{" "}
                      <span className="text-muted-foreground">
                        ({device.osType})
                      </span>
                    </div>
                  ))}
                </Evidence>
                <Evidence
                  title={`Associated findings (${detail.data.findings.length})`}
                >
                  {detail.data.findings.map((f) => (
                    <div key={f.id} className="rounded-lg border hairline p-3">
                      <div className="flex gap-2">
                        <Pill tone={severityTone(f.severity)}>
                          {f.severity}
                        </Pill>
                        <span className="font-medium">{f.title}</span>
                      </div>
                      <p className="mt-2 text-xs text-muted-foreground">
                        {f.evidence}
                      </p>
                    </div>
                  ))}
                </Evidence>
                <Evidence
                  title={`Suspicious files (${detail.data.files.length})`}
                >
                  {detail.data.files.map((f) => (
                    <div key={f.id} className="rounded-lg border hairline p-3">
                      <div className="flex flex-wrap gap-2">
                        <span className="font-medium">{f.fileName}</span>
                        <Pill
                          tone={
                            f.classification === "CONFIRMED_DETECTION"
                              ? "crit"
                              : f.classification === "SUSPICIOUS_INDICATOR"
                                ? "warn"
                                : "neutral"
                          }
                        >
                          {f.classification}
                        </Pill>
                      </div>
                      <div className="mt-2 break-all font-mono text-[11px] text-muted-foreground">
                        SHA-256 {f.sha256}
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {f.detectedType}; signature metadata{" "}
                        {f.signatureMetadata}
                      </div>
                    </div>
                  ))}
                </Evidence>
                {canAnalyze(role) && (
                  <div>
                    <label className="text-xs font-medium">
                      Import bounded `inspect-file` JSON evidence
                    </label>
                    <textarea
                      value={analysis}
                      onChange={(e) => setAnalysis(e.target.value)}
                      rows={5}
                      className="mt-2 w-full rounded-lg border border-input bg-card p-3 font-mono text-xs"
                      placeholder='{"fileName":"invoice.pdf.exe", ...}'
                    />
                    <button
                      disabled={!analysis.trim() || addFile.isPending}
                      onClick={() => addFile.mutate()}
                      className="mt-2 rounded-lg border border-violet/40 bg-violet/10 px-3 py-2 text-xs"
                    >
                      Attach metadata
                    </button>
                    {addFile.error && (
                      <p className="mt-2 text-xs text-crit">
                        {String(addFile.error)}
                      </p>
                    )}
                    <Evidence
                      title={`Evidence timeline (${detail.data.timeline.length})`}
                    >
                      {detail.data.timeline.map((event) => (
                        <div
                          key={event.id}
                          className="rounded-lg border hairline p-3"
                        >
                          <div className="flex flex-wrap justify-between gap-2 text-sm font-medium">
                            <span>{event.title}</span>
                            <time className="font-mono text-[11px] text-muted-foreground">
                              {new Date(event.occurredAt).toISOString()}
                            </time>
                          </div>
                          <p className="mt-2 text-xs text-muted-foreground">
                            {event.evidence}
                          </p>
                          <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                            Source: {event.source}
                          </p>
                        </div>
                      ))}
                    </Evidence>
                  </div>
                )}
                <Evidence title="Evidence limitations">
                  {detail.data.incident.evidenceLimitations.map((x, i) => (
                    <p key={i} className="text-xs text-muted-foreground">
                      - {x}
                    </p>
                  ))}
                </Evidence>
                <Evidence title="Recommended manual actions">
                  {detail.data.incident.recommendedActions.map((x, i) => (
                    <p key={i} className="text-xs text-muted-foreground">
                      - {x}
                    </p>
                  ))}
                </Evidence>
              </div>
            )
          )}
        </Panel>
      </div>
    </div>
  );
}

function Evidence({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      <div className="space-y-2">{children}</div>
    </section>
  );
}
