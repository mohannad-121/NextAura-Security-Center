import { useEffect, useState } from "react";
import { Link } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import {
  Apple,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  Download,
  Loader2,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import {
  getGetDeviceQueryKey,
  getGetEnrollmentQueryKey,
  getListEnrollmentsQueryKey,
  useCancelEnrollment,
  useCreateEnrollment,
  useGetDevice,
  useGetEnrollment,
  useListAgentBuilds,
  useListEnrollments,
  type AgentBuildPlatform,
  type EnrollmentCreated,
  type OsType,
} from "@workspace/api-client-react";
import { useT } from "@/i18n";
import { canAdmin, useMe, usePageMeta, useRole } from "@/lib/session";
import { errMsg, fmtBytes, fmtDate, fmtRel } from "@/lib/format";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import {
  Caveat,
  CodeLine,
  CopyButton,
  ErrorState,
  KV,
  PageHeader,
  Panel,
  Pill,
  SkeletonRows,
} from "@/components/app/primitives";

type Choice = {
  key: string;
  label: string;
  sub: string;
  osType: OsType;
  platform: AgentBuildPlatform;
};
const CHOICES: Choice[] = [
  {
    key: "win",
    label: "Windows",
    sub: "x64 · Windows 10 / 11",
    osType: "WINDOWS",
    platform: "windows-amd64",
  },
  {
    key: "mac-intel",
    label: "macOS",
    sub: "Intel",
    osType: "MACOS",
    platform: "darwin-amd64",
  },
  {
    key: "mac-arm",
    label: "macOS",
    sub: "Apple Silicon",
    osType: "MACOS",
    platform: "darwin-arm64",
  },
];
const BUILD_CMD: Record<AgentBuildPlatform, string> = {
  "windows-amd64": ".\\agent\\scripts\\build-agent.ps1",
  "darwin-amd64": "./agent/scripts/build-agent.sh darwin-amd64",
  "darwin-arm64": "./agent/scripts/build-agent.sh darwin-arm64",
};
const STEPS = [
  "Organization",
  "Operating system",
  "Install package",
  "Enrollment code",
  "Consent & install",
  "Wait for enrollment",
  "Verify online",
];

export default function Enroll() {
  const t = useT();
  usePageMeta(t("enroll.title"), t("enroll.description"));
  const role = useRole();
  const me = useMe();
  const [step, setStep] = useState(0);
  const [choice, setChoice] = useState<Choice | null>(null);
  const [detectedOS, setDetectedOS] = useState<string | null>(null);
  const [created, setCreated] = useState<EnrollmentCreated | null>(null);
  const [deviceId, setDeviceId] = useState<string | null>(null);

  useEffect(() => {
    const ua = navigator.userAgent;
    if (/Windows/i.test(ua)) {
      setDetectedOS(
        "Windows detected — Windows x64 selected. You can override it below.",
      );
      setChoice((current) => current ?? CHOICES[0]!);
    } else if (/Macintosh|Mac OS X/i.test(ua)) {
      setDetectedOS(
        "macOS detected — choose Intel or Apple Silicon to match About This Mac.",
      );
    } else {
      setDetectedOS(
        "This browser's operating system is unsupported. Select a supported target only for another authorized device.",
      );
    }
  }, []);

  if (!canAdmin(role))
    return (
      <div>
        <PageHeader title={t("enroll.title")} />
        <ErrorState title="Only Owners and Admins can enroll devices." />
      </div>
    );

  return (
    <div>
      <Link
        href="/devices"
        className="mb-4 inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Devices
      </Link>
      <PageHeader
        eyebrow="Seven steps · consent first"
        title={t("enroll.title")}
        description={t("enroll.description")}
      />
      <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
        <ol className="space-y-1">
          {STEPS.map((s, i) => (
            <li
              key={s}
              aria-current={i === step ? "step" : undefined}
              className={cn(
                "flex items-center gap-3 rounded-lg px-2.5 py-2 text-[13px]",
                i === step
                  ? "bg-white/[0.04] text-foreground"
                  : i < step
                    ? "text-muted-foreground"
                    : "text-muted-foreground/60",
              )}
            >
              <span
                className={cn(
                  "grid size-6 place-items-center rounded-full border font-mono text-[10.5px]",
                  i < step
                    ? "border-ok/40 bg-ok/10 text-ok"
                    : i === step
                      ? "border-violet bg-violet/15 text-foreground"
                      : "border-border",
                )}
              >
                {i < step ? <Check className="size-3" /> : i + 1}
              </span>
              {s}
            </li>
          ))}
        </ol>
        <div className="min-w-0" aria-live="polite" aria-atomic="false">
          {step === 0 && (
            <Panel
              title="Confirm organization"
              subtitle="The device will report into this organization only."
            >
              <dl>
                <KV label="Organization">{me.currentOrganization?.name}</KV>
                <KV label="Slug" mono>
                  {me.currentOrganization?.slug}
                </KV>
                <KV label="Your role">{me.currentOrganization?.role}</KV>
              </dl>
              {me.demoMode && (
                <Caveat tone="warn" className="mt-4">
                  This is the demonstration organization. Enroll real devices
                  into your own organization instead.
                </Caveat>
              )}
              <Nav onNext={() => setStep(1)} />
            </Panel>
          )}
          {step === 1 && (
            <Panel
              title="Choose operating system"
              subtitle="Both macOS variants enroll as osType MACOS; they only differ in the agent binary."
            >
              {detectedOS && <Caveat className="mb-4">{detectedOS}</Caveat>}
              <div className="grid gap-3 sm:grid-cols-3">
                {CHOICES.map((c) => (
                  <button
                    key={c.key}
                    data-testid={`button-os-${c.key}`}
                    onClick={() => setChoice(c)}
                    aria-pressed={choice?.key === c.key}
                    className={cn(
                      "rounded-xl border p-4 text-left transition-colors",
                      choice?.key === c.key
                        ? "border-violet bg-violet/10"
                        : "border-border hover:bg-white/[0.03]",
                    )}
                  >
                    {c.osType === "MACOS" ? (
                      <Apple className="size-5 text-muted-foreground" />
                    ) : (
                      <span className="font-mono text-xs text-cyan">WIN</span>
                    )}
                    <div className="mt-3 text-sm font-medium">{c.label}</div>
                    <div className="text-xs text-muted-foreground">{c.sub}</div>
                    <div className="mt-2 font-mono text-[10.5px] text-muted-foreground">
                      {c.platform}
                    </div>
                  </button>
                ))}
              </div>
              <Nav
                onBack={() => setStep(0)}
                onNext={() => setStep(2)}
                disabled={!choice}
              />
            </Panel>
          )}
          {step === 2 && choice && (
            <Install
              choice={choice}
              onBack={() => setStep(1)}
              onNext={() => setStep(3)}
            />
          )}
          {step === 3 && choice && (
            <CodeStep
              choice={choice}
              created={created}
              onCreated={setCreated}
              onBack={() => setStep(2)}
              onNext={() => setStep(4)}
            />
          )}
          {step === 4 && created && choice && (
            <Panel
              title="Consent and installation"
              subtitle="Show this notice to the person who uses the device before running the installer."
            >
              <ul className="space-y-2">
                {created.consentSummary.map((c, i) => (
                  <li
                    key={i}
                    className="flex gap-2.5 text-[13px] text-slate-300"
                  >
                    <Check className="mt-0.5 size-3.5 shrink-0 text-cyan" /> {c}
                  </li>
                ))}
              </ul>
              <Caveat className="mt-4">
                The agent cannot run commands, transfer files, or change
                settings. It only reports from fixed collectors.
              </Caveat>
              <div className="mt-5">
                <div className="eyebrow mb-1.5">
                  After extracting the downloaded package, run
                </div>
                <CodeLine copy>
                  {installCommand(choice, created.serverUrl)}
                </CodeLine>
              </div>
              <Caveat tone="warn" className="mt-4">
                Administrator authorization is required because the installer
                creates a visible background service and protects the device
                credential. It will request the enrollment code with hidden
                input so the code is not stored in shell history or process
                arguments. Do not disable SmartScreen, Gatekeeper, SIP, or TCC.
              </Caveat>
              <Nav
                onBack={() => setStep(3)}
                onNext={() => setStep(5)}
                nextLabel="Consent confirmed; installation started"
              />
            </Panel>
          )}
          {step === 5 && created && (
            <WaitEnroll
              id={created.id}
              onDone={(dev) => {
                setDeviceId(dev);
                setStep(6);
              }}
              onBack={() => setStep(4)}
            />
          )}
          {step === 6 && deviceId && <VerifyOnline id={deviceId} />}
        </div>
      </div>
      <ExistingCodes />
    </div>
  );
}

function Nav({
  onBack,
  onNext,
  disabled,
  nextLabel = "Continue",
}: {
  onBack?: () => void;
  onNext?: () => void;
  disabled?: boolean;
  nextLabel?: string;
}) {
  return (
    <div className="mt-6 flex justify-between border-t hairline pt-4">
      {onBack ? (
        <button
          onClick={onBack}
          data-testid="button-back"
          className="min-h-11 rounded-lg border border-border px-3.5 py-2 text-sm hover:bg-white/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet"
        >
          Back
        </button>
      ) : (
        <span />
      )}
      {onNext && (
        <button
          onClick={onNext}
          disabled={disabled}
          data-testid="button-next"
          className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet"
        >
          {nextLabel} <ArrowRight className="size-4" />
        </button>
      )}
    </div>
  );
}

function Install({
  choice,
  onBack,
  onNext,
}: {
  choice: Choice;
  onBack: () => void;
  onNext: () => void;
}) {
  const q = useListAgentBuilds();
  const b = q.data?.find((x) => x.platform === choice.platform);
  const ready = !!b?.available && b.verified && !!b.downloadPath;
  return (
    <Panel
      title="Installation information"
      subtitle={`${choice.label} ${choice.sub} · ${choice.platform}`}
    >
      {q.isLoading ? (
        <SkeletonRows rows={4} cols={2} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : b && b.available ? (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Pill tone={b.verified ? "ok" : "warn"}>
              {b.verified ? "Verified on target OS" : "Not verified"}
            </Pill>
            <Pill tone={b.signed ? "ok" : "warn"}>
              {b.signed ? "Code signed" : "Unsigned"}
            </Pill>
          </div>
          <dl>
            <KV label="File" mono>
              {b.fileName}
            </KV>
            <KV label="Version" mono>
              {b.version ?? "UNKNOWN"}
            </KV>
            <KV label="Size" mono>
              {fmtBytes(b.sizeBytes)}
            </KV>
            <KV label="Built">{fmtDate(b.builtAt)}</KV>
          </dl>
          {b.sha256 && (
            <div>
              <div className="eyebrow mb-1.5">SHA-256</div>
              <CodeLine copy>{b.sha256}</CodeLine>
            </div>
          )}
          <p className="text-xs text-muted-foreground">{b.verificationNote}</p>
          {ready && (
            <a
              href={b.downloadPath ?? undefined}
              data-testid="link-download-agent"
              className="inline-flex items-center gap-2 rounded-lg border border-cyan/40 bg-cyan/10 px-3.5 py-2 text-sm text-foreground hover:bg-cyan/15"
            >
              <Download className="size-4" /> Download {b.fileName}
            </a>
          )}
          {!b.verified && (
            <Caveat tone="warn">
              Download is disabled because this package has not completed a
              native enrollment test. Ask the release operator to follow the
              verification procedure.
            </Caveat>
          )}
          {b.verified && !b.signed && (
            <Caveat tone="warn">
              This controlled-testing package is not code signed. Verify its
              SHA-256. It is not production-ready and must not be distributed as
              trusted software.
            </Caveat>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-start gap-3 rounded-xl border border-dashed border-unknown/40 bg-white/[0.02] p-4">
            <ShieldAlert className="mt-0.5 size-4 text-unknown" />
            <div className="text-[13px]">
              <div className="font-medium">
                No verified build on this server
              </div>
              <div className="mt-1 text-muted-foreground">
                There is no complete {choice.platform} install package
                available. A release operator can build it with:
              </div>
            </div>
          </div>
          <CodeLine copy>{BUILD_CMD[choice.platform]}</CodeLine>
          {b && (
            <p className="text-xs text-muted-foreground">
              {b.verificationNote}
            </p>
          )}
        </div>
      )}
      <Nav
        onBack={onBack}
        onNext={onNext}
        disabled={!ready}
        nextLabel={ready ? "Package downloaded" : "Build not available"}
      />
    </Panel>
  );
}

function Countdown({ to }: { to: string }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const s = Math.max(0, Math.floor((new Date(to).getTime() - now) / 1000));
  return (
    <span
      className={cn(
        "font-mono tabular",
        s < 120 ? "text-warn" : "text-foreground",
      )}
      data-testid="text-countdown"
    >
      {s === 0
        ? "expired"
        : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`}
    </span>
  );
}

function CodeStep({
  choice,
  created,
  onCreated,
  onBack,
  onNext,
}: {
  choice: Choice;
  created: EnrollmentCreated | null;
  onCreated: (c: EnrollmentCreated) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const qc = useQueryClient();
  const [label, setLabel] = useState("");
  const m = useCreateEnrollment({
    mutation: {
      onSuccess: (c) => {
        onCreated(c);
        void qc.invalidateQueries({ queryKey: getListEnrollmentsQueryKey() });
      },
    },
  });
  if (!created)
    return (
      <Panel
        title="Generate enrollment code"
        subtitle="A single-use code with a short expiry. The full code is shown once and never stored."
      >
        <label className="block text-xs text-muted-foreground" htmlFor="label">
          Device label (optional)
        </label>
        <input
          id="label"
          data-testid="input-device-label"
          value={label}
          maxLength={120}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="Reception desktop"
          className="mt-1.5 h-9 w-full max-w-sm rounded-lg border border-input bg-card px-3 text-[13px] outline-none focus:border-violet"
        />
        {m.isError && (
          <p className="mt-2 text-xs text-crit" role="alert">
            {errMsg(m.error)}
          </p>
        )}
        <div className="mt-6 flex justify-between border-t hairline pt-4">
          <button
            onClick={onBack}
            className="rounded-lg border border-border px-3.5 py-2 text-sm hover:bg-white/[0.04]"
          >
            Back
          </button>
          <button
            data-testid="button-generate-code"
            disabled={m.isPending}
            onClick={() =>
              m.mutate({
                data: {
                  osType: choice.osType,
                  ...(label.trim() ? { deviceLabel: label.trim() } : {}),
                },
              })
            }
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
          >
            {m.isPending && <Loader2 className="size-4 animate-spin" />}{" "}
            Generate code
          </button>
        </div>
      </Panel>
    );
  return (
    <Panel
      title="Enrollment code"
      subtitle="Copy it now. It will not be shown again."
    >
      <div className="flex flex-wrap items-center gap-4 rounded-xl border border-violet/30 bg-violet/[0.07] p-5">
        <code
          className="font-mono text-2xl tracking-[0.2em] text-foreground"
          data-testid="text-enrollment-code"
        >
          {created.code}
        </code>
        <CopyButton value={created.code} />
        <div className="ml-auto text-xs text-muted-foreground">
          Expires in <Countdown to={created.expiresAt} />
        </div>
      </div>
      <div className="mt-5 space-y-3">
        <div>
          <div className="eyebrow mb-1.5">Server URL</div>
          <CodeLine copy>{created.serverUrl}</CodeLine>
        </div>
        <Caveat>
          The exact installer command appears on the next screen together with
          the consent notice.
        </Caveat>
      </div>
      <Nav onNext={onNext} />
    </Panel>
  );
}

function installCommand(choice: Choice, serverUrl: string) {
  return choice.osType === "WINDOWS"
    ? `.\\install-agent.ps1 -ServerUrl "${serverUrl}"`
    : `sudo ./install-agent.sh --server '${serverUrl}'`;
}

function WaitEnroll({
  id,
  onDone,
  onBack,
}: {
  id: string;
  onDone: (deviceId: string) => void;
  onBack: () => void;
}) {
  const q = useGetEnrollment(id, {
    query: {
      enabled: !!id,
      queryKey: getGetEnrollmentQueryKey(id),
      refetchInterval: (query) =>
        query.state.data?.status === "PENDING" || !query.state.data
          ? 3000
          : false,
    },
  });
  const e = q.data;
  return (
    <Panel
      title="Waiting for enrollment"
      subtitle="Checking every 3 seconds for the agent to redeem the code."
    >
      {!e ? (
        q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <SkeletonRows rows={2} cols={2} />
        )
      ) : e.status === "PENDING" ? (
        <div
          className="flex items-center gap-3 rounded-xl border hairline p-4"
          role="status"
        >
          <Loader2 className="size-4 animate-spin text-cyan" />
          <div className="text-[13px]">
            Code <span className="font-mono">{e.codeHint}••••</span> not yet
            used. Expires {fmtRel(e.expiresAt)}.
          </div>
        </div>
      ) : e.status === "CONSUMED" ? (
        <div className="space-y-4">
          <div
            className="flex items-center gap-3 rounded-xl border border-ok/30 bg-ok/[0.07] p-4 text-[13px]"
            role="status"
          >
            <CheckCircle2 className="size-4 text-ok" /> Enrolled as{" "}
            <span className="font-medium">{e.deviceName ?? "device"}</span> at{" "}
            {fmtDate(e.consumedAt)}.
          </div>
          {e.deviceId && (
            <Nav
              onNext={() => onDone(e.deviceId!)}
              nextLabel="Verify device online"
            />
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-3 rounded-xl border border-dashed border-unknown/40 p-4 text-[13px]">
            <XCircle className="size-4 text-unknown" /> This code is{" "}
            {e.status.toLowerCase()}. Generate a new one to continue.
          </div>
          <button
            onClick={onBack}
            className="rounded-lg border border-border px-3.5 py-2 text-sm hover:bg-white/[0.04]"
          >
            Back
          </button>
        </div>
      )}
    </Panel>
  );
}

function VerifyOnline({ id }: { id: string }) {
  const q = useGetDevice(id, {
    query: {
      enabled: !!id,
      queryKey: getGetDeviceQueryKey(id),
      refetchInterval: (query) => (query.state.data?.isOnline ? false : 5000),
    },
  });
  const d = q.data;
  return (
    <Panel
      title="Verify device online"
      subtitle="A device is online only after an authenticated heartbeat."
    >
      {!d ? (
        q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <SkeletonRows rows={2} cols={2} />
        )
      ) : d.isOnline ? (
        <div className="space-y-4">
          <div
            className="flex items-center gap-3 rounded-xl border border-ok/30 bg-ok/[0.07] p-4 text-[13px]"
            role="status"
          >
            <CheckCircle2 className="size-4 text-ok" /> {d.name} is online. Last
            heartbeat {fmtRel(d.lastSeenAt)}.
          </div>
          <Link
            href={`/devices/${d.id}`}
            data-testid="link-open-device"
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-medium text-primary-foreground"
          >
            Open device <ArrowRight className="size-4" />
          </Link>
        </div>
      ) : (
        <div
          className="flex items-center gap-3 rounded-xl border hairline p-4 text-[13px]"
          role="status"
        >
          <Loader2 className="size-4 animate-spin text-cyan" /> Waiting for
          first heartbeat from {d.name}…
        </div>
      )}
    </Panel>
  );
}

function ExistingCodes() {
  const q = useListEnrollments();
  const qc = useQueryClient();
  const { toast } = useToast();
  const cancel = useCancelEnrollment({
    mutation: {
      onSuccess: () => {
        void qc.invalidateQueries({ queryKey: getListEnrollmentsQueryKey() });
        toast({ title: "Enrollment code cancelled" });
      },
      onError: (e) =>
        toast({
          title: "Could not cancel",
          description: errMsg(e),
          variant: "destructive",
        }),
    },
  });
  const tone = {
    PENDING: "info",
    CONSUMED: "ok",
    EXPIRED: "neutral",
    CANCELLED: "neutral",
  } as const;
  return (
    <Panel
      className="mt-8"
      title="Enrollment codes"
      subtitle="Only the first four characters are retained."
      bodyClassName="p-0"
    >
      {q.isLoading ? (
        <div className="p-5">
          <SkeletonRows rows={3} cols={5} />
        </div>
      ) : q.isError ? (
        <div className="p-5">
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        </div>
      ) : !q.data?.length ? (
        <p className="p-5 text-sm text-muted-foreground">
          No enrollment codes generated yet.
        </p>
      ) : (
        <div className="overflow-x-auto scroll-thin">
          <table className="w-full min-w-[720px] text-[13px]">
            <thead>
              <tr className="eyebrow border-b hairline text-left">
                <th className="px-5 py-2.5 font-normal">Code</th>
                <th className="px-3 py-2.5 font-normal">OS</th>
                <th className="px-3 py-2.5 font-normal">Label / device</th>
                <th className="px-3 py-2.5 font-normal">Status</th>
                <th className="px-3 py-2.5 font-normal">Created</th>
                <th className="px-5 py-2.5 text-right font-normal" />
              </tr>
            </thead>
            <tbody>
              {q.data.map((e) => (
                <tr key={e.id} className="border-b hairline last:border-0">
                  <td className="px-5 py-2.5 font-mono text-xs">
                    {e.codeHint}••••
                  </td>
                  <td className="px-3 py-2.5 text-xs">{e.osType}</td>
                  <td className="px-3 py-2.5">
                    {e.deviceId ? (
                      <Link
                        href={`/devices/${e.deviceId}`}
                        className="text-cyan hover:underline"
                      >
                        {e.deviceName}
                      </Link>
                    ) : (
                      (e.deviceLabel ?? (
                        <span className="text-muted-foreground">—</span>
                      ))
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <Pill tone={tone[e.status]}>{e.status}</Pill>
                  </td>
                  <td className="px-3 py-2.5 text-xs text-muted-foreground">
                    {fmtDate(e.createdAt)} · {e.createdByEmail}
                  </td>
                  <td className="px-5 py-2.5 text-right">
                    {e.status === "PENDING" && (
                      <button
                        data-testid={`button-cancel-enrollment-${e.id}`}
                        disabled={cancel.isPending}
                        onClick={() => cancel.mutate({ id: e.id })}
                        className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-white/[0.04]"
                      >
                        Cancel
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
