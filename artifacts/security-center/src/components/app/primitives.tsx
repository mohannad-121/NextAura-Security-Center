import { useState, type ReactNode } from "react";
import { AlertTriangle, Check, Copy, Info, RotateCw } from "lucide-react";
import type {
  AgentReliability,
  CheckStatus,
  Confidence,
  CoverageStatus,
  MatchConfidence,
  RiskLevel,
  Severity,
} from "@workspace/api-client-react";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { errMsg, humanize } from "@/lib/format";

export type Tone = "ok" | "warn" | "crit" | "high" | "info" | "violet" | "neutral";

const toneCls: Record<Tone, string> = {
  ok: "text-ok bg-ok/10 border-ok/30",
  warn: "text-warn bg-warn/10 border-warn/30",
  crit: "text-crit bg-crit/10 border-crit/35",
  high: "text-high bg-high/10 border-high/30",
  info: "text-cyan bg-cyan/10 border-cyan/30",
  violet: "text-violet bg-violet/10 border-violet/30",
  neutral: "text-unknown bg-white/[0.03] border-unknown/40 border-dashed",
};
export const toneDot: Record<Tone, string> = {
  ok: "bg-ok",
  warn: "bg-warn",
  crit: "bg-crit",
  high: "bg-high",
  info: "bg-cyan",
  violet: "bg-violet",
  neutral: "bg-unknown/70",
};
export const toneHex: Record<Tone, string> = {
  ok: "#22C55E",
  warn: "#F59E0B",
  crit: "#EF4444",
  high: "#F97340",
  info: "#38BDF8",
  violet: "#7568E8",
  neutral: "#7F889C",
};

export const severityTone = (s: Severity | RiskLevel | string): Tone =>
  ({ CRITICAL: "crit", HIGH: "high", MEDIUM: "warn", LOW: "info", INFO: "neutral", UNKNOWN: "neutral" } as Record<string, Tone>)[s] ??
  "neutral";
export const checkTone = (s: CheckStatus | string): Tone =>
  ({ PASS: "ok", FAIL: "crit", WARNING: "warn", STALE: "warn" } as Record<string, Tone>)[s] ?? "neutral";
export const reliabilityTone = (s: AgentReliability): Tone =>
  ({ HEALTHY: "ok", DEGRADED: "warn", OFFLINE: "neutral", REVOKED: "crit", NEVER_REPORTED: "neutral" } as Record<string, Tone>)[s];
export const coverageTone = (s: CoverageStatus): Tone =>
  ({ FULL: "ok", PARTIAL: "warn", STALE: "warn", NONE: "neutral" } as Record<string, Tone>)[s];
export const confidenceTone = (s: Confidence | MatchConfidence): Tone =>
  ({ HIGH: "violet", CONFIRMED: "violet", MEDIUM: "info", PROBABLE: "info", LOW: "neutral", POSSIBLE: "neutral", UNKNOWN: "neutral" } as Record<string, Tone>)[s];

export function Pill({ tone, children, dot = true, className, ...rest }: { tone: Tone; children: ReactNode; dot?: boolean; className?: string; "data-testid"?: string }) {
  return (
    <span
      {...rest}
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-1.5 py-0.5 font-mono text-[10.5px] font-medium uppercase tracking-wider",
        toneCls[tone],
        className,
      )}
    >
      {dot && <span className={cn("size-1.5 rounded-full", toneDot[tone])} />}
      {children}
    </span>
  );
}

export const SeverityPill = ({ s }: { s: Severity | RiskLevel }) => <Pill tone={severityTone(s)}>{s}</Pill>;
export const CheckPill = ({ s }: { s: CheckStatus }) => <Pill tone={checkTone(s)}>{s.replace(/_/g, " ")}</Pill>;

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="rise mb-7 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
      <div className="min-w-0">
        {eyebrow && <div className="eyebrow mb-2">{eyebrow}</div>}
        <h1 className="text-[26px] font-semibold leading-tight tracking-[-0.02em] text-foreground">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className,
  bodyClassName,
  ...rest
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  "data-testid"?: string;
}) {
  return (
    <section {...rest} className={cn("glass rise rounded-2xl", className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b hairline px-5 py-3.5">
          <div className="min-w-0">
            {title && <h2 className="text-[13.5px] font-semibold tracking-tight text-foreground">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn("p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

export function KV({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b hairline py-2 last:border-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={cn("min-w-0 truncate text-right text-[13px] text-foreground", mono && "font-mono text-xs")}>{children}</dd>
    </div>
  );
}

export function EmptyState({ icon, title, body, action, className }: { icon?: ReactNode; title: string; body?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn("relative flex flex-col items-center justify-center overflow-hidden rounded-xl px-6 py-12 text-center", className)}>
      <div className="grid-bg pointer-events-none absolute inset-0 [mask-image:radial-gradient(closest-side,black,transparent)]" />
      {icon && (
        <div className="relative mb-4 grid size-12 place-items-center rounded-xl border border-violet/25 bg-violet/10 text-violet">{icon}</div>
      )}
      <h3 className="relative text-[15px] font-semibold text-foreground">{title}</h3>
      {body && <p className="relative mt-1.5 max-w-md text-sm text-muted-foreground">{body}</p>}
      {action && <div className="relative mt-5">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, title = "We could not load this data." }: { error?: unknown; onRetry?: () => void; title?: string }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-crit/25 bg-crit/[0.06] px-6 py-8 text-center" data-testid="state-error">
      <AlertTriangle className="size-5 text-crit" />
      <div>
        <div className="text-sm font-medium text-foreground">{title}</div>
        {error != null && <div className="mt-1 font-mono text-xs text-muted-foreground">{errMsg(error)}</div>}
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          data-testid="button-retry"
          className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-secondary px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-accent"
        >
          <RotateCw className="size-3.5" /> Try again
        </button>
      )}
    </div>
  );
}

export function Caveat({ children, tone = "info", className }: { children: ReactNode; tone?: "info" | "warn"; className?: string }) {
  return (
    <div
      className={cn(
        "flex gap-2.5 rounded-xl border px-3.5 py-2.5 text-xs leading-relaxed",
        tone === "info" ? "border-cyan/20 bg-cyan/[0.05] text-slate-300" : "border-warn/25 bg-warn/[0.06] text-amber-100/90",
        className,
      )}
    >
      <Info className={cn("mt-0.5 size-3.5 shrink-0", tone === "info" ? "text-cyan" : "text-warn")} />
      <div>{children}</div>
    </div>
  );
}

export function StatTile({ label, value, hint, accent, testId }: { label: string; value: ReactNode; hint?: ReactNode; accent?: Tone; testId?: string }) {
  return (
    <div className="glass rise relative overflow-hidden rounded-2xl p-4">
      {accent && <span className={cn("absolute inset-x-0 top-0 h-px opacity-70", toneDot[accent])} />}
      <div className="eyebrow">{label}</div>
      <div className="mt-2 text-[28px] font-semibold leading-none tracking-tight tabular text-foreground" data-testid={testId}>
        {value}
      </div>
      {hint && <div className="mt-2 text-xs text-muted-foreground">{hint}</div>}
    </div>
  );
}

export function SkeletonRows({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2.5" data-testid="state-loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          {Array.from({ length: cols }).map((__, j) => (
            <Skeleton key={j} className="h-5 flex-1 bg-white/[0.05]" style={{ opacity: 1 - i * 0.1 }} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonBlock({ className }: { className?: string }) {
  return <Skeleton className={cn("rounded-2xl bg-white/[0.04]", className)} />;
}

export function CopyButton({ value, label = "Copy", className }: { value: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      data-testid="button-copy"
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1600);
        });
      }}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border border-border bg-secondary px-2 py-1 text-[11px] font-medium text-foreground transition-colors hover:bg-accent",
        className,
      )}
    >
      {done ? <Check className="size-3 text-ok" /> : <Copy className="size-3" />}
      {done ? "Copied" : label}
    </button>
  );
}

export function CodeLine({ children, copy }: { children: string; copy?: boolean }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2">
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-pre font-mono text-xs text-cyan scroll-thin">{children}</code>
      {copy && <CopyButton value={children} />}
    </div>
  );
}

export function Meter({ value, tone = "violet" }: { value: number; tone?: Tone }) {
  const v = Math.max(0, Math.min(100, value));
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
      <div className={cn("h-full origin-left rounded-full", toneDot[tone])} style={{ width: `${v}%` }} />
    </div>
  );
}

export function FilterSelect<T extends string>({
  value,
  onChange,
  options,
  allLabel,
  testId,
}: {
  value: T | "";
  onChange: (v: NoInfer<T> | "") => void;
  options: readonly T[];
  allLabel: string;
  testId: string;
}) {
  return (
    <select
      data-testid={testId}
      value={value}
      onChange={(e) => onChange(e.target.value as T | "")}
      className="h-9 rounded-lg border border-input bg-card px-2.5 text-[13px] text-foreground outline-none transition-colors hover:border-violet/40 focus:border-violet"
    >
      <option value="">{allLabel}</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {humanize(o)}
        </option>
      ))}
    </select>
  );
}

export function SevCounts({ c }: { c: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number } }) {
  const items: [keyof typeof c, Tone][] = [
    ["CRITICAL", "crit"],
    ["HIGH", "high"],
    ["MEDIUM", "warn"],
    ["LOW", "info"],
  ];
  const total = c.CRITICAL + c.HIGH + c.MEDIUM + c.LOW;
  if (!total) return <span className="text-xs text-muted-foreground">None open</span>;
  return (
    <div className="flex items-center gap-1">
      {items.map(([k, t]) =>
        c[k] ? (
          <span key={k} title={k} className={cn("rounded px-1.5 py-0.5 font-mono text-[10.5px] tabular", toneCls[t].replace("border-dashed", ""))}>
            {c[k]}
            {k[0]}
          </span>
        ) : null,
      )}
    </div>
  );
}
