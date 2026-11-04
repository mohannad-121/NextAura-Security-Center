import { Link, Redirect } from "wouter";
import { useAuth } from "@clerk/react";
import { ArrowRight, Ban, Eye, FileCheck2, KeyRound, ListChecks, MonitorSmartphone, ShieldCheck, Terminal, UserCheck, Wrench } from "lucide-react";
import { useT } from "@/i18n";
import { usePageMeta } from "@/lib/session";
import { Logo } from "@/components/app/logo";
import { Pill } from "@/components/app/primitives";

const DOES = [
  { icon: Eye, t: "Observes posture", d: "Disk encryption, firewall, antivirus state, OS support and update status, read from the operating system's own interfaces." },
  { icon: ListChecks, t: "Inventories software", d: "Installed applications and startup persistence, matched against NVD and the CISA KEV catalog with stated confidence." },
  { icon: FileCheck2, t: "Shows its evidence", d: "Every result carries its data source, collection time, confidence and required permissions." },
  { icon: ShieldCheck, t: "Says UNKNOWN plainly", d: "When a check cannot run, you see UNKNOWN, UNSUPPORTED or PERMISSION DENIED. Never a quiet pass." },
];
const DOESNT = [
  { icon: Ban, t: "Not spyware", d: "No keystrokes, screenshots, browsing history, file contents, messages or location." },
  { icon: Terminal, t: "Not remote administration", d: "No shell, no script execution, no file transfer. Only six fixed, audited collectors exist." },
  { icon: Wrench, t: "Never changes a device", d: "Remediation is guidance for a person to perform. Acknowledging a finding only updates the dashboard." },
  { icon: UserCheck, t: "Consent-based", d: "Each enrollment uses a one-time code and shows the device user exactly what will be collected." },
];

export default function Landing() {
  const { isLoaded, isSignedIn } = useAuth();
  const t = useT();
  usePageMeta(t("landing.title"), t("landing.description"));
  if (isLoaded && isSignedIn) return <Redirect to="/dashboard" />;

  return (
    <div className="relative min-h-[100dvh] overflow-hidden">
      <div className="grid-bg pointer-events-none absolute inset-x-0 top-0 h-[760px] [mask-image:linear-gradient(to_bottom,black,transparent)]" />
      <header className="relative mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <Logo />
        <div className="flex items-center gap-2">
          <Link href="/sign-in" data-testid="link-sign-in" className="rounded-lg px-3.5 py-2 text-sm text-muted-foreground transition-colors hover:text-foreground">
            {t("landing.signIn")}
          </Link>
          <Link href="/sign-up" data-testid="link-sign-up" className="rounded-lg border border-border bg-secondary px-3.5 py-2 text-sm font-medium transition-colors hover:bg-accent">
            {t("landing.getStarted")}
          </Link>
        </div>
      </header>

      <section className="relative mx-auto grid max-w-6xl gap-12 px-6 pb-20 pt-14 lg:grid-cols-[1.1fr_1fr] lg:pt-20">
        <div className="rise">
          <div className="eyebrow">Endpoint security assessment · Windows & macOS</div>
          <h1 className="mt-5 text-[44px] font-semibold leading-[1.02] tracking-[-0.035em] md:text-[60px]">
            Visibility.
            <br />
            Detection.
            <br />
            <span className="bg-gradient-to-r from-violet to-cyan bg-clip-text text-transparent">Confidence.</span>
          </h1>
          <p className="mt-6 max-w-lg text-[15px] leading-relaxed text-muted-foreground">
            A read-only security desk for the person who looks after a company's computers without being a full-time analyst. Every number traces back to
            evidence from an authenticated agent, and anything the system cannot see is labelled UNKNOWN.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="/sign-up" data-testid="link-hero-start" className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground transition hover:brightness-110">
              Create account <ArrowRight className="size-4" />
            </Link>
            <Link href="/sign-in" data-testid="link-hero-sign-in" className="inline-flex items-center gap-2 rounded-lg border border-border px-5 py-2.5 text-sm transition-colors hover:bg-white/[0.04]">
              Sign in
            </Link>
          </div>
        </div>

        <div className="rise rise-2 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="eyebrow">Example evidence record</div>
              <div className="mt-1 font-mono text-sm text-foreground">WIN_DEFENDER_REALTIME</div>
            </div>
            <Pill tone="ok">PASS</Pill>
          </div>
          <dl className="mt-4 space-y-0 text-xs">
            {[
              ["Evidence", "RealTimeProtectionEnabled = True"],
              ["Data source", "Get-MpComputerStatus"],
              ["Collected", "14 May 2025, 09:42"],
              ["Confidence", "HIGH"],
              ["Permissions", "Standard user"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between border-b hairline py-2 last:border-0">
                <dt className="text-muted-foreground">{k}</dt>
                <dd className="font-mono text-foreground">{v}</dd>
              </div>
            ))}
          </dl>
          <div className="mt-4 rounded-xl border border-dashed border-unknown/40 bg-white/[0.02] p-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs text-foreground">MAC_FILEVAULT_STATUS</span>
              <Pill tone="neutral">PERMISSION DENIED</Pill>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">fdesetup requires administrator rights. Reported as not observed, not as passing.</p>
          </div>
          <p className="mt-4 text-[11px] text-muted-foreground">Illustration of the record format. Not data from a real device.</p>
        </div>
      </section>

      <section className="relative mx-auto max-w-6xl px-6 pb-20">
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="glass rounded-2xl p-6">
            <div className="flex items-center gap-2">
              <span className="size-2 rounded-full bg-ok" />
              <h2 className="text-lg font-semibold tracking-tight">What it does</h2>
            </div>
            <ul className="mt-5 space-y-5">
              {DOES.map((x) => (
                <li key={x.t} className="flex gap-3.5">
                  <x.icon className="mt-0.5 size-4 shrink-0 text-cyan" />
                  <div>
                    <div className="text-sm font-medium">{x.t}</div>
                    <div className="mt-0.5 text-[13px] leading-relaxed text-muted-foreground">{x.d}</div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
          <div className="glass rounded-2xl border-crit/20 p-6">
            <div className="flex items-center gap-2">
              <span className="size-2 rounded-full bg-crit" />
              <h2 className="text-lg font-semibold tracking-tight">What it does not do</h2>
            </div>
            <ul className="mt-5 space-y-5">
              {DOESNT.map((x) => (
                <li key={x.t} className="flex gap-3.5">
                  <x.icon className="mt-0.5 size-4 shrink-0 text-crit/90" />
                  <div>
                    <div className="text-sm font-medium">{x.t}</div>
                    <div className="mt-0.5 text-[13px] leading-relaxed text-muted-foreground">{x.d}</div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section className="relative mx-auto max-w-6xl px-6 pb-20">
        <div className="eyebrow">How it works</div>
        <h2 className="mt-2 text-2xl font-semibold tracking-tight">Three steps, each one visible to the device user.</h2>
        <ol className="mt-8 grid gap-px overflow-hidden rounded-2xl border hairline bg-border/40 md:grid-cols-[1.2fr_1fr_1fr]">
          {[
            { n: "01", icon: KeyRound, t: "Enroll with a one-time code", d: "An admin generates a short-lived code. The agent shows the collection disclosure before it registers." },
            { n: "02", icon: MonitorSmartphone, t: "Agent reports on a schedule", d: "Authenticated heartbeats and assessments from fixed collectors. No inbound connections." },
            { n: "03", icon: FileCheck2, t: "You review evidence", d: "Findings, CVE matches and coverage, exportable as PDF or CSV." },
          ].map((s) => (
            <li key={s.n} className="bg-card p-6">
              <div className="flex items-center justify-between">
                <s.icon className="size-5 text-violet" />
                <span className="font-mono text-xs text-muted-foreground">{s.n}</span>
              </div>
              <div className="mt-5 text-sm font-medium">{s.t}</div>
              <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">{s.d}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="relative mx-auto max-w-6xl px-6 pb-24">
        <div className="glass grid gap-8 rounded-2xl p-7 md:grid-cols-[1fr_1.4fr]">
          <div>
            <div className="eyebrow">The honesty model</div>
            <h2 className="mt-2 text-2xl font-semibold tracking-tight">Not seeing a problem is different from there being none.</h2>
            <p className="mt-3 text-sm text-muted-foreground">
              A clean result reads "No high-severity findings observed", followed by the coverage behind it. A low risk score is never presented as proof of a clean
              device.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3">
            {(
              [
                ["PASS", "ok", "Observed and compliant"],
                ["FAIL", "crit", "Observed, not compliant"],
                ["WARNING", "warn", "Observed, needs attention"],
                ["STALE", "warn", "Evidence is out of date"],
                ["UNKNOWN", "neutral", "Could not determine"],
                ["UNSUPPORTED", "neutral", "Not available on this OS"],
              ] as const
            ).map(([s, tone, d]) => (
              <div key={s} className="rounded-xl border hairline bg-background/50 p-3">
                <Pill tone={tone}>{s}</Pill>
                <div className="mt-2 text-xs text-muted-foreground">{d}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer className="relative border-t hairline">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-6 py-6 text-xs text-muted-foreground md:flex-row md:justify-between">
          <span>NextAura Security Center · {t("brand.tagline")}</span>
          <span>Read-only · Consent-based · Evidence-first</span>
        </div>
      </footer>
    </div>
  );
}
