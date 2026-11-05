import { useState, type ReactNode } from "react";
import { Link, Redirect, useLocation } from "wouter";
import { useAuth, useClerk } from "@clerk/react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Building2,
  ChevronsUpDown,
  FileText,
  Gauge,
  LogOut,
  Mail,
  Menu,
  Monitor,
  Plus,
  Settings,
  ShieldAlert,
  Bug,
  Check,
  Eye,
  Siren,
  Radar,
} from "lucide-react";
import {
  useGetMe,
  useSelectOrganization,
  type Me,
} from "@workspace/api-client-react";
import { MeContext, canAdmin } from "@/lib/session";
import { useT, type TKey } from "@/i18n";
import { cn } from "@/lib/utils";
import { ErrorState, SkeletonBlock } from "./primitives";
import { Logo } from "./logo";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";

const basePath = import.meta.env.BASE_URL.replace(/\/$/, "");
const APP_PREFIXES = [
  "/dashboard",
  "/devices",
  "/findings",
  "/incidents",
  "/scan-center",
  "/vulnerabilities",
  "/reports",
  "/email-security",
  "/settings",
  "/onboarding",
];

export function AppShell({ children }: { children: ReactNode }) {
  const [loc] = useLocation();
  const isApp = APP_PREFIXES.some((p) => loc === p || loc.startsWith(p + "/"));
  if (!isApp) return <>{children}</>;
  return <AuthGate onboarding={loc === "/onboarding"}>{children}</AuthGate>;
}

function AuthGate({
  children,
  onboarding,
}: {
  children: ReactNode;
  onboarding: boolean;
}) {
  const { isLoaded, isSignedIn } = useAuth();
  if (!isLoaded) return <ShellSkeleton />;
  if (!isSignedIn) return <Redirect to="/" />;
  return <MeGate onboarding={onboarding}>{children}</MeGate>;
}

function MeGate({
  children,
  onboarding,
}: {
  children: ReactNode;
  onboarding: boolean;
}) {
  const me = useGetMe();
  if (me.isLoading) return <ShellSkeleton />;
  if (me.isError || !me.data)
    return (
      <div className="grid min-h-[100dvh] place-items-center px-4">
        <div className="w-full max-w-md">
          <ErrorState
            error={me.error}
            onRetry={() => void me.refetch()}
            title="We could not load your account."
          />
        </div>
      </div>
    );
  const data = me.data;
  if (!data.currentOrganization && !onboarding)
    return <Redirect to="/onboarding" />;
  if (data.currentOrganization && onboarding)
    return <Redirect to="/dashboard" />;
  return (
    <MeContext.Provider value={data}>
      {onboarding ? children : <Frame me={data}>{children}</Frame>}
    </MeContext.Provider>
  );
}

type NavItem = { href: string; key: TKey; icon: typeof Gauge };
const NAV: { group: TKey; items: NavItem[] }[] = [
  {
    group: "nav.groupFleet",
    items: [
      { href: "/dashboard", key: "nav.dashboard", icon: Gauge },
      { href: "/devices", key: "nav.devices", icon: Monitor },
      { href: "/scan-center", key: "nav.scanCenter", icon: Radar },
      { href: "/findings", key: "nav.findings", icon: ShieldAlert },
      { href: "/incidents", key: "nav.incidents", icon: Siren },
    ],
  },
  {
    group: "nav.groupIntel",
    items: [
      { href: "/vulnerabilities", key: "nav.vulnerabilities", icon: Bug },
      { href: "/email-security", key: "nav.email", icon: Mail },
      { href: "/reports", key: "nav.reports", icon: FileText },
    ],
  },
  {
    group: "nav.groupAdmin",
    items: [{ href: "/settings", key: "nav.settings", icon: Settings }],
  },
];

function Frame({ me, children }: { me: Me; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const t = useT();
  return (
    <div className="min-h-[100dvh]">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[248px] border-r border-sidebar-border bg-sidebar lg:block">
        <SidebarBody me={me} />
      </aside>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent
          side="left"
          className="w-[264px] border-sidebar-border bg-sidebar p-0"
        >
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SidebarBody me={me} onNavigate={() => setOpen(false)} />
        </SheetContent>
      </Sheet>
      <div className="lg:pl-[248px]">
        {me.demoMode && (
          <div
            className="sticky top-0 z-20 flex items-center gap-3 border-b border-warn/30 bg-[#2a1f0b]/95 px-5 py-2 text-xs backdrop-blur"
            data-testid="banner-demo"
          >
            <span className="rounded border border-warn/50 bg-warn/15 px-1.5 py-0.5 font-mono text-[10.5px] font-semibold tracking-[0.18em] text-warn">
              {t("shell.demoBanner")}
            </span>
            <span className="text-amber-100/85">{t("shell.demoBody")}</span>
          </div>
        )}
        <div className="flex items-center gap-3 border-b hairline px-4 py-3 lg:hidden">
          <button
            onClick={() => setOpen(true)}
            className="rounded-lg border border-border p-2"
            data-testid="button-open-nav"
            aria-label="Open navigation"
          >
            <Menu className="size-4" />
          </button>
          <Logo compact />
        </div>
        <main className="mx-auto w-full max-w-[1400px] px-4 py-7 md:px-8 md:py-9">
          {children}
        </main>
      </div>
    </div>
  );
}

function SidebarBody({ me, onNavigate }: { me: Me; onNavigate?: () => void }) {
  const [loc] = useLocation();
  const t = useT();
  const role = me.currentOrganization?.role ?? "VIEWER";
  return (
    <div className="flex h-full flex-col">
      <div className="px-5 pb-4 pt-5">
        <Logo />
      </div>
      <div className="px-3">
        <OrgSwitcher me={me} />
      </div>
      <nav className="mt-5 flex-1 space-y-5 overflow-y-auto px-3 scroll-thin">
        {NAV.map((g) => (
          <div key={g.group}>
            <div className="eyebrow px-2.5 pb-1.5 !text-[9.5px]">
              {t(g.group)}
            </div>
            <div className="space-y-0.5">
              {g.items.map((it) => {
                const active =
                  loc === it.href ||
                  (loc.startsWith(it.href + "/") &&
                    !(it.href === "/devices" && loc === "/devices/enroll"));
                return (
                  <Link
                    key={it.href}
                    href={it.href}
                    onClick={onNavigate}
                    data-testid={`link-nav-${it.href.slice(1)}`}
                    className={cn(
                      "group relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] transition-colors",
                      active
                        ? "bg-sidebar-accent text-foreground"
                        : "text-sidebar-foreground/75 hover:bg-white/[0.03] hover:text-foreground",
                    )}
                  >
                    {active && (
                      <span className="absolute left-0 top-2 bottom-2 w-[2px] rounded-full bg-violet" />
                    )}
                    <it.icon
                      className={cn(
                        "size-4",
                        active
                          ? "text-violet"
                          : "text-muted-foreground group-hover:text-foreground",
                      )}
                    />
                    {t(it.key)}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
        {canAdmin(role) && (
          <Link
            href="/devices/enroll"
            onClick={onNavigate}
            data-testid="link-nav-enroll"
            className="flex items-center gap-2 rounded-lg border border-violet/30 bg-violet/10 px-2.5 py-2 text-[13px] font-medium text-foreground transition-colors hover:bg-violet/20"
          >
            <Plus className="size-4 text-violet" /> {t("nav.enroll")}
          </Link>
        )}
      </nav>
      <div className="mx-3 mb-3 mt-4 flex gap-2 rounded-lg border hairline bg-white/[0.02] p-2.5 text-[11px] leading-snug text-muted-foreground">
        <Eye className="mt-0.5 size-3.5 shrink-0 text-cyan" />
        {t("shell.readOnly")}
      </div>
      <div className="border-t border-sidebar-border p-3">
        <UserMenu me={me} />
      </div>
    </div>
  );
}

function OrgSwitcher({ me }: { me: Me }) {
  const qc = useQueryClient();
  const t = useT();
  const [, setLocation] = useLocation();
  const select = useSelectOrganization({
    mutation: {
      onSuccess: () => {
        void qc.invalidateQueries();
        setLocation("/dashboard");
      },
    },
  });
  const cur = me.currentOrganization;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        data-testid="button-org-switcher"
        className="flex w-full items-center gap-2.5 rounded-xl border border-sidebar-border bg-white/[0.02] px-2.5 py-2 text-left transition-colors hover:bg-white/[0.04]"
      >
        <span className="grid size-7 shrink-0 place-items-center rounded-lg bg-gradient-to-br from-violet/40 to-cyan/30 text-[11px] font-semibold text-foreground">
          {(cur?.name ?? "?").slice(0, 2).toUpperCase()}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13px] font-medium text-foreground">
            {cur?.name}
          </span>
          <span className="block font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            {cur ? t(`shell.role.${cur.role}` as TKey) : ""}
          </span>
        </span>
        <ChevronsUpDown className="size-3.5 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-[230px]">
        <DropdownMenuLabel className="eyebrow">
          {t("shell.switchOrg")}
        </DropdownMenuLabel>
        {me.organizations.map((o) => (
          <DropdownMenuItem
            key={o.id}
            data-testid={`item-org-${o.id}`}
            disabled={select.isPending}
            onSelect={() =>
              o.id !== cur?.id &&
              select.mutate({ data: { organizationId: o.id } })
            }
            className="gap-2"
          >
            <Building2 className="size-3.5 text-muted-foreground" />
            <span className="flex-1 truncate">{o.name}</span>
            {o.id === cur?.id && <Check className="size-3.5 text-violet" />}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function UserMenu({ me }: { me: Me }) {
  const { signOut } = useClerk();
  const t = useT();
  const initials = (me.name || me.email)
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase())
    .join("");
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        data-testid="button-user-menu"
        className="flex w-full items-center gap-2.5 rounded-lg px-1.5 py-1.5 text-left transition-colors hover:bg-white/[0.04]"
      >
        <span className="grid size-8 place-items-center rounded-full border border-border bg-secondary text-[11px] font-semibold">
          {initials}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13px] text-foreground">
            {me.name || me.email}
          </span>
          <span className="block truncate text-[11px] text-muted-foreground">
            {me.email}
          </span>
        </span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" side="top" className="w-[220px]">
        <DropdownMenuItem asChild>
          <Link href="/settings" data-testid="link-user-settings">
            <Settings className="mr-2 size-3.5" /> {t("nav.settings")}
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          data-testid="button-sign-out"
          onSelect={() => void signOut({ redirectUrl: basePath || "/" })}
        >
          <LogOut className="mr-2 size-3.5" /> {t("shell.signOut")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function ShellSkeleton() {
  return (
    <div className="min-h-[100dvh]" data-testid="state-shell-loading">
      <aside className="fixed inset-y-0 left-0 hidden w-[248px] border-r border-sidebar-border bg-sidebar p-5 lg:block">
        <SkeletonBlock className="h-7 w-32" />
        <SkeletonBlock className="mt-6 h-11 w-full" />
        <div className="mt-6 space-y-2">
          {Array.from({ length: 7 }).map((_, i) => (
            <SkeletonBlock key={i} className="h-8 w-full rounded-lg" />
          ))}
        </div>
      </aside>
      <div className="px-8 py-9 lg:pl-[280px]">
        <SkeletonBlock className="h-8 w-64" />
        <SkeletonBlock className="mt-3 h-4 w-96" />
        <div className="mt-8 grid grid-cols-2 gap-4 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonBlock key={i} className="h-28" />
          ))}
        </div>
        <SkeletonBlock className="mt-4 h-80" />
      </div>
    </div>
  );
}
