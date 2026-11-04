import { useState } from "react";
import { Link } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { UserProfile } from "@clerk/react";
import { Loader2, ShieldCheck, Trash2, UserPlus } from "lucide-react";
import {
  OsType,
  Role,
  getGetMeQueryKey,
  getGetOrganizationSettingsQueryKey,
  getListMembersQueryKey,
  useAddMember,
  useGetOrganizationSettings,
  useListAuditLogs,
  useListMembers,
  useListRules,
  useRemoveMember,
  useRequestDataDeletion,
  useUpdateMember,
  useUpdateOrganizationSettings,
  type OrganizationSettings,
  type OrganizationSettingsUpdate,
} from "@workspace/api-client-react";
import { useT } from "@/i18n";
import { canAdmin, isOwner, useMe, usePageMeta, useRole } from "@/lib/session";
import { errMsg, fmtDate, fmtRel } from "@/lib/format";
import { useToast } from "@/hooks/use-toast";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
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
import { Caveat, EmptyState, ErrorState, KV, PageHeader, Panel, Pill, SeverityPill, SkeletonBlock, SkeletonRows } from "@/components/app/primitives";


const inputCls = "h-9 w-full rounded-lg border border-input bg-card px-3 text-[13px] outline-none focus:border-violet disabled:opacity-60";

export default function SettingsPage() {
  const t = useT();
  usePageMeta(t("settings.title"), t("settings.description"));
  const settings = useGetOrganizationSettings();
  const tabs = [
    ["org", "Organization"],
    ["team", "Team"],
    ["security", "Security"],
    ["privacy", "Privacy & data"],
    ["enrollment", "Enrollment policy"],
    ["audit", "Audit history"],
    ["rules", "Rules catalog"],
  ];
  return (
    <div>
      <PageHeader eyebrow="Administration" title={t("settings.title")} description={t("settings.description")} />
      <Tabs defaultValue="org">
        <div className="overflow-x-auto scroll-thin">
          <TabsList className="h-auto gap-1 rounded-xl border hairline bg-sidebar p-1">
            {tabs.map(([v, l]) => (
              <TabsTrigger key={v} value={v} data-testid={`tab-${v}`} className="rounded-lg px-3 py-1.5 text-[12.5px] data-[state=active]:bg-card data-[state=active]:text-foreground">{l}</TabsTrigger>
            ))}
          </TabsList>
        </div>
        {settings.isLoading ? (
          <SkeletonBlock className="mt-5 h-96" />
        ) : settings.isError || !settings.data ? (
          <div className="mt-5"><ErrorState error={settings.error} onRetry={() => void settings.refetch()} /></div>
        ) : (
          <>
            <TabsContent value="org" className="mt-5"><OrgTab s={settings.data} key={settings.data.id + settings.dataUpdatedAt} /></TabsContent>
            <TabsContent value="team" className="mt-5"><TeamTab /></TabsContent>
            <TabsContent value="security" className="mt-5"><SecurityTab s={settings.data} /></TabsContent>
            <TabsContent value="privacy" className="mt-5"><PrivacyTab s={settings.data} /></TabsContent>
            <TabsContent value="enrollment" className="mt-5"><EnrollmentTab s={settings.data} key={settings.data.id + settings.dataUpdatedAt} /></TabsContent>
            <TabsContent value="audit" className="mt-5"><AuditTab /></TabsContent>
            <TabsContent value="rules" className="mt-5"><RulesTab /></TabsContent>
          </>
        )}
      </Tabs>
    </div>
  );
}

function useSave() {
  const qc = useQueryClient();
  const { toast } = useToast();
  return useUpdateOrganizationSettings({
    mutation: {
      onSuccess: (d) => {
        qc.setQueryData(getGetOrganizationSettingsQueryKey(), d);
        void qc.invalidateQueries({ queryKey: getGetMeQueryKey() });
        toast({ title: "Settings saved" });
      },
      onError: (e) => toast({ title: "Settings not saved", description: errMsg(e), variant: "destructive" }),
    },
  });
}

function NumField({ label, value, onChange, min, max, unit, disabled, id }: { label: string; value: number; onChange: (n: number) => void; min: number; max: number; unit: string; disabled?: boolean; id: string }) {
  const bad = value < min || value > max || !Number.isFinite(value);
  return (
    <label className="block">
      <span className="text-xs text-muted-foreground">{label}</span>
      <div className="mt-1.5 flex items-center gap-2">
        <input id={id} data-testid={`input-${id}`} type="number" min={min} max={max} value={value} disabled={disabled} onChange={(e) => onChange(Number(e.target.value))} className={inputCls + (bad ? " border-crit" : "")} />
        <span className="w-14 shrink-0 text-xs text-muted-foreground">{unit}</span>
      </div>
      <span className="mt-1 block font-mono text-[10.5px] text-muted-foreground">{min}–{max}</span>
    </label>
  );
}

function OrgTab({ s }: { s: OrganizationSettings }) {
  const role = useRole();
  const editable = canAdmin(role);
  const save = useSave();
  const [f, setF] = useState({
    name: s.name,
    retentionDays: s.retentionDays,
    heartbeatIntervalMinutes: s.heartbeatIntervalMinutes,
    postureIntervalHours: s.postureIntervalHours,
    inventoryIntervalHours: s.inventoryIntervalHours,
    onlineThresholdMinutes: s.onlineThresholdMinutes,
    allowedOsTypes: s.allowedOsTypes,
    requireMfa: s.requireMfa,
  });
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF((p) => ({ ...p, [k]: v }));
  const valid =
    f.name.trim().length >= 2 && f.name.length <= 120 &&
    f.retentionDays >= 7 && f.retentionDays <= 730 &&
    f.heartbeatIntervalMinutes >= 1 && f.heartbeatIntervalMinutes <= 60 &&
    f.postureIntervalHours >= 1 && f.postureIntervalHours <= 72 &&
    f.inventoryIntervalHours >= 6 && f.inventoryIntervalHours <= 168 &&
    f.onlineThresholdMinutes >= 2 && f.onlineThresholdMinutes <= 180 &&
    f.allowedOsTypes.length > 0;
  return (
    <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
      <Panel title="Organization" subtitle={editable ? "Owners and Admins can edit these settings." : "Read-only for your role."}>
        <div className="space-y-5">
          <label className="block">
            <span className="text-xs text-muted-foreground">Name</span>
            <input data-testid="input-org-name" value={f.name} disabled={!editable} maxLength={120} onChange={(e) => set("name", e.target.value)} className={inputCls + " mt-1.5"} />
          </label>
          <div className="grid gap-4 sm:grid-cols-2">
            <NumField id="retention" label="Evidence retention" value={f.retentionDays} onChange={(n) => set("retentionDays", n)} min={7} max={730} unit="days" disabled={!editable} />
            <NumField id="heartbeat" label="Heartbeat interval" value={f.heartbeatIntervalMinutes} onChange={(n) => set("heartbeatIntervalMinutes", n)} min={1} max={60} unit="min" disabled={!editable} />
            <NumField id="posture" label="Posture assessment interval" value={f.postureIntervalHours} onChange={(n) => set("postureIntervalHours", n)} min={1} max={72} unit="hours" disabled={!editable} />
            <NumField id="inventory" label="Inventory interval" value={f.inventoryIntervalHours} onChange={(n) => set("inventoryIntervalHours", n)} min={6} max={168} unit="hours" disabled={!editable} />
            <NumField id="online" label="Online threshold" value={f.onlineThresholdMinutes} onChange={(n) => set("onlineThresholdMinutes", n)} min={2} max={180} unit="min" disabled={!editable} />
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Allowed operating systems</span>
            <div className="mt-2 flex gap-2">
              {Object.values(OsType).map((o) => {
                const on = f.allowedOsTypes.includes(o);
                return (
                  <button key={o} type="button" disabled={!editable} data-testid={`toggle-os-${o}`} onClick={() => set("allowedOsTypes", on ? f.allowedOsTypes.filter((x) => x !== o) : [...f.allowedOsTypes, o])} className={"rounded-lg border px-3 py-1.5 font-mono text-xs transition-colors " + (on ? "border-violet bg-violet/15" : "border-border text-muted-foreground")}>
                    {o}
                  </button>
                );
              })}
            </div>
          </div>
          <label className="flex items-center justify-between gap-4 rounded-xl border hairline p-3.5">
            <span>
              <span className="block text-[13px] font-medium">Require MFA (policy flag)</span>
              <span className="block text-xs text-muted-foreground">Displayed to administrators. MFA itself is enforced by the identity provider.</span>
            </span>
            <Switch checked={f.requireMfa} disabled={!editable} onCheckedChange={(v) => set("requireMfa", v)} data-testid="switch-require-mfa" />
          </label>
          {editable && (
            <button data-testid="button-save-org" disabled={!valid || save.isPending} onClick={() => save.mutate({ data: { ...f, name: f.name.trim() } satisfies OrganizationSettingsUpdate })} className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50">
              {save.isPending && <Loader2 className="size-4 animate-spin" />} Save changes
            </button>
          )}
        </div>
      </Panel>
      <Panel title="Details">
        <dl>
          <KV label="Slug" mono>{s.slug}</KV>
          <KV label="Created">{fmtDate(s.createdAt)}</KV>
          <KV label="Minimum agent version" mono>{s.minimumAgentVersion}</KV>
          <KV label="Demo organization">{s.demoMode ? <Pill tone="warn">Demo data</Pill> : "No"}</KV>
        </dl>
      </Panel>
    </div>
  );
}

function TeamTab() {
  const role = useRole();
  const me = useMe();
  const qc = useQueryClient();
  const { toast } = useToast();
  const q = useListMembers();
  const [email, setEmail] = useState("");
  const [newRole, setNewRole] = useState<Role>("VIEWER");
  const [removing, setRemoving] = useState<{ id: string; email: string } | null>(null);
  const inv = () => void qc.invalidateQueries({ queryKey: getListMembersQueryKey() });
  const add = useAddMember({ mutation: { onSuccess: () => { inv(); setEmail(""); toast({ title: "Member authorized", description: "They can join after signing in with this email." }); }, onError: (e) => toast({ title: "Could not add", description: errMsg(e), variant: "destructive" }) } });
  const upd = useUpdateMember({ mutation: { onSuccess: () => { inv(); toast({ title: "Role updated" }); }, onError: (e) => toast({ title: "Could not update", description: errMsg(e), variant: "destructive" }) } });
  const rem = useRemoveMember({ mutation: { onSuccess: () => { inv(); setRemoving(null); toast({ title: "Member removed" }); }, onError: (e) => toast({ title: "Could not remove", description: errMsg(e), variant: "destructive" }) } });
  const admin = canAdmin(role);
  const roles = Object.values(Role).filter((r) => r !== "OWNER" || isOwner(role));

  return (
    <div className="space-y-5">
      {admin && (
        <Panel title="Authorize a teammate" subtitle={`They sign up with this email, then appear in ${me.currentOrganization?.name}.`}>
          <form className="flex flex-col gap-2 md:flex-row" onSubmit={(e) => { e.preventDefault(); if (email.includes("@")) add.mutate({ data: { email: email.trim(), role: newRole } }); }}>
            <input data-testid="input-member-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="colleague@company.com" className={inputCls + " flex-1"} />
            <select data-testid="select-member-role" value={newRole} onChange={(e) => setNewRole(e.target.value as Role)} className="h-9 rounded-lg border border-input bg-card px-2.5 text-[13px]">
              {roles.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
            </select>
            <button data-testid="button-add-member" disabled={add.isPending || !email.includes("@")} className="inline-flex h-9 items-center gap-2 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground disabled:opacity-50">
              <UserPlus className="size-4" /> Authorize
            </button>
          </form>
          <div className="mt-3 grid gap-2 text-[11px] text-muted-foreground sm:grid-cols-4">
            <span><b className="text-foreground">Owner</b> · everything incl. data deletion</span>
            <span><b className="text-foreground">Admin</b> · enroll, revoke, settings</span>
            <span><b className="text-foreground">Analyst</b> · finding status, assessments</span>
            <span><b className="text-foreground">Viewer</b> · read-only</span>
          </div>
        </Panel>
      )}
      <Panel title="Members" bodyClassName="p-0">
        {q.isLoading ? <div className="p-5"><SkeletonRows rows={4} cols={4} /></div> : q.isError ? <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div> : (
          <ul className="divide-y hairline">
            {q.data?.map((m) => (
              <li key={m.id} className="flex flex-wrap items-center gap-3 px-5 py-3" data-testid={`row-member-${m.id}`}>
                <span className="grid size-8 place-items-center rounded-full border border-border bg-secondary text-[11px] font-semibold">{(m.name || m.email).slice(0, 2).toUpperCase()}</span>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium">{m.name ?? m.email} {m.isCurrentUser && <span className="text-xs text-muted-foreground">(you)</span>}</div>
                  <div className="text-xs text-muted-foreground">{m.email} · {m.userId ? `last sign-in ${fmtRel(m.lastSignInAt)}` : "invited, not yet signed in"}</div>
                </div>
                {admin && !m.isCurrentUser && (m.role !== "OWNER" || isOwner(role)) ? (
                  <>
                    <select value={m.role} data-testid={`select-role-${m.id}`} onChange={(e) => upd.mutate({ id: m.id, data: { role: e.target.value as Role } })} className="h-8 rounded-lg border border-input bg-card px-2 text-xs">
                      {roles.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
                    </select>
                    <button data-testid={`button-remove-${m.id}`} onClick={() => setRemoving({ id: m.id, email: m.email })} className="rounded-lg p-2 text-muted-foreground hover:bg-crit/10 hover:text-crit" aria-label="Remove member">
                      <Trash2 className="size-3.5" />
                    </button>
                  </>
                ) : (
                  <Pill tone="violet" dot={false}>{m.role.replace(/_/g, " ")}</Pill>
                )}
              </li>
            ))}
          </ul>
        )}
      </Panel>
      <AlertDialog open={!!removing} onOpenChange={(o) => !o && setRemoving(null)}>
        <AlertDialogContent className="border-border bg-[#11152a]">
          <AlertDialogHeader>
            <AlertDialogTitle>Remove {removing?.email}?</AlertDialogTitle>
            <AlertDialogDescription>They lose access to this organization immediately. Their identity account is not deleted.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction data-testid="button-confirm-remove" className="bg-destructive text-destructive-foreground" onClick={(e) => { e.preventDefault(); if (removing) rem.mutate({ id: removing.id }); }}>Remove</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function SecurityTab({ s }: { s: OrganizationSettings }) {
  const [open, setOpen] = useState(false);
  return (
    <Panel title="Multi-factor authentication">
      <div className="flex flex-col gap-5 md:flex-row md:items-start">
        <ShieldCheck className="size-8 shrink-0 text-violet" />
        <div className="flex-1 space-y-3">
          <p className="text-[13px] text-slate-300">
            MFA is handled by the identity provider, not by this console. Organization policy: {s.requireMfa ? <Pill tone="ok">MFA required</Pill> : <Pill tone="neutral">MFA not required</Pill>}
          </p>
          <p className="text-xs text-muted-foreground">Set up an authenticator app or backup codes from your account's security settings.</p>
          <button data-testid="button-open-account-security" onClick={() => setOpen(true)} className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground">Open account security</button>
        </div>
      </div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[90dvh] max-w-[920px] overflow-auto border-border bg-[#11152a] p-2">
          <DialogTitle className="sr-only">Account security</DialogTitle>
          <UserProfile routing="hash" appearance={{ elements: { rootBox: "w-full", cardBox: "w-full max-w-full bg-[#161B30] shadow-none border-0" } }} />
        </DialogContent>
      </Dialog>
    </Panel>
  );
}

function PrivacyTab({ s }: { s: OrganizationSettings }) {
  const role = useRole();
  const qc = useQueryClient();
  const { toast } = useToast();
  const [confirm, setConfirm] = useState("");
  const del = useRequestDataDeletion({
    mutation: {
      onSuccess: (r) => {
        void qc.invalidateQueries();
        setConfirm("");
        toast({ title: "Data deleted", description: `${r.deletedDevices} devices, ${r.deletedAssessments} assessments, ${r.deletedFindings} findings removed at ${fmtDate(r.completedAt)}.` });
      },
      onError: (e) => toast({ title: "Deletion failed", description: errMsg(e), variant: "destructive" }),
    },
  });
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Panel title="Retention">
        <p className="text-[13px] text-slate-300">Evidence older than <span className="font-mono text-foreground">{s.retentionDays} days</span> is removed automatically. Change this under Organization.</p>
        <Caveat className="mt-4">Collected data is limited to the six documented collectors. No file contents, browsing history, keystrokes or screenshots are ever collected.</Caveat>
      </Panel>
      <Panel title="Delete organization data" className="border-crit/25">
        {isOwner(role) ? (
          <div className="space-y-3">
            <p className="text-[13px] text-slate-300">Permanently deletes all devices, assessments and findings for this organization. This cannot be undone.</p>
            <label className="block text-xs text-muted-foreground">Type the organization slug <span className="font-mono text-foreground">{s.slug}</span> to confirm</label>
            <input data-testid="input-delete-confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} className={inputCls + " font-mono"} />
            <button data-testid="button-delete-data" disabled={confirm !== s.slug || del.isPending} onClick={() => del.mutate({ data: { confirmation: confirm } })} className="inline-flex items-center gap-2 rounded-lg bg-destructive px-4 py-2 text-sm font-medium text-destructive-foreground disabled:opacity-40">
              {del.isPending && <Loader2 className="size-4 animate-spin" />} Delete all data
            </button>
          </div>
        ) : (
          <p className="text-[13px] text-muted-foreground">Only Owners can delete organization data.</p>
        )}
      </Panel>
    </div>
  );
}

function EnrollmentTab({ s }: { s: OrganizationSettings }) {
  const role = useRole();
  const save = useSave();
  const [ttl, setTtl] = useState(s.enrollmentCodeTtlMinutes);
  const editable = canAdmin(role);
  return (
    <Panel title="Enrollment policy">
      <div className="grid gap-6 md:grid-cols-2">
        <div className="space-y-4">
          <NumField id="ttl" label="Enrollment code lifetime" value={ttl} onChange={setTtl} min={5} max={120} unit="min" disabled={!editable} />
          {editable && (
            <button data-testid="button-save-ttl" disabled={ttl < 5 || ttl > 120 || save.isPending} onClick={() => save.mutate({ data: { enrollmentCodeTtlMinutes: ttl } })} className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50">
              {save.isPending && <Loader2 className="size-4 animate-spin" />} Save
            </button>
          )}
        </div>
        <dl>
          <KV label="Allowed OS">{s.allowedOsTypes.join(", ")}</KV>
          <KV label="Minimum agent version" mono>{s.minimumAgentVersion}</KV>
          <KV label="Codes">Single-use, hashed at rest</KV>
          <KV label="Consent">Shown to the device user before registration</KV>
        </dl>
      </div>
      {editable && <Link href="/devices/enroll" className="mt-5 inline-block text-xs text-cyan hover:underline">Go to enrollment wizard</Link>}
    </Panel>
  );
}

function AuditTab() {
  const q = useListAuditLogs({ limit: 100 });
  return (
    <Panel title="Audit history" subtitle="Last 100 events" bodyClassName="p-0">
      {q.isLoading ? <div className="p-5"><SkeletonRows rows={8} cols={4} /></div> : q.isError ? <div className="p-5"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div> : !q.data?.length ? <EmptyState title="No audit events yet" /> : (
        <div className="overflow-x-auto scroll-thin">
          <table className="w-full min-w-[820px] text-[13px]">
            <thead><tr className="eyebrow border-b hairline text-left"><th className="px-5 py-2.5 font-normal">When</th><th className="px-3 py-2.5 font-normal">Action</th><th className="px-3 py-2.5 font-normal">Actor</th><th className="px-3 py-2.5 font-normal">Target</th><th className="px-5 py-2.5 font-normal">Details</th></tr></thead>
            <tbody>
              {q.data.map((a) => (
                <tr key={a.id} className="border-b hairline align-top last:border-0">
                  <td className="whitespace-nowrap px-5 py-2.5 font-mono text-[11px] text-muted-foreground">{fmtDate(a.createdAt)}</td>
                  <td className="px-3 py-2.5 font-mono text-xs">{a.action}</td>
                  <td className="px-3 py-2.5 text-xs"><Pill tone={a.actorType === "USER" ? "violet" : a.actorType === "DEVICE" ? "info" : "neutral"} dot={false}>{a.actorType}</Pill> <span className="text-muted-foreground">{a.actorEmail ?? ""}</span></td>
                  <td className="px-3 py-2.5 text-xs">{a.targetLabel ?? a.targetId ?? "—"}</td>
                  <td className="px-5 py-2.5 text-xs text-muted-foreground">{a.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function RulesTab() {
  const q = useListRules();
  return (
    <div className="space-y-3">
      <Caveat>Findings are produced only by these deterministic rules. Each requires specific evidence; a rule never fires on missing data.</Caveat>
      {q.isLoading ? <SkeletonRows rows={6} cols={3} /> : q.isError ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : (
        <div className="grid gap-3 lg:grid-cols-2">
          {q.data?.map((r) => (
            <div key={r.ruleId} className="glass rounded-2xl p-4" data-testid={`card-rule-${r.ruleId}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[11px] text-muted-foreground">{r.ruleId}</span>
                <SeverityPill s={r.severity} />
              </div>
              <div className="mt-1.5 text-[13.5px] font-medium">{r.title}</div>
              <p className="mt-1 text-xs text-muted-foreground">{r.description}</p>
              <dl className="mt-3 text-xs">
                <KV label="Trigger" mono>{r.triggerLogic}</KV>
                <KV label="Evidence required">{r.evidenceRequirement}</KV>
                <KV label="Collector" mono>{r.collectorId}</KV>
                <KV label="Platforms">{r.platforms.join(", ")}</KV>
              </dl>
              <p className="mt-2 text-xs text-slate-300"><span className="text-muted-foreground">Remediation: </span>{r.remediation}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


