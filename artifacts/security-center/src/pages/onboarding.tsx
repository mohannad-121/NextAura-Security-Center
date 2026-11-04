import { useState } from "react";
import { useLocation } from "wouter";
import { useClerk } from "@clerk/react";
import { useQueryClient } from "@tanstack/react-query";
import { Building2, Loader2, LogOut, MailCheck } from "lucide-react";
import { getGetMeQueryKey, useCreateOrganization } from "@workspace/api-client-react";
import { useMe, usePageMeta } from "@/lib/session";
import { errMsg } from "@/lib/format";
import { Logo } from "@/components/app/logo";
import { Input } from "@/components/ui/input";

const basePath = import.meta.env.BASE_URL.replace(/\/$/, "");

export default function Onboarding() {
  usePageMeta("Set up your organization", "Create an organization or wait for an owner to authorize your email.");
  const me = useMe();
  const qc = useQueryClient();
  const [, setLocation] = useLocation();
  const { signOut } = useClerk();
  const [name, setName] = useState("");
  const create = useCreateOrganization({
    mutation: {
      onSuccess: (data) => {
        qc.setQueryData(getGetMeQueryKey(), data);
        setLocation("/dashboard");
      },
    },
  });
  const valid = name.trim().length >= 2 && name.trim().length <= 120;

  return (
    <div className="relative min-h-[100dvh] px-4 py-10">
      <div className="grid-bg pointer-events-none absolute inset-0 [mask-image:radial-gradient(ellipse_at_top,black,transparent_70%)]" />
      <div className="relative mx-auto max-w-4xl">
        <div className="flex items-center justify-between">
          <Logo />
          <button
            onClick={() => void signOut({ redirectUrl: basePath || "/" })}
            data-testid="button-sign-out"
            className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <LogOut className="size-3.5" /> Sign out
          </button>
        </div>
        <div className="rise mt-14">
          <div className="eyebrow">Signed in as {me.email}</div>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">You are not part of an organization yet.</h1>
          <p className="mt-2 max-w-xl text-sm text-muted-foreground">
            Organizations hold devices, findings and reports. There is no public self-registration into an existing organization.
          </p>
        </div>
        <div className="mt-8 grid gap-5 md:grid-cols-[1.25fr_1fr]">
          <form
            className="glass rise rise-1 rounded-2xl p-6"
            onSubmit={(e) => {
              e.preventDefault();
              if (valid) create.mutate({ data: { name: name.trim() } });
            }}
          >
            <Building2 className="size-5 text-violet" />
            <h2 className="mt-4 text-base font-semibold">Create a new organization</h2>
            <p className="mt-1 text-[13px] text-muted-foreground">You become its Owner and can authorize teammates by email.</p>
            <label className="mt-5 block text-xs font-medium text-muted-foreground" htmlFor="org-name">
              Organization name
            </label>
            <Input id="org-name" data-testid="input-org-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Halvorsen Dental Group" className="mt-1.5" maxLength={120} />
            {create.isError && <p className="mt-2 text-xs text-crit">{errMsg(create.error)}</p>}
            <button
              type="submit"
              disabled={!valid || create.isPending}
              data-testid="button-create-org"
              className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition hover:brightness-110 disabled:opacity-50"
            >
              {create.isPending && <Loader2 className="size-4 animate-spin" />} Create organization
            </button>
          </form>
          <div className="glass rise rise-2 rounded-2xl p-6">
            <MailCheck className="size-5 text-cyan" />
            <h2 className="mt-4 text-base font-semibold">Joining your team's organization?</h2>
            <p className="mt-1 text-[13px] leading-relaxed text-muted-foreground">
              Ask an Owner or Admin to add <span className="font-mono text-foreground">{me.email}</span> under Settings → Team. After they do, reload this page and
              the organization will appear.
            </p>
            <button onClick={() => window.location.reload()} data-testid="button-reload" className="mt-5 rounded-lg border border-border px-3.5 py-2 text-xs hover:bg-white/[0.04]">
              I have been authorized — reload
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
