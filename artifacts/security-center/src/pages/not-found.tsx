import { Link } from "wouter";
import { Compass } from "lucide-react";
import { useT } from "@/i18n";
import { usePageMeta } from "@/lib/session";
import { LogoMark } from "@/components/app/logo";

export default function NotFound() {
  const t = useT();
  usePageMeta(t("notFound.title"), t("notFound.body"));
  return (
    <div className="relative grid min-h-[100dvh] place-items-center px-4">
      <div className="grid-bg pointer-events-none absolute inset-0 [mask-image:radial-gradient(closest-side,black,transparent)]" />
      <div className="relative max-w-md text-center">
        <LogoMark className="mx-auto size-10" />
        <div className="eyebrow mt-6">Status 404 · Unknown route</div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">{t("notFound.title")}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{t("notFound.body")}</p>
        <Link
          href="/dashboard"
          data-testid="link-not-found-home"
          className="mt-6 inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition hover:brightness-110"
        >
          <Compass className="size-4" /> {t("notFound.back")}
        </Link>
      </div>
    </div>
  );
}
