import { cn } from "@/lib/utils";

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" fill="none" className={cn("size-8", className)} aria-hidden>
      <defs>
        <linearGradient id="nx-g" x1="8" y1="6" x2="56" y2="58" gradientUnits="userSpaceOnUse">
          <stop stopColor="#7568E8" />
          <stop offset="1" stopColor="#38BDF8" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="16" fill="#161B30" />
      <path d="M32 9 L51 16 V31 C51 43 43 51.5 32 55 C21 51.5 13 43 13 31 V16 Z" stroke="url(#nx-g)" strokeWidth="3" strokeLinejoin="round" />
      <path d="M24 39 V25 L40 39 V25" stroke="#F8FAFC" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Logo({ compact }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <LogoMark />
      <div className="leading-none">
        <div className="text-[14px] font-semibold tracking-tight text-foreground">NextAura</div>
        {!compact && <div className="mt-1 font-mono text-[9.5px] uppercase tracking-[0.2em] text-muted-foreground">Security Center</div>}
      </div>
    </div>
  );
}
