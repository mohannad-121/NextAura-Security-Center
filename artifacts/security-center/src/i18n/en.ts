export const en = {
  "brand.name": "NextAura",
  "brand.product": "Security Center",
  "brand.tagline": "Visibility. Detection. Confidence.",

  "nav.overview": "Overview",
  "nav.dashboard": "Dashboard",
  "nav.devices": "Devices",
  "nav.enroll": "Enroll device",
  "nav.findings": "Findings",
  "nav.incidents": "Incidents",
  "nav.vulnerabilities": "Vulnerabilities",
  "nav.reports": "Reports",
  "nav.email": "Email security",
  "nav.settings": "Settings",
  "nav.groupFleet": "Fleet",
  "nav.groupIntel": "Intelligence",
  "nav.groupAdmin": "Administration",

  "shell.demoBanner": "DEMO DATA",
  "shell.demoBody":
    "This organization contains illustrative records. Nothing here was collected from a real endpoint.",
  "shell.signOut": "Sign out",
  "shell.switchOrg": "Switch organization",
  "shell.readOnly":
    "Read-only observation. This console never changes an endpoint.",
  "shell.role.OWNER": "Owner",
  "shell.role.ADMIN": "Admin",
  "shell.role.SECURITY_ANALYST": "Security analyst",
  "shell.role.VIEWER": "Viewer",

  "common.retry": "Try again",
  "common.loadError": "We could not load this data.",
  "common.never": "Never",
  "common.unknown": "UNKNOWN",
  "common.cancel": "Cancel",
  "common.save": "Save changes",
  "common.close": "Close",
  "common.copy": "Copy",
  "common.copied": "Copied",
  "common.all": "All",
  "common.lowScoreCaveat": "A low score is not proof of a clean device.",

  "landing.title": "NextAura Security Center",
  "landing.description":
    "Read-only, consent-based endpoint security assessment for Windows and macOS fleets.",
  "landing.signIn": "Sign in",
  "landing.getStarted": "Create account",

  "dashboard.title": "Fleet overview",
  "dashboard.description":
    "Fleet posture, open findings and agent health across your organization.",
  "dashboard.emptyTitle": "No devices enrolled yet",
  "dashboard.emptyBody":
    "Enroll your first device to start collecting evidence. Until an authenticated agent reports, every figure on this page is zero by design, not because the fleet is clean.",
  "dashboard.noHigh": "No high-severity findings observed",
  "dashboard.coverageCaveat":
    "Findings reflect only what agents could observe. Checks returning UNKNOWN, UNSUPPORTED or PERMISSION_DENIED are not counted as passing.",

  "devices.title": "Devices",
  "devices.description":
    "Every enrolled endpoint, its heartbeat, risk and evidence coverage.",
  "devices.emptyTitle": "No devices enrolled yet",
  "devices.emptyBody":
    "Enroll your first device. The agent is installed with the device user's knowledge and reports only the fixed, documented collectors.",
  "devices.noMatch": "No devices match these filters",

  "enroll.title": "Enroll a device",
  "enroll.description":
    "A guided, consent-first enrollment for a single Windows or macOS computer.",

  "findings.title": "Findings",
  "findings.description":
    "Deterministic rule results, each traceable to collected evidence.",
  "findings.ackCaveat":
    "Changing a finding's status only updates dashboard records. It never modifies the endpoint.",
  "findings.empty": "No findings recorded",

  "vulns.title": "Vulnerabilities",
  "vulns.description":
    "Installed software matched against NVD and the CISA Known Exploited Vulnerabilities catalog.",

  "reports.title": "Reports",
  "reports.description":
    "Export device and organization evidence as PDF, or findings as CSV.",

  "email.title": "Email security",
  "email.description":
    "Audit a domain's SPF, DMARC and DKIM records from public DNS.",

  "settings.title": "Settings",
  "settings.description":
    "Organization policy, team access, privacy and audit history.",

  "onboarding.title": "Set up your organization",

  "notFound.title": "Page not found",
  "notFound.body":
    "This address does not match any page in the Security Center.",
  "notFound.back": "Return to dashboard",
} as const;

export type TKey = keyof typeof en;
