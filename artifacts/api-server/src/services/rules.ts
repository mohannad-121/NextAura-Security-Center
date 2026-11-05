/**
 * Deterministic rules engine. Every rule is transparent: trigger logic,
 * evidence requirement and remediation are documented and exposed via
 * GET /api/rules. Rules never infer "clean"; they only raise findings when
 * concrete evidence exists. UNKNOWN / UNSUPPORTED / PERMISSION_DENIED produce
 * visibility-gap findings, never PASS.
 */
import type { AgentCheck, CollectorResult } from "../routes/agent/contract";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type OsType = "WINDOWS" | "MACOS";
export type CollectorId = CollectorResult["collectorId"];

export interface RuleContext {
  osType: OsType;
  deviceName: string;
  assessmentId: string;
  collectors: CollectorResult[];
  /** Flattened checks with their collector info. */
  checks: Array<
    AgentCheck & {
      collectorId: CollectorId;
      collectorVersion: string;
      collectedAt: string;
    }
  >;
}

export interface RuleHit {
  fingerprint: string;
  title?: string;
  evidence: string;
  confidence: Confidence;
  severity?: Severity;
  collectorId: CollectorId;
  rawStatus: string;
  collectorVersion: string;
  observedAt: string;
  detectionSource: string;
}

export interface Rule {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  triggerLogic: string;
  evidenceRequirement: string;
  remediation: string;
  platforms: OsType[];
  collectorId: CollectorId;
  evaluate(ctx: RuleContext): RuleHit[];
}

type Check = RuleContext["checks"][number];

function find(ctx: RuleContext, checkId: string): Check | undefined {
  return ctx.checks.find((c) => c.checkId === checkId);
}

function hitFromCheck(
  c: Check,
  confidence: Confidence = c.confidence,
  extra?: Partial<RuleHit>,
): RuleHit {
  return {
    fingerprint: c.checkId,
    evidence: c.evidence || `${c.title}: ${c.status}`,
    confidence,
    collectorId: c.collectorId,
    rawStatus: c.status,
    collectorVersion: c.collectorVersion,
    observedAt: c.collectedAt,
    detectionSource: c.dataSource || c.collectorId,
    ...extra,
  };
}

/** Builds a "check FAILED" rule for a specific checkId. */
function failRule(opts: {
  ruleId: string;
  checkId: string;
  title: string;
  description: string;
  severity: Severity;
  remediation: string;
  platforms: OsType[];
  collectorId: CollectorId;
  includeWarning?: boolean;
}): Rule {
  return {
    ruleId: opts.ruleId,
    title: opts.title,
    description: opts.description,
    severity: opts.severity,
    triggerLogic: `Check "${opts.checkId}" reports status FAIL${opts.includeWarning ? " or WARNING" : ""}.`,
    evidenceRequirement: `The agent must have read the setting directly from the OS (status FAIL${opts.includeWarning ? "/WARNING" : ""} with evidence). UNKNOWN, UNSUPPORTED and PERMISSION_DENIED never trigger this rule.`,
    remediation: opts.remediation,
    platforms: opts.platforms,
    collectorId: opts.collectorId,
    evaluate(ctx) {
      if (!opts.platforms.includes(ctx.osType)) return [];
      const c = find(ctx, opts.checkId);
      if (!c) return [];
      if (c.status === "FAIL") return [hitFromCheck(c)];
      if (opts.includeWarning && c.status === "WARNING") {
        return [
          hitFromCheck(c, c.confidence, { severity: downgrade(opts.severity) }),
        ];
      }
      return [];
    },
  };
}

function downgrade(s: Severity): Severity {
  const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  return order[Math.min(order.indexOf(s) + 1, order.length - 1)]!;
}

export const RULES: Rule[] = [
  failRule({
    ruleId: "FIREWALL_DISABLED",
    checkId: "FIREWALL_ENABLED",
    title: "Host firewall is disabled",
    description:
      "The operating system firewall is turned off, exposing listening services to the local network.",
    severity: "HIGH",
    remediation:
      "Enable the built-in firewall (Windows Defender Firewall for all profiles, or macOS Application Firewall) and verify with a follow-up assessment.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "SECURITY_POSTURE",
    includeWarning: true,
  }),
  failRule({
    ruleId: "DISK_ENCRYPTION_OFF",
    checkId: "DISK_ENCRYPTION",
    title: "System disk is not encrypted",
    description:
      "Full-disk encryption (BitLocker / FileVault) is not active on the system volume. A lost or stolen device exposes all data.",
    severity: "HIGH",
    remediation:
      "Enable BitLocker (Windows) or FileVault (macOS) on the system volume and escrow the recovery key in a managed location.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "SECURITY_POSTURE",
    includeWarning: true,
  }),
  failRule({
    ruleId: "OS_UPDATES_PENDING",
    checkId: "OS_UPDATES",
    title: "Operating system updates are pending",
    description:
      "Security updates are available but not installed, or automatic updates are disabled.",
    severity: "MEDIUM",
    remediation:
      "Install pending updates and ensure automatic updates are enabled. Reboot if required.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "SECURITY_POSTURE",
    includeWarning: true,
  }),
  failRule({
    ruleId: "OS_UNSUPPORTED",
    checkId: "OS_SUPPORT",
    title: "Operating system version is no longer supported",
    description:
      "The installed OS release no longer receives security updates from its vendor.",
    severity: "CRITICAL",
    remediation:
      "Upgrade to a supported OS release or replace the device. Isolate it from sensitive data until then.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "SYSTEM_INFO",
    includeWarning: true,
  }),
  failRule({
    ruleId: "SCREEN_LOCK_DISABLED",
    checkId: "SCREEN_LOCK",
    title: "Screen lock is not enforced",
    description:
      "The device does not require a password after sleep or screensaver, or the timeout is longer than 15 minutes.",
    severity: "LOW",
    remediation:
      "Require a password immediately after sleep/screensaver and set the idle timeout to 15 minutes or less.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "SECURITY_POSTURE",
    includeWarning: true,
  }),
  failRule({
    ruleId: "SECURE_BOOT_DISABLED",
    checkId: "SECURE_BOOT",
    title: "Secure Boot is disabled",
    description:
      "UEFI Secure Boot is off, weakening protection against boot-level malware.",
    severity: "MEDIUM",
    remediation:
      "Enable Secure Boot in UEFI firmware settings (requires GPT/UEFI boot mode).",
    platforms: ["WINDOWS"],
    collectorId: "SECURITY_POSTURE",
  }),
  failRule({
    ruleId: "UAC_DISABLED",
    checkId: "UAC_ENABLED",
    title: "User Account Control is disabled",
    description:
      "UAC is turned off, allowing silent elevation to administrator.",
    severity: "HIGH",
    remediation:
      "Set EnableLUA to 1 and restore the default UAC prompt level, then reboot.",
    platforms: ["WINDOWS"],
    collectorId: "SECURITY_POSTURE",
  }),
  failRule({
    ruleId: "SIP_DISABLED",
    checkId: "SIP_ENABLED",
    title: "System Integrity Protection is disabled",
    description:
      "macOS SIP is off, allowing modification of protected system files.",
    severity: "HIGH",
    remediation: "Boot into Recovery and run `csrutil enable`.",
    platforms: ["MACOS"],
    collectorId: "SECURITY_POSTURE",
  }),
  failRule({
    ruleId: "GATEKEEPER_DISABLED",
    checkId: "GATEKEEPER_ENABLED",
    title: "Gatekeeper is disabled",
    description:
      "macOS Gatekeeper is off; unsigned applications can run without warning.",
    severity: "HIGH",
    remediation:
      "Run `sudo spctl --master-enable` or re-enable via System Settings > Privacy & Security.",
    platforms: ["MACOS"],
    collectorId: "SECURITY_POSTURE",
  }),
  failRule({
    ruleId: "GUEST_ACCOUNT_ENABLED",
    checkId: "GUEST_ACCOUNT",
    title: "Guest account is enabled",
    description: "A guest account allows unauthenticated local access.",
    severity: "LOW",
    remediation: "Disable the guest account.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "SECURITY_POSTURE",
  }),
  failRule({
    ruleId: "REMOTE_ACCESS_ENABLED",
    checkId: "REMOTE_ACCESS",
    title: "Remote access service is enabled",
    description:
      "Remote Desktop / Remote Login (SSH) or Screen Sharing is enabled on an end-user device.",
    severity: "MEDIUM",
    remediation:
      "Disable remote access unless there is a documented business need; restrict it by firewall if required.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "SECURITY_POSTURE",
    includeWarning: true,
  }),
  failRule({
    ruleId: "SMBV1_ENABLED",
    checkId: "SMBV1",
    title: "SMBv1 protocol is enabled",
    description:
      "The legacy SMBv1 protocol is enabled; it is targeted by wormable exploits.",
    severity: "HIGH",
    remediation:
      "Disable the SMB1Protocol Windows optional feature and reboot.",
    platforms: ["WINDOWS"],
    collectorId: "SAFE_NETWORK_SUMMARY",
  }),
  failRule({
    ruleId: "SECURITY_TELEMETRY_ANOMALY",
    checkId: "SECURITY_TELEMETRY_ANOMALIES",
    title: "Endpoint security telemetry anomaly observed",
    description:
      "The endpoint security event source reported a recent detection or protection-state change.",
    severity: "HIGH",
    remediation:
      "Correlate the event counts with antivirus history, device activity, suspicious files, and persistence evidence. Do not assume remediation succeeded without product-console evidence.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "ANTIVIRUS_STATUS",
    includeWarning: true,
  }),
  {
    ruleId: "AV_DISABLED",
    title: "Antivirus real-time protection is disabled",
    description:
      "No antivirus product is actively protecting the device in real time.",
    severity: "CRITICAL",
    triggerLogic:
      "ANTIVIRUS_STATUS reports status DISABLED, or realTimeProtection FAIL.",
    evidenceRequirement:
      "Status read from Windows Security Center / Defender APIs or macOS XProtect & third-party product state. UNKNOWN never triggers this rule.",
    remediation:
      "Re-enable real-time protection in the installed antivirus product, or install a supported product.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "ANTIVIRUS_STATUS",
    evaluate(ctx) {
      const col = ctx.collectors.find(
        (c) => c.collectorId === "ANTIVIRUS_STATUS",
      );
      const av = col?.antivirus;
      if (!col || !av) return [];
      if (av.status === "DISABLED" || av.realTimeProtection === "FAIL") {
        return [
          {
            fingerprint: "AV_DISABLED",
            evidence:
              `Product: ${av.product ?? "none detected"}; status=${av.status}; realTimeProtection=${av.realTimeProtection}. ${av.note}`.trim(),
            confidence:
              av.status === "DISABLED" && av.realTimeProtection === "FAIL"
                ? "HIGH"
                : "MEDIUM",
            collectorId: "ANTIVIRUS_STATUS",
            rawStatus: `${av.status}/${av.realTimeProtection}`,
            collectorVersion: col.collectorVersion,
            observedAt: col.collectedAt,
            detectionSource: av.source ?? "ANTIVIRUS_STATUS",
          },
        ];
      }
      return [];
    },
  },
  {
    ruleId: "AV_DEFINITIONS_STALE",
    title: "Antivirus definitions are out of date",
    description:
      "Signature definitions are older than 7 days, reducing detection of current malware.",
    severity: "MEDIUM",
    triggerLogic:
      "ANTIVIRUS_STATUS reports definitionsAgeDays > 7 for an ACTIVE product.",
    evidenceRequirement:
      "Definition age must be reported by the product; null age never triggers this rule.",
    remediation:
      "Force a definition update and verify the product can reach its update servers.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "ANTIVIRUS_STATUS",
    evaluate(ctx) {
      const col = ctx.collectors.find(
        (c) => c.collectorId === "ANTIVIRUS_STATUS",
      );
      const av = col?.antivirus;
      if (!col || !av || av.definitionsAgeDays == null) return [];
      if (av.definitionsAgeDays > 7) {
        return [
          {
            fingerprint: "AV_DEFINITIONS_STALE",
            evidence: `Definitions are ${av.definitionsAgeDays} days old (last update ${av.lastDefinitionUpdate ?? "unknown"}), product ${av.product ?? "unknown"}.`,
            confidence: "HIGH",
            severity: av.definitionsAgeDays > 30 ? "HIGH" : "MEDIUM",
            collectorId: "ANTIVIRUS_STATUS",
            rawStatus: String(av.definitionsAgeDays),
            collectorVersion: col.collectorVersion,
            observedAt: col.collectedAt,
            detectionSource: av.source ?? "ANTIVIRUS_STATUS",
          },
        ];
      }
      return [];
    },
  },
  {
    ruleId: "THREAT_DETECTED_RECENT",
    title: "Antivirus reported a threat in the last 30 days",
    description:
      "The installed antivirus product logged a detection recently. Even if remediated, it indicates exposure.",
    severity: "HIGH",
    triggerLogic:
      "ANTIVIRUS_STATUS threat history contains a detection with detectedAt within 30 days.",
    evidenceRequirement:
      "Detection record read from the AV product's own history (e.g. Defender threat history). Not an independent scan result.",
    remediation:
      "Review the detection in the AV console, confirm the action taken (quarantined/removed), and investigate how the file arrived.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "ANTIVIRUS_STATUS",
    evaluate(ctx) {
      const col = ctx.collectors.find(
        (c) => c.collectorId === "ANTIVIRUS_STATUS",
      );
      if (!col?.threats) return [];
      const cutoff = Date.now() - 30 * 86400_000;
      return col.threats
        .filter(
          (t) => t.detectedAt && new Date(t.detectedAt).getTime() >= cutoff,
        )
        .map((t) => ({
          fingerprint: `THREAT:${t.externalId ?? t.threatName}:${t.detectedAt}`,
          title: `Threat detected: ${t.threatName}`,
          evidence: `${t.product} reported "${t.threatName}" (${t.severity ?? "severity n/a"}) at ${t.detectedAt}; action: ${t.actionTaken ?? "unknown"}.`,
          confidence: "HIGH" as const,
          collectorId: "ANTIVIRUS_STATUS" as const,
          rawStatus: t.actionTaken ?? "DETECTED",
          collectorVersion: col.collectorVersion,
          observedAt: col.collectedAt,
          detectionSource: t.source,
        }));
    },
  },
  {
    ruleId: "SUSPICIOUS_PERSISTENCE",
    title: "Suspicious persistence entry observed",
    description:
      "A startup item, service, scheduled task, LaunchAgent, or LaunchDaemon references a user-writable location or a commonly abused command interpreter.",
    severity: "HIGH",
    triggerLogic:
      "STARTUP_INVENTORY contains an enabled entry whose location matches a bounded, documented suspicious-location or interpreter pattern.",
    evidenceRequirement:
      "The exact startup item name, kind, and bounded location string collected from the operating system. A missing publisher alone never triggers this rule.",
    remediation:
      "Validate the entry with the device owner and software inventory. Inspect the referenced file by hash and signature; disable or remove it only through an approved incident-response process.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "STARTUP_INVENTORY",
    evaluate(ctx) {
      const col = ctx.collectors.find(
        (c) => c.collectorId === "STARTUP_INVENTORY",
      );
      if (!col?.startupItems) return [];
      const locationPatterns = [
        /\\appdata\\local\\temp\\/i,
        /\\users\\public\\/i,
        /\\downloads\\/i,
        /(?:^|\s)(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?)(?:\s|$)/i,
        /(?:^|\/)var\/tmp\//i,
        /(?:^|\/)tmp\//i,
        /\/Users\/[^/]+\/\.[^/]+\//i,
      ];
      return col.startupItems.flatMap((item, index) => {
        if (
          item.enabled === false ||
          !locationPatterns.some((pattern) => pattern.test(item.location))
        )
          return [];
        return [
          {
            fingerprint: `PERSISTENCE:${item.kind}:${item.name}:${index}`,
            title: `Suspicious ${item.kind.toLowerCase().replaceAll("_", " ")}: ${item.name}`,
            evidence: `${item.kind} entry "${item.name}" references ${item.location.slice(0, 900)}. Publisher: ${item.publisher ?? "not reported"}. Classification: SUSPICIOUS_INDICATOR.`,
            confidence: "MEDIUM" as const,
            collectorId: "STARTUP_INVENTORY" as const,
            rawStatus: "SUSPICIOUS_INDICATOR",
            collectorVersion: col.collectorVersion,
            observedAt: col.collectedAt,
            detectionSource: "startup inventory heuristic",
          },
        ];
      });
    },
  },
  {
    ruleId: "VISIBILITY_GAP",
    title: "Security state could not be verified",
    description:
      "One or more checks returned UNKNOWN, UNSUPPORTED or PERMISSION_DENIED. The device is not known to be safe in those areas.",
    severity: "LOW",
    triggerLogic:
      "Any check with status UNKNOWN, UNSUPPORTED or PERMISSION_DENIED, or any collector that failed.",
    evidenceRequirement: "The unavailable reason reported by the collector.",
    remediation:
      "Grant the agent the required permission (see check details), run it as a service/root as documented, or accept the gap explicitly.",
    platforms: ["WINDOWS", "MACOS"],
    collectorId: "SECURITY_POSTURE",
    evaluate(ctx) {
      const hits: RuleHit[] = [];
      for (const c of ctx.checks) {
        if (
          c.status === "UNKNOWN" ||
          c.status === "UNSUPPORTED" ||
          c.status === "PERMISSION_DENIED"
        ) {
          hits.push(
            hitFromCheck(c, "HIGH", {
              fingerprint: `GAP:${c.checkId}`,
              title: `Could not verify: ${c.title}`,
              evidence:
                `${c.title} returned ${c.status}. ${c.unavailableReason ?? ""} Required: ${c.requiredPermissions || "n/a"}.`.trim(),
              severity: c.status === "PERMISSION_DENIED" ? "LOW" : "INFO",
            }),
          );
        }
      }
      for (const col of ctx.collectors) {
        if (col.status !== "OK") {
          hits.push({
            fingerprint: `GAP:COLLECTOR:${col.collectorId}`,
            title: `Collector ${col.collectorId} did not complete`,
            evidence: `Collector status ${col.status}: ${col.error ?? "no error detail"}.`,
            confidence: "HIGH",
            severity: col.status === "UNSUPPORTED" ? "INFO" : "LOW",
            collectorId: col.collectorId,
            rawStatus: col.status,
            collectorVersion: col.collectorVersion,
            observedAt: col.collectedAt,
            detectionSource: col.collectorId,
          });
        }
      }
      return hits;
    },
  },
];

export const RULE_IDS = RULES.map((r) => r.ruleId);

export function buildContext(input: {
  osType: OsType;
  deviceName: string;
  assessmentId: string;
  collectors: CollectorResult[];
}): RuleContext {
  const checks: RuleContext["checks"] = [];
  for (const col of input.collectors) {
    for (const ch of col.checks) {
      checks.push({
        ...ch,
        collectorId: col.collectorId,
        collectorVersion: col.collectorVersion,
        collectedAt: col.collectedAt,
      });
    }
  }
  return { ...input, checks };
}

export function evaluateRules(
  ctx: RuleContext,
): Array<RuleHit & { rule: Rule; severity: Severity; title: string }> {
  const out: Array<
    RuleHit & { rule: Rule; severity: Severity; title: string }
  > = [];
  for (const rule of RULES) {
    for (const hit of rule.evaluate(ctx)) {
      out.push({
        ...hit,
        rule,
        severity: hit.severity ?? rule.severity,
        title: hit.title ?? rule.title,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 30,
  HIGH: 15,
  MEDIUM: 7,
  LOW: 2,
  INFO: 0,
};

/**
 * Risk score 0-100. Transparent sum of open finding weights, capped at 100.
 * Returns null when nothing could be evaluated (coverage 0) — a null score is
 * not a clean device.
 */
export function computeRiskScore(
  openFindings: Array<{ severity: Severity }>,
  coveragePercent: number,
): number | null {
  if (coveragePercent <= 0) return null;
  const sum = openFindings.reduce(
    (acc, f) => acc + SEVERITY_WEIGHT[f.severity],
    0,
  );
  return Math.min(100, sum);
}

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export function riskLevelFor(
  score: number | null,
  coveragePercent: number,
): RiskLevel {
  if (score == null || coveragePercent <= 0) return "UNKNOWN";
  if (score >= 60) return "CRITICAL";
  if (score >= 30) return "HIGH";
  if (score >= 10) return "MEDIUM";
  return "LOW";
}

/** Coverage: share of the six fixed collectors that completed with status OK. */
export function computeCoverage(
  collectors: Array<{ status: string }>,
  requested: number,
): number {
  if (requested <= 0) return 0;
  const ok = collectors.filter((c) => c.status === "OK").length;
  return Math.round((ok / 6) * 100);
}
