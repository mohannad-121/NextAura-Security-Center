/**
 * Vulnerability intelligence: NVD CVE API 2.0 + CISA KEV catalog.
 *
 * - Network fetches happen in a single in-process worker that honours NVD
 *   rate limits (5 req / 30 s without key, 50 with NVD_API_KEY).
 * - Matching uses ONLY cached data so ingestion never blocks on the network.
 * - Every match carries an explicit confidence and the reason behind it.
 */
import { and, count, eq, inArray, sql } from "drizzle-orm";
import {
  db,
  cveCacheTable,
  cveProductQueriesTable,
  intelligenceStateTable,
  kevCatalogTable,
  securityFindingsTable,
  softwareInventoryTable,
  vulnerabilityMatchesTable,
  devicesTable,
  type Device,
} from "@workspace/db";
import { logger } from "../lib/logger";
import type { Severity } from "./rules";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const QUERY_TTL_MS = 7 * 86400_000;
const KEV_TTL_MS = 12 * 3600_000;
const MANUAL_REFRESH_COOLDOWN_MS = 15 * 60_000;
const STATE_ID = "global";

const nvdApiKey = process.env.NVD_API_KEY;
const NVD_MIN_INTERVAL_MS = nvdApiKey ? 700 : 6500;

export function nvdConfigured() {
  return true; // NVD works without a key (slower). Key is optional.
}

// ---------------------------------------------------------------------------
// Version comparison (lenient semver-ish)
// ---------------------------------------------------------------------------
function versionParts(v: string): number[] {
  return v
    .trim()
    .split(/[.\-+_ ]/)
    .map((p) => parseInt(p.replace(/[^0-9]/g, ""), 10))
    .map((n) => (Number.isNaN(n) ? 0 : n));
}
export function compareVersions(a: string, b: string): number {
  const pa = versionParts(a);
  const pb = versionParts(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

type Config = NonNullable<typeof cveCacheTable.$inferSelect.configurations>[number];

export function versionInRange(installed: string, cfg: Config): { inRange: boolean; explicit: boolean } {
  if (cfg.exactVersion && cfg.exactVersion !== "*" && cfg.exactVersion !== "-") {
    return { inRange: compareVersions(installed, cfg.exactVersion) === 0, explicit: true };
  }
  const hasRange = cfg.versionStartIncluding || cfg.versionStartExcluding || cfg.versionEndIncluding || cfg.versionEndExcluding;
  if (!hasRange) return { inRange: true, explicit: false };
  if (cfg.versionStartIncluding && compareVersions(installed, cfg.versionStartIncluding) < 0) return { inRange: false, explicit: true };
  if (cfg.versionStartExcluding && compareVersions(installed, cfg.versionStartExcluding) <= 0) return { inRange: false, explicit: true };
  if (cfg.versionEndIncluding && compareVersions(installed, cfg.versionEndIncluding) > 0) return { inRange: false, explicit: true };
  if (cfg.versionEndExcluding && compareVersions(installed, cfg.versionEndExcluding) >= 0) return { inRange: false, explicit: true };
  return { inRange: true, explicit: true };
}

function rangeText(cfg: Config): string {
  if (cfg.exactVersion && cfg.exactVersion !== "*") return `= ${cfg.exactVersion}`;
  const parts: string[] = [];
  if (cfg.versionStartIncluding) parts.push(`>= ${cfg.versionStartIncluding}`);
  if (cfg.versionStartExcluding) parts.push(`> ${cfg.versionStartExcluding}`);
  if (cfg.versionEndIncluding) parts.push(`<= ${cfg.versionEndIncluding}`);
  if (cfg.versionEndExcluding) parts.push(`< ${cfg.versionEndExcluding}`);
  return parts.length ? parts.join(", ") : "all versions (no range published)";
}

// ---------------------------------------------------------------------------
// NVD fetch + parse
// ---------------------------------------------------------------------------
function severityFromScore(score: number | null, label?: string): Severity {
  if (label) {
    const l = label.toUpperCase();
    if (l === "CRITICAL" || l === "HIGH" || l === "MEDIUM" || l === "LOW") return l;
  }
  if (score == null) return "MEDIUM";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

interface NvdCve {
  id: string;
  published?: string;
  lastModified?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: Record<string, { cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string }; baseSeverity?: string }[]>;
  references?: { url: string }[];
  configurations?: { nodes?: { cpeMatch?: { vulnerable: boolean; criteria: string; versionStartIncluding?: string; versionStartExcluding?: string; versionEndIncluding?: string; versionEndExcluding?: string }[] }[] }[];
}

function parseCve(c: NvdCve) {
  const metricSets = c.metrics ?? {};
  const pick = metricSets["cvssMetricV31"]?.[0] ?? metricSets["cvssMetricV40"]?.[0] ?? metricSets["cvssMetricV30"]?.[0] ?? metricSets["cvssMetricV2"]?.[0];
  const score = pick?.cvssData?.baseScore ?? null;
  const vector = pick?.cvssData?.vectorString ?? null;
  const sevLabel = pick?.cvssData?.baseSeverity ?? pick?.baseSeverity;
  const configurations: Config[] = [];
  for (const conf of c.configurations ?? []) {
    for (const node of conf.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (!m.vulnerable) continue;
        const parts = m.criteria.split(":");
        // cpe:2.3:a:vendor:product:version:...
        if (parts.length < 6) continue;
        configurations.push({
          vendor: parts[3]!.replace(/_/g, " "),
          product: parts[4]!.replace(/_/g, " "),
          exactVersion: parts[5] && parts[5] !== "*" ? parts[5] : undefined,
          versionStartIncluding: m.versionStartIncluding,
          versionStartExcluding: m.versionStartExcluding,
          versionEndIncluding: m.versionEndIncluding,
          versionEndExcluding: m.versionEndExcluding,
        });
      }
    }
  }
  return {
    cveId: c.id,
    description: c.descriptions?.find((d) => d.lang === "en")?.value ?? "",
    severity: severityFromScore(score, sevLabel),
    cvssScore: score,
    cvssVector: vector,
    publishedAt: c.published ? new Date(c.published) : null,
    lastModifiedAt: c.lastModified ? new Date(c.lastModified) : null,
    references: (c.references ?? []).map((r) => r.url).slice(0, 20),
    configurations,
    fetchedAt: new Date(),
  };
}

let lastNvdCall = 0;
async function nvdThrottle() {
  const wait = lastNvdCall + NVD_MIN_INTERVAL_MS - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastNvdCall = Date.now();
}

async function fetchNvdForQuery(queryKey: string, keyword: string): Promise<void> {
  await nvdThrottle();
  const url = `${NVD_BASE}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=200`;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (nvdApiKey) headers["apiKey"] = nvdApiKey;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
  if (res.status === 429 || res.status === 403) throw new Error(`NVD rate limited (${res.status})`);
  if (!res.ok) throw new Error(`NVD HTTP ${res.status}`);
  const data = (await res.json()) as { vulnerabilities?: { cve: NvdCve }[] };
  const cves = (data.vulnerabilities ?? []).map((v) => parseCve(v.cve));
  for (const cve of cves) {
    await db
      .insert(cveCacheTable)
      .values(cve)
      .onConflictDoUpdate({ target: cveCacheTable.cveId, set: { ...cve } });
  }
  await db
    .insert(cveProductQueriesTable)
    .values({ queryKey, cveIds: cves.map((c) => c.cveId), fetchedAt: new Date(), error: null })
    .onConflictDoUpdate({
      target: cveProductQueriesTable.queryKey,
      set: { cveIds: cves.map((c) => c.cveId), fetchedAt: new Date(), error: null },
    });
  await setState({ nvdLastSyncAt: new Date(), nvdLastStatus: "OK", nvdLastError: null });
}

export async function syncKev(): Promise<void> {
  const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
  const data = (await res.json()) as {
    vulnerabilities: { cveID: string; vendorProject: string; product: string; vulnerabilityName: string; dateAdded: string; dueDate?: string; requiredAction?: string; knownRansomwareCampaignUse?: string }[];
  };
  const rows = data.vulnerabilities.map((v) => ({
    cveId: v.cveID,
    vendorProject: v.vendorProject,
    product: v.product,
    vulnerabilityName: v.vulnerabilityName,
    dateAdded: v.dateAdded,
    dueDate: v.dueDate ?? null,
    requiredAction: v.requiredAction ?? "",
    knownRansomwareUse: (v.knownRansomwareCampaignUse ?? "").toLowerCase() === "known",
    fetchedAt: new Date(),
  }));
  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500);
    await db
      .insert(kevCatalogTable)
      .values(chunk)
      .onConflictDoUpdate({
        target: kevCatalogTable.cveId,
        set: {
          dueDate: sql`excluded.due_date`,
          requiredAction: sql`excluded.required_action`,
          knownRansomwareUse: sql`excluded.known_ransomware_use`,
          fetchedAt: sql`excluded.fetched_at`,
        },
      });
  }
  await setState({ kevLastSyncAt: new Date(), kevLastStatus: "OK", kevLastError: null, kevCount: rows.length });
}

async function getState() {
  const [row] = await db.select().from(intelligenceStateTable).where(eq(intelligenceStateTable.id, STATE_ID));
  if (row) return row;
  const [created] = await db.insert(intelligenceStateTable).values({ id: STATE_ID }).onConflictDoNothing().returning();
  return created ?? (await db.select().from(intelligenceStateTable).where(eq(intelligenceStateTable.id, STATE_ID)))[0]!;
}
async function setState(patch: Partial<typeof intelligenceStateTable.$inferInsert>) {
  await getState();
  await db.update(intelligenceStateTable).set(patch).where(eq(intelligenceStateTable.id, STATE_ID));
}

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------
const pendingQueries = new Map<string, string>(); // queryKey -> keyword
let workerRunning = false;
let refreshInProgress = false;
let lastMatchRunAt: Date | null = null;

function enqueueQuery(queryKey: string, keyword: string) {
  if (!pendingQueries.has(queryKey)) pendingQueries.set(queryKey, keyword);
  void runWorker();
}

async function runWorker() {
  if (workerRunning) return;
  workerRunning = true;
  try {
    while (pendingQueries.size) {
      const [queryKey, keyword] = pendingQueries.entries().next().value as [string, string];
      pendingQueries.delete(queryKey);
      try {
        await fetchNvdForQuery(queryKey, keyword);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn({ err: message, queryKey }, "NVD query failed");
        await db
          .insert(cveProductQueriesTable)
          .values({ queryKey, cveIds: [], fetchedAt: new Date(0), error: message })
          .onConflictDoUpdate({ target: cveProductQueriesTable.queryKey, set: { error: message } });
        await setState({ nvdLastStatus: "ERROR", nvdLastError: message });
        if (/rate limited/i.test(message)) await new Promise((r) => setTimeout(r, 30_000));
      }
    }
  } finally {
    workerRunning = false;
  }
}

// Software that is noise for CVE keyword search (OS components, runtimes updated by OS).
const SKIP_PATTERNS = [/^microsoft visual c\+\+/, /^microsoft \.net/, /^windows /, /^update for/, /^security update/, /^hotfix/, /^kb\d+/, /^microsoft edge webview/, /^microsoft update health/, /^intel\(r\)/, /^realtek/, /^nvidia /];

function queryKeyFor(normalizedName: string, normalizedVendor: string | null): { key: string; keyword: string } | null {
  if (!normalizedName || normalizedName.length < 3) return null;
  if (SKIP_PATTERNS.some((p) => p.test(normalizedName))) return null;
  const keyword = normalizedName.split(" ").slice(0, 3).join(" ");
  return { key: `${normalizedVendor ?? ""}|${keyword}`, keyword };
}

function tokens(s: string) {
  return new Set(s.split(" ").filter((t) => t.length > 1));
}
function productMatches(cfgProduct: string, normalizedName: string): boolean {
  const a = tokens(cfgProduct.toLowerCase());
  const b = tokens(normalizedName);
  if (a.size === 0) return false;
  let hit = 0;
  for (const t of a) if (b.has(t)) hit++;
  return hit === a.size || (a.size >= 2 && hit >= Math.ceil(a.size * 0.75));
}
function vendorMatches(cfgVendor: string, normalizedVendor: string | null): boolean {
  if (!normalizedVendor) return false;
  const a = tokens(cfgVendor.toLowerCase());
  const b = tokens(normalizedVendor);
  for (const t of a) if (b.has(t)) return true;
  return false;
}

type MatchConfidence = "CONFIRMED" | "PROBABLE" | "POSSIBLE" | "UNKNOWN";

/**
 * Matches a device's current software snapshot against cached CVEs.
 * Missing product queries are enqueued for the background worker.
 */
export async function matchDeviceSoftware(
  device: Device,
  software: { id: string; normalizedName: string; normalizedVendor: string | null; version: string | null; name: string; vendor: string | null }[],
) {
  const now = new Date();
  const seen = new Set<string>();
  for (const sw of software) {
    const q = queryKeyFor(sw.normalizedName, sw.normalizedVendor);
    if (!q) continue;
    const [cached] = await db.select().from(cveProductQueriesTable).where(eq(cveProductQueriesTable.queryKey, q.key));
    if (!cached || now.getTime() - cached.fetchedAt.getTime() > QUERY_TTL_MS) {
      enqueueQuery(q.key, q.keyword);
      if (!cached) continue;
    }
    if (!cached.cveIds.length) continue;
    const cves = await db.select().from(cveCacheTable).where(inArray(cveCacheTable.cveId, cached.cveIds));
    const kev = await db
      .select()
      .from(kevCatalogTable)
      .where(inArray(kevCatalogTable.cveId, cached.cveIds));
    const kevById = new Map(kev.map((k) => [k.cveId, k]));

    for (const cve of cves) {
      const relevant = cve.configurations.filter((c) => productMatches(c.product, sw.normalizedName));
      if (!relevant.length) continue;
      let best: { confidence: MatchConfidence; reason: string; range: string; cfg: Config } | null = null;
      for (const cfg of relevant) {
        const vMatch = vendorMatches(cfg.vendor, sw.normalizedVendor);
        let confidence: MatchConfidence;
        let reason: string;
        if (!sw.version) {
          confidence = "POSSIBLE";
          reason = `Product name matches CPE ${cfg.vendor}:${cfg.product} but the installed version is unknown, so the affected range could not be checked.`;
        } else {
          const { inRange, explicit } = versionInRange(sw.version, cfg);
          if (!inRange) continue;
          if (explicit && vMatch) {
            confidence = "CONFIRMED";
            reason = `Vendor and product match CPE ${cfg.vendor}:${cfg.product}; installed ${sw.version} is within the published affected range (${rangeText(cfg)}).`;
          } else if (explicit) {
            confidence = "PROBABLE";
            reason = `Product matches CPE ${cfg.product} and installed ${sw.version} is within ${rangeText(cfg)}, but the vendor (${sw.vendor ?? "unknown"}) could not be confirmed against ${cfg.vendor}.`;
          } else {
            confidence = "POSSIBLE";
            reason = `Product matches CPE ${cfg.vendor}:${cfg.product} but NVD publishes no version range for this entry; the installed version may not be affected.`;
          }
        }
        const rank = { CONFIRMED: 3, PROBABLE: 2, POSSIBLE: 1, UNKNOWN: 0 };
        if (!best || rank[confidence] > rank[best.confidence]) best = { confidence, reason, range: rangeText(cfg), cfg };
      }
      if (!best) continue;
      const k = kevById.get(cve.cveId);
      const key = `${cve.cveId}|${sw.name}|${sw.version ?? ""}`;
      seen.add(key);
      await db
        .insert(vulnerabilityMatchesTable)
        .values({
          organizationId: device.organizationId,
          deviceId: device.id,
          softwareId: sw.id,
          cveId: cve.cveId,
          vendor: sw.vendor ?? best.cfg.vendor,
          product: sw.name,
          installedVersion: sw.version ?? "unknown",
          affectedRange: best.range,
          severity: cve.severity,
          cvssScore: cve.cvssScore,
          cvssVector: cve.cvssVector,
          knownExploited: !!k,
          kevDateAdded: k?.dateAdded ?? null,
          matchConfidence: best.confidence,
          matchReason: best.reason + (k ? ` Listed in CISA KEV (added ${k.dateAdded}).` : ""),
          references: cve.references,
          remediation: k?.requiredAction || `Update ${sw.name} to a version outside the affected range, or remove it if unused.`,
          description: cve.description,
          publishedAt: cve.publishedAt,
          firstSeenAt: now,
          lastSeenAt: now,
          current: true,
        })
        .onConflictDoUpdate({
          target: [vulnerabilityMatchesTable.deviceId, vulnerabilityMatchesTable.cveId, vulnerabilityMatchesTable.product, vulnerabilityMatchesTable.installedVersion],
          set: {
            softwareId: sw.id,
            lastSeenAt: now,
            current: true,
            knownExploited: !!k,
            kevDateAdded: k?.dateAdded ?? null,
            matchConfidence: best.confidence,
            matchReason: best.reason + (k ? ` Listed in CISA KEV (added ${k.dateAdded}).` : ""),
            severity: cve.severity,
            cvssScore: cve.cvssScore,
          },
        });
    }
  }

  // Mark matches not seen in this snapshot as no longer current.
  const current = await db
    .select({ id: vulnerabilityMatchesTable.id, cveId: vulnerabilityMatchesTable.cveId, product: vulnerabilityMatchesTable.product, installedVersion: vulnerabilityMatchesTable.installedVersion })
    .from(vulnerabilityMatchesTable)
    .where(and(eq(vulnerabilityMatchesTable.deviceId, device.id), eq(vulnerabilityMatchesTable.current, true)));
  const stale = current.filter((m) => !seen.has(`${m.cveId}|${m.product}|${m.installedVersion === "unknown" ? "" : m.installedVersion}`));
  if (stale.length) {
    await db.update(vulnerabilityMatchesTable).set({ current: false }).where(inArray(vulnerabilityMatchesTable.id, stale.map((s) => s.id)));
  }

  await syncVulnerabilityFindings(device);
  lastMatchRunAt = new Date();
}

/** Creates/updates findings for KEV and CRITICAL CVE matches with adequate confidence. */
async function syncVulnerabilityFindings(device: Device) {
  const matches = await db
    .select()
    .from(vulnerabilityMatchesTable)
    .where(and(eq(vulnerabilityMatchesTable.deviceId, device.id), eq(vulnerabilityMatchesTable.current, true)));
  const now = new Date();
  const fingerprints = new Set<string>();
  for (const m of matches) {
    const strong = m.matchConfidence === "CONFIRMED" || m.matchConfidence === "PROBABLE";
    if (!strong) continue;
    let ruleId: string | null = null;
    let severity: Severity | null = null;
    if (m.knownExploited) {
      ruleId = "VULN_KEV";
      severity = "CRITICAL";
    } else if (m.severity === "CRITICAL" && m.matchConfidence === "CONFIRMED") {
      ruleId = "VULN_CRITICAL";
      severity = "HIGH";
    }
    if (!ruleId || !severity) continue;
    const fp = `${ruleId}:${m.cveId}:${m.product}`;
    fingerprints.add(fp);
    await db
      .insert(securityFindingsTable)
      .values({
        organizationId: device.organizationId,
        deviceId: device.id,
        ruleId,
        fingerprint: fp,
        title: ruleId === "VULN_KEV" ? `Known exploited vulnerability: ${m.cveId} in ${m.product}` : `Critical vulnerability: ${m.cveId} in ${m.product}`,
        description: m.description || "See CVE references.",
        severity,
        confidence: m.matchConfidence === "CONFIRMED" ? "HIGH" : "MEDIUM",
        evidence: `${m.product} ${m.installedVersion} installed; affected range ${m.affectedRange}. ${m.matchReason}`,
        detectionSource: m.knownExploited ? "NVD + CISA KEV" : "NVD",
        remediation: m.remediation,
        status: "OPEN",
        firstSeenAt: now,
        lastSeenAt: now,
        collectorId: "SOFTWARE_INVENTORY",
        rawStatus: m.matchConfidence,
        observedAt: now,
      })
      .onConflictDoUpdate({
        target: [securityFindingsTable.deviceId, securityFindingsTable.fingerprint],
        set: {
          lastSeenAt: now,
          evidence: `${m.product} ${m.installedVersion} installed; affected range ${m.affectedRange}. ${m.matchReason}`,
          status: sql`CASE WHEN ${securityFindingsTable.status} = 'RESOLVED' THEN 'OPEN'::finding_status ELSE ${securityFindingsTable.status} END`,
        },
      });
  }
  const open = await db
    .select({ id: securityFindingsTable.id, fingerprint: securityFindingsTable.fingerprint })
    .from(securityFindingsTable)
    .where(and(eq(securityFindingsTable.deviceId, device.id), inArray(securityFindingsTable.ruleId, ["VULN_KEV", "VULN_CRITICAL"]), inArray(securityFindingsTable.status, ["OPEN", "ACKNOWLEDGED"])));
  const resolve = open.filter((f) => !fingerprints.has(f.fingerprint));
  if (resolve.length) {
    await db
      .update(securityFindingsTable)
      .set({ status: "RESOLVED", statusChangedAt: now, statusChangedByEmail: "system", statusNote: "Affected software no longer present in the current inventory." })
      .where(inArray(securityFindingsTable.id, resolve.map((f) => f.id)));
  }
}

export async function intelligenceStatus() {
  const state = await getState();
  const [{ n: cached }] = await db.select({ n: count() }).from(cveCacheTable);
  const [{ n: kevN }] = await db.select({ n: count() }).from(kevCatalogTable);
  const nextAllowed = state.lastManualRefreshAt ? new Date(state.lastManualRefreshAt.getTime() + MANUAL_REFRESH_COOLDOWN_MS) : null;
  return {
    nvdConfigured: nvdConfigured(),
    nvdCachedCves: Number(cached),
    nvdLastSyncAt: state.nvdLastSyncAt?.toISOString() ?? null,
    nvdLastError: state.nvdLastError,
    kevCatalogEntries: Number(kevN),
    kevLastSyncAt: state.kevLastSyncAt?.toISOString() ?? null,
    kevLastError: state.kevLastError,
    lastMatchRunAt: lastMatchRunAt?.toISOString() ?? null,
    refreshInProgress: refreshInProgress || workerRunning,
    nextAllowedRefreshAt: nextAllowed && nextAllowed > new Date() ? nextAllowed.toISOString() : null,
  };
}

/** Manual refresh: re-sync KEV, expire cached product queries for the org, re-match all org devices. */
export async function refreshIntelligence(organizationId: string): Promise<{ allowed: boolean; nextAllowedRefreshAt: string | null }> {
  const state = await getState();
  if (state.lastManualRefreshAt && Date.now() - state.lastManualRefreshAt.getTime() < MANUAL_REFRESH_COOLDOWN_MS) {
    return { allowed: false, nextAllowedRefreshAt: new Date(state.lastManualRefreshAt.getTime() + MANUAL_REFRESH_COOLDOWN_MS).toISOString() };
  }
  await setState({ lastManualRefreshAt: new Date() });
  refreshInProgress = true;
  void (async () => {
    try {
      await syncKev();
    } catch (err) {
      await setState({ kevLastStatus: "ERROR", kevLastError: err instanceof Error ? err.message : String(err) });
    }
    try {
      await rematchOrganization(organizationId, true);
    } finally {
      refreshInProgress = false;
    }
  })();
  return { allowed: true, nextAllowedRefreshAt: new Date(Date.now() + MANUAL_REFRESH_COOLDOWN_MS).toISOString() };
}

export async function rematchOrganization(organizationId: string, forceRequery = false) {
  const devices = await db.select().from(devicesTable).where(and(eq(devicesTable.organizationId, organizationId), eq(devicesTable.status, "ACTIVE")));
  for (const device of devices) {
    const sw = await db
      .select({ id: softwareInventoryTable.id, normalizedName: softwareInventoryTable.normalizedName, normalizedVendor: softwareInventoryTable.normalizedVendor, version: softwareInventoryTable.version, name: softwareInventoryTable.name, vendor: softwareInventoryTable.vendor })
      .from(softwareInventoryTable)
      .where(and(eq(softwareInventoryTable.deviceId, device.id), eq(softwareInventoryTable.current, true)));
    if (forceRequery) {
      for (const s of sw) {
        const q = queryKeyFor(s.normalizedName, s.normalizedVendor);
        if (q) enqueueQuery(q.key, q.keyword);
      }
    }
    await matchDeviceSoftware(device, sw);
  }
}

/** Periodic maintenance: KEV sync every 12h; re-match devices whose queries completed. */
export function startIntelligenceScheduler() {
  const tick = async () => {
    try {
      const state = await getState();
      if (!state.kevLastSyncAt || Date.now() - state.kevLastSyncAt.getTime() > KEV_TTL_MS) await syncKev();
    } catch (err) {
      logger.warn({ err }, "KEV sync failed");
      await setState({ kevLastStatus: "ERROR", kevLastError: err instanceof Error ? err.message : String(err) }).catch(() => {});
    }
  };
  void tick();
  setInterval(() => void tick(), 60 * 60_000).unref();
}
