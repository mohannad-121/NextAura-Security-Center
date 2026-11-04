/**
 * Passive SPF / DMARC / DKIM audit using public DNS only.
 * No mail is sent; nothing is probed beyond TXT/MX lookups.
 */
import { promises as dns } from "node:dns";

type CheckStatus = "PASS" | "FAIL" | "WARNING" | "UNKNOWN" | "UNSUPPORTED" | "PERMISSION_DENIED" | "STALE";

export interface DnsCheckResult {
  status: CheckStatus;
  record: string | null;
  evaluation: string;
  recommendations: string[];
}

export const EMAIL_AUDIT_LIMITATIONS =
  "This audit reads public DNS records only. It confirms whether SPF, DMARC and DKIM records exist and are syntactically reasonable; it cannot verify that your mail provider actually signs outgoing mail, that receivers enforce your policy, or that DKIM selectors you did not list are configured. DNS caching may delay visibility of recent changes.";

export function normalizeDomain(input: string): string | null {
  const d = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  if (!/^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(d)) return null;
  return d;
}

async function txt(name: string): Promise<string[] | null> {
  try {
    const rows = await dns.resolveTxt(name);
    return rows.map((parts) => parts.join(""));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOTFOUND" || code === "ENODATA") return [];
    return null; // resolver failure → UNKNOWN
  }
}

function evaluateSpf(records: string[] | null): DnsCheckResult {
  if (records === null) return { status: "UNKNOWN", record: null, evaluation: "DNS lookup failed; SPF could not be evaluated.", recommendations: ["Retry later or check DNS resolver reachability."] };
  const spf = records.filter((r) => /^v=spf1(\s|$)/i.test(r));
  if (spf.length === 0) return { status: "FAIL", record: null, evaluation: "No SPF record found. Any server can send mail claiming to be from this domain.", recommendations: ["Publish a TXT record starting with v=spf1 that lists your mail providers and ends with -all or ~all."] };
  if (spf.length > 1) return { status: "FAIL", record: spf.join(" | "), evaluation: "Multiple SPF records found; receivers treat this as a permanent error.", recommendations: ["Merge into a single v=spf1 record."] };
  const rec = spf[0]!;
  const recs: string[] = [];
  let status: CheckStatus = "PASS";
  const lookups = (rec.match(/\b(include:|a:|a\b|mx\b|mx:|ptr|exists:|redirect=)/gi) ?? []).length;
  if (/\+all/i.test(rec)) { status = "FAIL"; recs.push("Replace +all with -all (or ~all): +all authorises every sender."); }
  else if (/\?all/i.test(rec)) { status = "WARNING"; recs.push("?all is neutral and offers no protection; use -all or ~all."); }
  else if (/~all/i.test(rec)) { recs.push("Consider moving from ~all (softfail) to -all once all legitimate senders are listed."); }
  else if (!/-all/i.test(rec)) { status = "WARNING"; recs.push("Record does not end with an all mechanism; add -all."); }
  if (lookups > 10) { status = "FAIL"; recs.push(`Record requires ${lookups} DNS lookups (limit 10); receivers will return permerror.`); }
  else if (lookups > 7) recs.push(`Record uses ${lookups} DNS lookups; the limit is 10.`);
  if (/\bptr\b/i.test(rec)) recs.push("Avoid the ptr mechanism; it is deprecated and slow.");
  return { status, record: rec, evaluation: status === "PASS" ? "SPF record present with an enforcing or softfail policy." : "SPF record present but weak or invalid.", recommendations: recs };
}

function evaluateDmarc(records: string[] | null): DnsCheckResult {
  if (records === null) return { status: "UNKNOWN", record: null, evaluation: "DNS lookup failed; DMARC could not be evaluated.", recommendations: [] };
  const dm = records.filter((r) => /^v=dmarc1(\s|;|$)/i.test(r));
  if (dm.length === 0) return { status: "FAIL", record: null, evaluation: "No DMARC record at _dmarc.<domain>. Receivers cannot enforce alignment and you receive no abuse reports.", recommendations: ["Publish v=DMARC1; p=none; rua=mailto:dmarc@<domain> to start monitoring, then move to quarantine and reject."] };
  if (dm.length > 1) return { status: "FAIL", record: dm.join(" | "), evaluation: "Multiple DMARC records found; receivers ignore all of them.", recommendations: ["Keep a single DMARC record."] };
  const rec = dm[0]!;
  const tags = Object.fromEntries(rec.split(";").map((t) => t.trim()).filter(Boolean).map((t) => { const [k, ...v] = t.split("="); return [k!.trim().toLowerCase(), v.join("=").trim()]; }));
  const recs: string[] = [];
  let status: CheckStatus = "PASS";
  const p = (tags["p"] ?? "").toLowerCase();
  if (p === "none") { status = "WARNING"; recs.push("Policy is p=none (monitor only). Move to p=quarantine, then p=reject, once reports show legitimate mail aligns."); }
  else if (p === "quarantine") recs.push("Consider p=reject for full protection.");
  else if (p !== "reject") { status = "FAIL"; recs.push("Missing or invalid p= tag; DMARC requires p=none|quarantine|reject."); }
  if (!tags["rua"]) { recs.push("Add rua= to receive aggregate reports."); if (status === "PASS") status = "WARNING"; }
  const pct = tags["pct"] ? parseInt(tags["pct"], 10) : 100;
  if (pct < 100) { recs.push(`pct=${pct} applies the policy to only ${pct}% of mail; raise to 100.`); if (status === "PASS") status = "WARNING"; }
  if ((tags["sp"] ?? "").toLowerCase() === "none" && p !== "none") recs.push("Subdomain policy sp=none leaves subdomains unprotected.");
  return { status, record: rec, evaluation: status === "PASS" ? `DMARC enforcing policy p=${p}.` : `DMARC record present with policy p=${p || "missing"}.`, recommendations: recs };
}

function evaluateDkim(records: string[] | null, selector: string): DnsCheckResult & { selector: string } {
  if (records === null) return { selector, status: "UNKNOWN", record: null, evaluation: `DNS lookup for ${selector}._domainkey failed.`, recommendations: [] };
  const dk = records.filter((r) => /(^|;|\s)p=/i.test(r) || /v=dkim1/i.test(r));
  if (dk.length === 0) return { selector, status: "FAIL", record: null, evaluation: `No DKIM key found for selector "${selector}".`, recommendations: ["Confirm the selector name with your mail provider and publish the key they issue."] };
  const rec = dk[0]!;
  const p = /p=([A-Za-z0-9+/=]*)/.exec(rec)?.[1] ?? "";
  if (p === "") return { selector, status: "FAIL", record: rec, evaluation: "DKIM record has an empty public key (revoked).", recommendations: ["Rotate the key with your mail provider."] };
  const keyBits = Math.round((p.length * 6) / 8) * 8;
  const recs: string[] = [];
  let status: CheckStatus = "PASS";
  if (keyBits < 1900) { status = "WARNING"; recs.push(`Public key appears to be ~${keyBits <= 1100 ? 1024 : keyBits} bits; 2048-bit keys are recommended.`); }
  if (/\bt=y\b/i.test(rec)) { status = "WARNING"; recs.push("Testing flag t=y is set; remove it once DKIM is stable."); }
  return { selector, status, record: rec.length > 120 ? rec.slice(0, 117) + "..." : rec, evaluation: `DKIM public key published for selector "${selector}".`, recommendations: recs };
}

export async function runEmailAudit(domain: string, dkimSelectors: string[]) {
  const [spfTxt, dmarcTxt, mx] = await Promise.all([
    txt(domain),
    txt(`_dmarc.${domain}`),
    dns.resolveMx(domain).then((r) => r.sort((a, b) => a.priority - b.priority).map((m) => `${m.exchange} (${m.priority})`)).catch(() => [] as string[]),
  ]);
  const selectors = dkimSelectors.length ? dkimSelectors : ["default", "selector1", "selector2", "google", "k1", "s1", "s2", "dkim"];
  const dkim = await Promise.all(selectors.map(async (s) => evaluateDkim(await txt(`${s}._domainkey.${domain}`), s)));
  const spf = evaluateSpf(spfTxt);
  const dmarc = evaluateDmarc(dmarcTxt);
  const dkimBest: CheckStatus = dkim.some((d) => d.status === "PASS") ? "PASS" : dkim.some((d) => d.status === "WARNING") ? "WARNING" : dkim.every((d) => d.status === "UNKNOWN") ? "UNKNOWN" : dkimSelectors.length ? "FAIL" : "UNKNOWN";
  const all = [spf.status, dmarc.status, dkimBest];
  const overallStatus: CheckStatus = all.includes("FAIL") ? "FAIL" : all.includes("WARNING") ? "WARNING" : all.includes("UNKNOWN") ? "UNKNOWN" : "PASS";
  // When no selectors were supplied, only report the guessed ones that were found, plus one note.
  const dkimOut = dkimSelectors.length ? dkim : dkim.filter((d) => d.status !== "FAIL");
  if (!dkimSelectors.length && dkimOut.length === 0) {
    dkimOut.push({ selector: "(none supplied)", status: "UNKNOWN", record: null, evaluation: "No DKIM selector was provided and none of the common selectors exist. DKIM cannot be evaluated without the selector your provider uses.", recommendations: ["Find the selector in your mail provider's DKIM settings and re-run the audit with it."] });
  }
  return { spf, dmarc, dkim: dkimOut, mx, overallStatus, limitations: EMAIL_AUDIT_LIMITATIONS };
}
