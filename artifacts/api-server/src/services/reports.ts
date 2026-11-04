import PDFDocument from "pdfkit";
import { and, desc, eq, inArray } from "drizzle-orm";
import {
  db,
  devicesTable,
  securityFindingsTable,
  vulnerabilityMatchesTable,
  assessmentChecksTable,
  type Organization,
  type Device,
} from "@workspace/db";
import { latestAssessmentFor, riskLevelLabel } from "./reportHelpers";
import { riskLevelFor } from "./rules";

const DISCLAIMER =
  "Scope and limitations: this report reflects data collected by the NextAura read-only agent at the stated times. Checks marked UNKNOWN, UNSUPPORTED or PERMISSION_DENIED were not verified and must not be read as passing. A low risk score is not proof of a clean device. Vulnerability matches are derived from software inventory and public CVE data; confidence is stated per match.";

function pdfToBuffer(build: (doc: PDFKit.PDFDocument) => void): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "A4", margin: 48, info: { Title: "NextAura Security Report", Author: "NextAura Security Center" } });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
    build(doc);
    doc.end();
  });
}

function header(doc: PDFKit.PDFDocument, title: string, org: Organization) {
  doc.fillColor("#7568E8").fontSize(10).text("NEXTAURA SECURITY CENTER", { characterSpacing: 1 });
  doc.moveDown(0.2);
  doc.fillColor("#111111").fontSize(20).text(title);
  doc.fontSize(9).fillColor("#555555").text(`Organization: ${org.name}    Generated: ${new Date().toISOString()}${org.isDemo ? "    DEMO DATA" : ""}`);
  doc.moveDown(0.6);
  doc.moveTo(48, doc.y).lineTo(547, doc.y).strokeColor("#CCCCCC").stroke();
  doc.moveDown(0.8);
}

function section(doc: PDFKit.PDFDocument, title: string) {
  if (doc.y > 720) doc.addPage();
  doc.moveDown(0.4);
  doc.fillColor("#111111").fontSize(13).text(title);
  doc.moveDown(0.3);
  doc.fontSize(9).fillColor("#222222");
}

function kv(doc: PDFKit.PDFDocument, pairs: [string, string | number | null | undefined][]) {
  for (const [k, v] of pairs) {
    doc.font("Helvetica-Bold").text(`${k}: `, { continued: true }).font("Helvetica").text(String(v ?? "n/a"));
  }
}

function footer(doc: PDFKit.PDFDocument) {
  doc.moveDown(1);
  doc.fontSize(8).fillColor("#666666").text(DISCLAIMER, { align: "left" });
}

export async function buildDevicePdf(org: Organization, device: Device): Promise<Buffer> {
  const assessment = await latestAssessmentFor(device.id);
  const checks = assessment ? await db.select().from(assessmentChecksTable).where(eq(assessmentChecksTable.assessmentId, assessment.id)) : [];
  const findings = await db.select().from(securityFindingsTable).where(and(eq(securityFindingsTable.deviceId, device.id), inArray(securityFindingsTable.status, ["OPEN", "ACKNOWLEDGED"]))).orderBy(desc(securityFindingsTable.lastSeenAt));
  const vulns = await db.select().from(vulnerabilityMatchesTable).where(and(eq(vulnerabilityMatchesTable.deviceId, device.id), eq(vulnerabilityMatchesTable.current, true)));
  return pdfToBuffer((doc) => {
    header(doc, `Device Security Report — ${device.name}`, org);
    section(doc, "Summary");
    kv(doc, [
      ["Operating system", `${device.osName} ${device.osVersion}${device.osBuild ? ` (${device.osBuild})` : ""} ${device.architecture}`],
      ["Agent version", device.agentVersion],
      ["Enrolled", device.enrolledAt.toISOString()],
      ["Last seen", device.lastSeenAt?.toISOString() ?? "never"],
      ["Last assessment", device.lastAssessmentAt?.toISOString() ?? "never"],
      ["Coverage", `${device.coveragePercent}% of collectors completed`],
      ["Risk score", device.riskScore == null ? "n/a (insufficient coverage)" : `${device.riskScore}/100 (${riskLevelLabel(riskLevelFor(device.riskScore, device.coveragePercent))})`],
      ["Open findings", findings.length],
    ]);
    section(doc, `Security checks (${checks.length})`);
    if (!checks.length) doc.text("No assessment received yet.");
    for (const c of checks) {
      if (doc.y > 760) doc.addPage();
      doc.font("Helvetica-Bold").text(`[${c.status}] ${c.title}`, { continued: false });
      doc.font("Helvetica").fillColor("#444444").text(`${c.evidence || "(no evidence)"} — source: ${c.dataSource || c.collectorId}; confidence ${c.confidence}; collected ${c.collectedAt.toISOString()}${c.unavailableReason ? `; reason: ${c.unavailableReason}` : ""}`);
      doc.fillColor("#222222").moveDown(0.2);
    }
    section(doc, `Open findings (${findings.length})`);
    if (!findings.length) doc.text("No high-severity findings observed. Review coverage and UNKNOWN checks before treating this device as compliant.");
    for (const f of findings) {
      if (doc.y > 740) doc.addPage();
      doc.font("Helvetica-Bold").text(`${f.severity} — ${f.title} (${f.status})`);
      doc.font("Helvetica").text(`Evidence: ${f.evidence}`);
      doc.text(`Remediation: ${f.remediation}`);
      doc.fillColor("#444444").text(`Rule ${f.ruleId}; confidence ${f.confidence}; first seen ${f.firstSeenAt.toISOString()}`).fillColor("#222222");
      doc.moveDown(0.3);
    }
    section(doc, `Vulnerability matches (${vulns.length})`);
    if (!vulns.length) doc.text("No CVE matches in cached intelligence for the current inventory.");
    for (const v of vulns) {
      if (doc.y > 750) doc.addPage();
      doc.font("Helvetica-Bold").text(`${v.cveId} — ${v.product} ${v.installedVersion} [${v.severity}${v.knownExploited ? ", KEV" : ""}] ${v.matchConfidence}`);
      doc.font("Helvetica").fillColor("#444444").text(v.matchReason).fillColor("#222222");
      doc.moveDown(0.2);
    }
    footer(doc);
  });
}

export async function buildOrganizationPdf(org: Organization): Promise<Buffer> {
  const devices = await db.select().from(devicesTable).where(and(eq(devicesTable.organizationId, org.id), eq(devicesTable.status, "ACTIVE")));
  const findings = await db.select().from(securityFindingsTable).where(and(eq(securityFindingsTable.organizationId, org.id), inArray(securityFindingsTable.status, ["OPEN", "ACKNOWLEDGED"])));
  const vulns = await db.select().from(vulnerabilityMatchesTable).where(and(eq(vulnerabilityMatchesTable.organizationId, org.id), eq(vulnerabilityMatchesTable.current, true)));
  const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as Record<string, number>;
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
  const nameOf = new Map(devices.map((d) => [d.id, d.name]));
  const online = devices.filter((d) => d.lastSeenAt && Date.now() - d.lastSeenAt.getTime() <= org.onlineThresholdMinutes * 60_000).length;
  return pdfToBuffer((doc) => {
    header(doc, "Organization Security Summary", org);
    section(doc, "Fleet");
    kv(doc, [
      ["Active devices", devices.length],
      ["Online now", `${online} (heartbeat within ${org.onlineThresholdMinutes} min)`],
      ["Never assessed", devices.filter((d) => !d.lastAssessmentAt).length],
      ["Open findings", `${findings.length} (C ${bySev["CRITICAL"]}, H ${bySev["HIGH"]}, M ${bySev["MEDIUM"]}, L ${bySev["LOW"]}, I ${bySev["INFO"]})`],
      ["Vulnerability matches", `${vulns.length} (${vulns.filter((v) => v.knownExploited).length} known exploited)`],
    ]);
    section(doc, "Devices");
    for (const d of devices) {
      if (doc.y > 760) doc.addPage();
      const open = findings.filter((f) => f.deviceId === d.id).length;
      doc.font("Helvetica-Bold").text(d.name, { continued: true }).font("Helvetica").text(`  ${d.osType} ${d.osVersion} · coverage ${d.coveragePercent}% · risk ${d.riskScore ?? "n/a"} · ${open} open findings · last seen ${d.lastSeenAt?.toISOString() ?? "never"}`);
    }
    section(doc, "Critical and high findings");
    const top = findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").sort((a, b) => a.severity.localeCompare(b.severity));
    if (!top.length) doc.text("No critical or high findings observed in the current data.");
    for (const f of top) {
      if (doc.y > 750) doc.addPage();
      doc.font("Helvetica-Bold").text(`${f.severity} — ${f.title}`, { continued: true }).font("Helvetica").text(`  on ${nameOf.get(f.deviceId) ?? f.deviceId}`);
      doc.fillColor("#444444").text(f.remediation).fillColor("#222222").moveDown(0.2);
    }
    footer(doc);
  });
}

function csvEscape(v: unknown): string {
  const s = v == null ? "" : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export async function buildFindingsCsv(org: Organization): Promise<Buffer> {
  const rows = await db
    .select({ f: securityFindingsTable, deviceName: devicesTable.name })
    .from(securityFindingsTable)
    .innerJoin(devicesTable, eq(devicesTable.id, securityFindingsTable.deviceId))
    .where(eq(securityFindingsTable.organizationId, org.id))
    .orderBy(desc(securityFindingsTable.lastSeenAt));
  const headers = ["id", "device", "rule_id", "title", "severity", "confidence", "status", "first_seen_at", "last_seen_at", "evidence", "detection_source", "remediation", "collector_id", "raw_status", "status_changed_by", "status_changed_at"];
  const lines = [headers.join(",")];
  for (const { f, deviceName } of rows) {
    lines.push([f.id, deviceName, f.ruleId, f.title, f.severity, f.confidence, f.status, f.firstSeenAt.toISOString(), f.lastSeenAt.toISOString(), f.evidence, f.detectionSource, f.remediation, f.collectorId, f.rawStatus, f.statusChangedByEmail, f.statusChangedAt?.toISOString()].map(csvEscape).join(","));
  }
  lines.push("");
  lines.push(`# ${DISCLAIMER}`);
  return Buffer.from("\uFEFF" + lines.join("\r\n"), "utf8");
}
