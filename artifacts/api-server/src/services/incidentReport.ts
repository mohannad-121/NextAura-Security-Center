import PDFDocument from "pdfkit";

export interface IncidentReportData {
  title: string;
  severity: string;
  status: string;
  confidence: string;
  summary: string;
  organizationName: string;
  devices: Array<{ name: string; osType: string }>;
  findings: Array<{ title: string; severity: string; evidence: string }>;
  files: Array<{
    fileName: string;
    sha256: string;
    detectedType: string;
    classification: string;
    signatureMetadata: string;
    limitations: string[];
  }>;
  timeline: Array<{
    occurredAt: Date;
    title: string;
    evidence: string;
    source: string;
  }>;
  limitations: string[];
  actions: string[];
}

export function buildIncidentPdf(data: IncidentReportData): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      margin: 48,
      info: { Title: data.title, Author: "NextAura Security Center" },
    });
    const chunks: Buffer[] = [];
    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
    const section = (title: string) => {
      if (doc.y > 720) doc.addPage();
      doc
        .moveDown(0.7)
        .font("Helvetica-Bold")
        .fontSize(13)
        .fillColor("#111111")
        .text(title)
        .moveDown(0.25)
        .font("Helvetica")
        .fontSize(9);
    };
    doc
      .fillColor("#7568E8")
      .fontSize(10)
      .text("NEXTAURA INCIDENT INVESTIGATION", { characterSpacing: 1 });
    doc
      .fillColor("#111111")
      .font("Helvetica-Bold")
      .fontSize(20)
      .text(data.title);
    doc
      .font("Helvetica")
      .fontSize(9)
      .fillColor("#444444")
      .text(
        `Organization: ${data.organizationName} | Severity: ${data.severity} | Status: ${data.status} | Confidence: ${data.confidence}`,
      );
    section("Summary");
    doc.text(data.summary || "No summary supplied.");
    section("Associated devices");
    data.devices.length
      ? data.devices.forEach((d) => doc.text(`${d.name} (${d.osType})`))
      : doc.text("No devices associated.");
    section("Detection evidence");
    data.findings.length
      ? data.findings.forEach((f) =>
          doc.text(`[${f.severity}] ${f.title}: ${f.evidence}`),
        )
      : doc.text("No platform findings associated.");
    section("Suspicious file evidence");
    data.files.length
      ? data.files.forEach((f) =>
          doc.text(
            `${f.fileName} | ${f.detectedType} | ${f.classification}\nSHA-256: ${f.sha256}\nSignature metadata: ${f.signatureMetadata}${f.limitations.length ? `\nLimits: ${f.limitations.join("; ")}` : ""}`,
          ),
        )
      : doc.text("No file evidence associated.");
    section("Timeline");
    data.timeline.length
      ? data.timeline.forEach((e) =>
          doc.text(
            `${e.occurredAt.toISOString()} | ${e.title} | ${e.evidence} | ${e.source}`,
          ),
        )
      : doc.text("No timeline events recorded.");
    section("Evidence limitations");
    data.limitations.length
      ? data.limitations.forEach((x) => doc.text(`- ${x}`))
      : doc.text(
          "No additional limitations recorded. This does not mean the investigation is complete.",
        );
    section("Recommended manual actions");
    data.actions.length
      ? data.actions.forEach((x) => doc.text(`- ${x}`))
      : doc.text("No actions recorded.");
    doc
      .moveDown(1)
      .fontSize(8)
      .fillColor("#666666")
      .text(
        "This report reflects observed evidence only. NO_FINDINGS_OBSERVED does not mean clean. Files were not executed, mounted, uploaded, deleted, or quarantined by NextAura.",
      );
    doc.end();
  });
}
