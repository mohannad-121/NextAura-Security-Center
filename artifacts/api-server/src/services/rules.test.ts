import assert from "node:assert/strict";
import test from "node:test";
import { buildContext, evaluateRules } from "./rules";
import type { CollectorResult } from "../routes/agent/contract";

function startup(
  items: NonNullable<CollectorResult["startupItems"]>,
): CollectorResult {
  return {
    collectorId: "STARTUP_INVENTORY",
    collectorVersion: "test",
    status: "OK",
    collectedAt: "2026-11-05T00:00:00.000Z",
    checks: [],
    startupItems: items,
  };
}

test("suspicious persistence rules require concrete risky locations", () => {
  const hits = evaluateRules(
    buildContext({
      osType: "WINDOWS",
      deviceName: "test",
      assessmentId: "assessment",
      collectors: [
        startup([
          {
            name: "Updater",
            location: "C:\\Program Files\\Vendor\\updater.exe",
            kind: "SERVICE",
            enabled: true,
            publisher: "Vendor",
          },
          {
            name: "InvoiceUpdate",
            location: "powershell.exe -File C:\\Users\\Public\\invoice.ps1",
            kind: "SCHEDULED_TASK",
            enabled: true,
          },
          {
            name: "Disabled",
            location: "C:\\Users\\Public\\disabled.exe",
            kind: "REGISTRY_RUN",
            enabled: false,
          },
        ]),
      ],
    }),
  );
  const persistence = hits.filter(
    (hit) => hit.rule.ruleId === "SUSPICIOUS_PERSISTENCE",
  );
  assert.equal(persistence.length, 1);
  assert.match(persistence[0]!.evidence, /SUSPICIOUS_INDICATOR/);
  assert.doesNotMatch(persistence[0]!.evidence, /Program Files/);
});

test("unsupported or missing antivirus telemetry is a visibility gap, not a clean or malware verdict", () => {
  const hits = evaluateRules(
    buildContext({
      osType: "MACOS",
      deviceName: "test",
      assessmentId: "assessment",
      collectors: [
        {
          collectorId: "ANTIVIRUS_STATUS",
          collectorVersion: "test",
          status: "OK",
          collectedAt: "2026-11-05T00:00:00.000Z",
          checks: [
            {
              checkId: "THREAT_HISTORY",
              category: "ANTIVIRUS",
              title: "Threat history",
              status: "UNSUPPORTED",
              evidence: "Not applicable",
              dataSource: "n/a",
              confidence: "HIGH",
              requiredPermissions: "vendor integration",
              unavailableReason: "No standard API",
            },
          ],
          antivirus: {
            product: null,
            status: "UNKNOWN",
            realTimeProtection: "UNKNOWN",
            definitionsAgeDays: null,
            lastDefinitionUpdate: null,
            source: null,
            note: "No approved integration",
          },
        },
      ],
    }),
  );
  assert.equal(
    hits.some((hit) => hit.rule.ruleId === "AV_DISABLED"),
    false,
  );
  assert.equal(
    hits.some((hit) => hit.rule.ruleId === "THREAT_DETECTED_RECENT"),
    false,
  );
  assert.equal(
    hits.some((hit) => hit.rule.ruleId === "VISIBILITY_GAP"),
    true,
  );
});
