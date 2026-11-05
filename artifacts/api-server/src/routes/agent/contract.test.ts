import assert from "node:assert/strict";
import { test } from "node:test";
import {
  collectorIdSchema,
  enrollBodySchema,
  fileEvidenceBodySchema,
  heartbeatBodySchema,
} from "./contract";

test("collector contract rejects arbitrary execution identifiers", () => {
  assert.equal(collectorIdSchema.safeParse("SYSTEM_INFO").success, true);
  assert.equal(collectorIdSchema.safeParse("RUN_SHELL").success, false);
});

function fileEvidence() {
  return {
    idempotencyKey: "evidence-1",
    agentRequestId: "11111111-1111-4111-8111-111111111111",
    scopeId: `scope_${"a".repeat(32)}`,
    filesObserved: 1,
    filesAnalyzed: 1,
    partial: false,
    limitations: [],
    evidence: [
      {
        evidenceKey: "b".repeat(64),
        relativePathHash: "c".repeat(64),
        observedAt: "2026-11-05T00:00:00Z",
        detectorId: "NEXTAURA_STATIC_FILE_ANALYZER",
        detectorVersion: "1.1.0",
        evidenceSource: "LOCAL_APPROVED_SCOPE_STATIC_ANALYSIS",
        confidence: "MEDIUM",
        severity: "INFO",
        result: {
          fileName: "sample.pdf",
          sizeBytes: 10,
          sha256: "d".repeat(64),
          extension: ".pdf",
          detectedType: "PDF",
          signatureMetadata: "NOT_APPLICABLE",
          classification: "NO_FINDINGS_OBSERVED",
          indicators: [],
          limitations: [],
        },
      },
    ],
  };
}

test("file evidence accepts only the compiled detector provenance and redacted filenames", () => {
  assert.equal(fileEvidenceBodySchema.safeParse(fileEvidence()).success, true);
  const forged = fileEvidence();
  forged.evidence[0]!.detectorId = "UNTRUSTED_VENDOR";
  assert.equal(fileEvidenceBodySchema.safeParse(forged).success, false);
  const leakedPath = fileEvidence();
  leakedPath.evidence[0]!.result.fileName = "Users/alice/private.pdf";
  assert.equal(fileEvidenceBodySchema.safeParse(leakedPath).success, false);
});

test("enrollment contract rejects unsupported operating systems", () => {
  const parsed = enrollBodySchema.safeParse({
    code: "ABCDE-ABCDE-ABCDE-ABCDE-ABCDE",
    agentVersion: "0.1.0",
    osType: "LINUX",
    system: {
      hostname: "host",
      osName: "Linux",
      osVersion: "1",
      architecture: "amd64",
    },
  });
  assert.equal(parsed.success, false);
});

test("heartbeat contract requires a bounded request id and offset timestamp", () => {
  assert.equal(
    heartbeatBodySchema.safeParse({
      requestId: "request-1",
      agentVersion: "0.1.0",
      timestamp: "2026-11-04T12:00:00Z",
      collectorErrors: [],
    }).success,
    true,
  );
  assert.equal(
    heartbeatBodySchema.safeParse({
      requestId: "",
      agentVersion: "0.1.0",
      timestamp: "not-a-date",
    }).success,
    false,
  );
});
