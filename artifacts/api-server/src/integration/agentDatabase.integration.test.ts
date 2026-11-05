import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";

const databaseUrl = process.env.NEXTAURA_INTEGRATION_DB_URL;

test(
  "agent lifecycle persists evidence and enforces replay, revocation, and tenant isolation",
  { skip: !databaseUrl },
  async () => {
    process.env.SUPABASE_DB_URL = databaseUrl!;
    process.env.NODE_ENV = "test";
    const [
      { default: express },
      { default: agentRouter },
      { default: scanCenterRouter },
      { errorHandler },
      database,
      { listFindingsForOrganization },
    ] = await Promise.all([
      import("express"),
      import("../routes/agent/index"),
      import("../routes/scanCenter"),
      import("../middlewares/errorHandler"),
      import("@workspace/db"),
      import("../services/findingQueries"),
    ]);
    const { pool } = database;
    const orgA = randomUUID();
    const orgB = randomUUID();
    const validEnrollment = randomUUID();
    const expiredEnrollment = randomUUID();
    const validCode = "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY";
    const expiredCode = "23456-789AB-CDEFG-HJKLM-NPQRS";
    const hashCode = (value: string) =>
      createHash("sha256")
        .update(value.toUpperCase().replace(/[^A-Z0-9]/g, ""))
        .digest("hex");
    await pool.query(
      "insert into organizations (id,name,slug) values ($1,'Integration A',$2),($3,'Integration B',$4)",
      [orgA, `integration-a-${orgA}`, orgB, `integration-b-${orgB}`],
    );
    await pool.query(
      "insert into user_profiles (user_id,email,current_organization_id) values ('integration-user','analyst@example.com',$1) on conflict (user_id) do update set email=excluded.email,current_organization_id=excluded.current_organization_id",
      [orgA],
    );
    await pool.query(
      "insert into organization_members (organization_id,email,user_id,role) values ($1,'analyst@example.com','integration-user','SECURITY_ANALYST')",
      [orgA],
    );
    await pool.query(
      "insert into device_enrollment_requests (id,organization_id,os_type,code_hash,code_hint,created_by_user_id,created_by_email,expires_at) values ($1,$2,'WINDOWS',$3,'VWXY','test','test@example.com',now()+interval '10 minutes'),($4,$2,'WINDOWS',$5,'NPQRS','test','test@example.com',now()-interval '1 minute')",
      [
        validEnrollment,
        orgA,
        hashCode(validCode),
        expiredEnrollment,
        hashCode(expiredCode),
      ],
    );

    const app = express();
    app.use(express.json({ limit: "2mb" }));
    app.use("/api/agent/v1", agentRouter);
    app.use(
      "/api",
      (req, _res, next) => {
        req.identity = {
          userId: "integration-user",
          email: "analyst@example.com",
          name: "Integration Analyst",
        };
        next();
      },
      scanCenterRouter,
    );
    app.use(errorHandler);
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("test server did not bind");
    const base = `http://127.0.0.1:${address.port}/api/agent/v1`;
    const request = (
      path: string,
      body: unknown,
      token?: string,
      method = "POST",
    ) =>
      fetch(base + path, {
        method,
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        ...(method === "GET" ? {} : { body: JSON.stringify(body) }),
      });
    const operatorRequest = (path: string, body?: unknown, method = "POST") =>
      fetch(`http://127.0.0.1:${address.port}/api${path}`, {
        method,
        headers: { "content-type": "application/json" },
        ...(method === "GET" ? {} : { body: JSON.stringify(body) }),
      });
    try {
      const enrollmentPayload = {
        code: validCode,
        agentVersion: "0.1.0-test",
        osType: "WINDOWS",
        system: {
          hostname: "integration-host",
          osName: "Windows",
          osVersion: "11",
          architecture: "amd64",
        },
      };
      const enrolled = await request("/enroll", enrollmentPayload);
      assert.equal(enrolled.status, 201);
      const enrollment = (await enrolled.json()) as {
        deviceId: string;
        deviceToken: string;
      };
      assert.match(enrollment.deviceToken, /^nxa_/);
      assert.equal(
        (await request("/enroll", enrollmentPayload)).status,
        401,
        "one-time code must not be reusable",
      );
      assert.equal(
        (await request("/enroll", { ...enrollmentPayload, code: expiredCode }))
          .status,
        401,
        "expired code must fail",
      );
      const expired = await pool.query(
        "select status from device_enrollment_requests where id=$1",
        [expiredEnrollment],
      );
      assert.equal(expired.rows[0].status, "EXPIRED");
      assert.equal(
        (await request("/heartbeat", heartbeat("unknown"), "nxa_invalid"))
          .status,
        401,
      );

      const firstHeartbeat = await request(
        "/heartbeat",
        heartbeat("heartbeat-1"),
        enrollment.deviceToken,
      );
      assert.equal(firstHeartbeat.status, 200);
      assert.equal(
        ((await firstHeartbeat.json()) as { duplicate: boolean }).duplicate,
        false,
      );
      const duplicateHeartbeat = await request(
        "/heartbeat",
        heartbeat("heartbeat-1"),
        enrollment.deviceToken,
      );
      assert.equal(duplicateHeartbeat.status, 200);
      assert.equal(
        ((await duplicateHeartbeat.json()) as { duplicate: boolean }).duplicate,
        true,
      );
      const heartbeatCount = await pool.query(
        "select count(*)::int count from device_heartbeats where device_id=$1",
        [enrollment.deviceId],
      );
      assert.equal(heartbeatCount.rows[0].count, 1);

      await pool.query(
        "update device_credentials set revoked_at=now() where device_id=$1",
        [enrollment.deviceId],
      );
      assert.equal(
        (
          await request(
            "/heartbeat",
            heartbeat("heartbeat-2"),
            enrollment.deviceToken,
          )
        ).status,
        403,
        "revoked credential must fail",
      );
      await pool.query(
        "update device_credentials set revoked_at=null where device_id=$1",
        [enrollment.deviceId],
      );

      const scopeId = `scope_${"a".repeat(32)}`;
      const scopedHeartbeat = await request(
        "/heartbeat",
        {
          ...heartbeat("heartbeat-scopes"),
          scanScopes: [
            { id: scopeId, label: "Approved installers", enabled: true },
          ],
        },
        enrollment.deviceToken,
      );
      assert.equal(scopedHeartbeat.status, 200);
      const scopeRows = await pool.query(
        "select scope_id,label,enabled from device_scan_scopes where device_id=$1",
        [enrollment.deviceId],
      );
      assert.deepEqual(scopeRows.rows[0], {
        scope_id: scopeId,
        label: "Approved installers",
        enabled: true,
      });

      const createdScan = await operatorRequest("/scan-jobs", {
        scanType: "APPROVED_SCOPE_FILES",
        collectors: [],
        targets: [{ deviceId: enrollment.deviceId, scopeId }],
        expiresInHours: 1,
      });
      assert.equal(createdScan.status, 201);
      const scanJobId = ((await createdScan.json()) as { id: string }).id;
      const requestRow = await pool.query(
        "select id from agent_requests where scan_job_id=$1",
        [scanJobId],
      );
      const agentRequestId = requestRow.rows[0].id as string;
      const crossTenantScan = await operatorRequest("/scan-jobs", {
        scanType: "SECURITY_ASSESSMENT",
        collectors: ["SECURITY_POSTURE"],
        targets: [{ deviceId: randomUUID() }],
      });
      assert.equal(
        crossTenantScan.status,
        400,
        "unknown or cross-tenant devices must be rejected",
      );
      const pending = await request(
        "/requests",
        null,
        enrollment.deviceToken,
        "GET",
      );
      assert.equal(pending.status, 200);
      const pendingBody = (await pending.json()) as {
        requests: Array<{ id: string; operation: string; scopeId: string }>;
      };
      assert.equal(pendingBody.requests[0]?.id, agentRequestId);
      assert.equal(pendingBody.requests[0]?.operation, "FILE_SCOPE_SCAN");
      assert.equal(pendingBody.requests[0]?.scopeId, scopeId);
      assert.equal(
        (
          await request(
            "/requests/ack",
            { requestId: agentRequestId, status: "ACKNOWLEDGED" },
            enrollment.deviceToken,
          )
        ).status,
        200,
      );
      const running = await pool.query(
        "select status from scan_job_devices where agent_request_id=$1",
        [agentRequestId],
      );
      assert.equal(running.rows[0].status, "RUNNING");

      const fileEvidence = {
        idempotencyKey: "file-evidence-1",
        agentRequestId,
        scopeId,
        filesObserved: 1,
        filesAnalyzed: 1,
        partial: false,
        limitations: ["Synthetic harmless integration fixture"],
        evidence: [
          {
            evidenceKey: "b".repeat(64),
            relativePathHash: "c".repeat(64),
            observedAt: new Date().toISOString(),
            detectorId: "NEXTAURA_STATIC_FILE_ANALYZER",
            detectorVersion: "test",
            evidenceSource: "LOCAL_APPROVED_SCOPE_STATIC_ANALYSIS",
            confidence: "MEDIUM",
            severity: "HIGH",
            result: {
              fileName: "harmless.pdf",
              sizeBytes: 8,
              sha256: "d".repeat(64),
              extension: ".pdf",
              detectedType: "PDF",
              signatureMetadata: "NOT_APPLICABLE",
              classification: "SUSPICIOUS_INDICATOR",
              indicators: [
                {
                  id: "SYNTHETIC_TEST_INDICATOR",
                  classification: "SUSPICIOUS_INDICATOR",
                  severity: "HIGH",
                  evidence: "Synthetic harmless fixture",
                },
              ],
              limitations: ["No result proves a file is safe"],
            },
          },
        ],
      };
      const evidenceAccepted = await request(
        "/file-evidence",
        fileEvidence,
        enrollment.deviceToken,
      );
      assert.equal(evidenceAccepted.status, 201);
      assert.equal(
        ((await evidenceAccepted.json()) as { accepted: number }).accepted,
        1,
      );
      const evidenceDuplicate = await request(
        "/file-evidence",
        fileEvidence,
        enrollment.deviceToken,
      );
      assert.equal(evidenceDuplicate.status, 200);
      assert.equal(
        ((await evidenceDuplicate.json()) as { duplicate: boolean }).duplicate,
        true,
      );
      const conflictingEvidence = await request(
        "/file-evidence",
        { ...fileEvidence, idempotencyKey: "file-evidence-conflict" },
        enrollment.deviceToken,
      );
      assert.equal(
        conflictingEvidence.status,
        400,
        "a completed request must not accept a fresh idempotency key",
      );
      const evidenceRows = await pool.query(
        "select organization_id,file_name from scan_file_evidence where scan_job_id=$1",
        [scanJobId],
      );
      assert.equal(evidenceRows.rowCount, 1);
      assert.deepEqual(evidenceRows.rows[0], {
        organization_id: orgA,
        file_name: "harmless.pdf",
      });
      const completedTarget = await pool.query(
        "select status from scan_job_devices where agent_request_id=$1",
        [agentRequestId],
      );
      assert.equal(completedTarget.rows[0].status, "COMPLETED");
      const completedJob = await pool.query(
        "select status from scan_jobs where id=$1",
        [scanJobId],
      );
      assert.equal(completedJob.rows[0].status, "COMPLETED");
      const fileFindings = await pool.query(
        "select organization_id,device_id,rule_id from security_findings where device_id=$1 and rule_id='STATIC_FILE_EVIDENCE'",
        [enrollment.deviceId],
      );
      assert.equal(fileFindings.rowCount, 1);
      assert.deepEqual(fileFindings.rows[0], {
        organization_id: orgA,
        device_id: enrollment.deviceId,
        rule_id: "STATIC_FILE_EVIDENCE",
      });

      const assessment = {
        idempotencyKey: "assessment-1",
        trigger: "MANUAL",
        agentVersion: "0.1.0-test",
        startedAt: new Date(Date.now() - 1000).toISOString(),
        completedAt: new Date().toISOString(),
        collectors: [
          {
            collectorId: "SECURITY_POSTURE",
            collectorVersion: "test",
            status: "OK",
            collectedAt: new Date().toISOString(),
            checks: [
              {
                checkId: "FIREWALL_ENABLED",
                category: "FIREWALL",
                title: "Firewall enabled",
                status: "FAIL",
                evidence: "Synthetic fixture: all profiles disabled",
                dataSource: "integration fixture",
                confidence: "HIGH",
                requiredPermissions: "none",
              },
            ],
          },
        ],
      };
      const accepted = await request(
        "/assessments",
        assessment,
        enrollment.deviceToken,
      );
      assert.equal(accepted.status, 201);
      const acceptedBody = (await accepted.json()) as {
        duplicate: boolean;
        findingsOpened: number;
      };
      assert.equal(acceptedBody.duplicate, false);
      assert.equal(acceptedBody.findingsOpened, 1);
      const repeated = await request(
        "/assessments",
        assessment,
        enrollment.deviceToken,
      );
      assert.equal(repeated.status, 200);
      assert.equal(
        ((await repeated.json()) as { duplicate: boolean }).duplicate,
        true,
      );
      const assessments = await pool.query(
        "select count(*)::int count from assessments where device_id=$1",
        [enrollment.deviceId],
      );
      assert.equal(assessments.rows[0].count, 1);
      const findingsA = await listFindingsForOrganization(orgA);
      const findingsB = await listFindingsForOrganization(orgB);
      assert.equal(findingsA.length, 2);
      assert.deepEqual(
        new Set(findingsA.map((finding) => finding.ruleId)),
        new Set(["FIREWALL_DISABLED", "STATIC_FILE_EVIDENCE"]),
      );
      assert.equal(
        findingsA.every((finding) => finding.deviceId === enrollment.deviceId),
        true,
      );
      assert.equal(
        findingsB.length,
        0,
        "another tenant must not retrieve the finding",
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      await pool.query("delete from organizations where id = any($1::uuid[])", [
        [orgA, orgB],
      ]);
      await pool.query(
        "delete from user_profiles where user_id='integration-user'",
      );
      await pool.end();
    }
  },
);

function heartbeat(requestId: string) {
  return {
    requestId,
    agentVersion: "0.1.0-test",
    timestamp: new Date().toISOString(),
    uptimeSeconds: 120,
    collectorErrors: [],
  };
}
