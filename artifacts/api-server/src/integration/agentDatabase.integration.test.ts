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
      { errorHandler },
      database,
      { listFindingsForOrganization },
    ] = await Promise.all([
      import("express"),
      import("../routes/agent/index"),
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
    app.use(errorHandler);
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("test server did not bind");
    const base = `http://127.0.0.1:${address.port}/api/agent/v1`;
    const request = (path: string, body: unknown, token?: string) =>
      fetch(base + path, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
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
      assert.equal(findingsA.length, 1);
      assert.equal(findingsA[0]!.deviceId, enrollment.deviceId);
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
