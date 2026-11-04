import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { artifactBuildId, buildManifest } from "./write-manifest.mjs";

test("manifest binds each artifact to its content and starts unverified", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "nextaura-manifest-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  await fs.writeFile(
    path.join(dir, "nextaura-agent-windows-amd64.zip"),
    "first",
  );
  const first = await buildManifest(dir, "0.1.0", "2026-11-04T00:00:00Z");
  const artifact = first.manifest.artifacts["windows-amd64"];
  assert.equal(artifact.nativeVerification, null);
  assert.equal(
    artifact.buildId,
    artifactBuildId("0.1.0", "windows-amd64", artifact.sha256),
  );

  await fs.writeFile(
    path.join(dir, "nextaura-agent-windows-amd64.zip"),
    "second",
  );
  const second = await buildManifest(dir, "0.1.0", "2026-11-04T00:01:00Z");
  assert.notEqual(
    second.manifest.artifacts["windows-amd64"].sha256,
    artifact.sha256,
  );
  assert.notEqual(
    second.manifest.artifacts["windows-amd64"].buildId,
    artifact.buildId,
  );
  assert.equal(
    second.manifest.artifacts["windows-amd64"].nativeVerification,
    null,
  );
});
